use bincode;
use log::warn;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Component;
use std::path::{Path, PathBuf};
use urlencoding::{decode, encode};
use walkdir::WalkDir;

use crate::errors::*;

pub type DirStructure = Vec<(String, Vec<u8>)>;

// returns bytes read and if the whole file was read
pub fn read_file<P: AsRef<Path>>(path: P, max_size: usize) -> Result<(Vec<u8>, bool), io::Error>
{
    let mut f = File::open(path)?;
    let mut buffer = vec![0; max_size + 1];
    let size_read = f.read(&mut buffer)?;
    let all_file = size_read < (max_size + 1);
    let resize_to = if all_file { size_read } else { max_size };
    buffer.resize_with(resize_to, Default::default);
    Ok((buffer, all_file))
}

#[allow(unused_variables)]
pub fn write_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>, mode: u32) -> io::Result<()>
{
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(target_os = "linux")]
    opts.mode(mode);
    opts.open(path.as_ref())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Unable to write to {} {}",
                    path.as_ref().to_string_lossy(),
                    e
                ),
            )
        })?
        .write_all(contents.as_ref())
}

pub fn read_file_to_string<P: AsRef<Path>>(
    path: P,
    max_size: usize,
) -> Result<(String, bool), io::Error>
{
    let (buffer, full) = read_file(path, max_size)?;
    Ok((String::from_utf8_lossy(&buffer).to_string(), full))
}

pub fn dir_to_dir_structure(directory: &str, max_file_size: usize) -> DirStructure
{
    let mut hash = DirStructure::new();
    let walk = WalkDir::new(directory)
        .follow_links(false)
        .min_depth(1)
        .max_depth(1)
        .sort_by(|a, b| a.file_name().cmp(b.file_name()))
        .into_iter()
        .filter_map(|e| e.ok());
    for entry in walk {
        let full_path = entry.path();
        let file_name = match entry.file_name().to_str() {
            Some(f) => f,
            None => {
                warn!("Ignoring file {}", full_path.display());
                continue;
            }
        };
        let data = match read_file(&full_path, max_file_size) {
            Ok((d, read)) if read => d,
            Ok(_) => {
                warn!("File is larger than {} ignoring", max_file_size,);
                continue;
            }
            Err(err) => {
                warn!(
                    "Unable to read file {} Message: {}",
                    full_path.display(),
                    err.to_string()
                );
                continue;
            }
        };
        hash.push((file_name.to_owned(), data));
    }
    hash
}

pub fn dir_to_bytes(directory: &str, max_file_size: usize) -> Result<Vec<u8>, EncryptionError>
{
    if !Path::new(directory).exists() {
        return Err(EncryptionError::InvalidMessage(format!(
            "Directory {} does not exist",
            directory
        )));
    }
    let hash = dir_to_dir_structure(directory, max_file_size);
    if hash.is_empty() {
        return Ok(vec![]);
    }
    let add_bytes = bincode::serialize(&hash).map_err(|err| {
        EncryptionError::SerializeFailed(format!(
            "Failed to serialize directory {} {}",
            directory,
            (*err).to_string()
        ))
    })?;
    Ok(add_bytes)
}

pub fn files_to_dir_structure(files: Vec<&str>, max_file_size: usize) -> DirStructure
{
    let mut hash = DirStructure::new();
    for file in files {
        let normalized_path = file.strip_prefix("file://").unwrap_or(file);
        let file_path = Path::new(&normalized_path);
        let file_name = match file_path.file_name() {
            Some(f) => {
                if let Some(s) = f.to_str() {
                    s.to_owned()
                } else {
                    continue;
                }
            }
            None => {
                warn!("Ignoring file {}", file_path.display());
                continue;
            }
        };
        let data = match read_file(&file_path, max_file_size) {
            Ok((d, full)) if full => d,
            Ok(_) => {
                warn!("File is larger than {} ignoring", max_file_size,);
                continue;
            }
            Err(err) => {
                warn!(
                    "Unable to read file {} Message: {}",
                    file_path.display(),
                    err.to_string()
                );
                continue;
            }
        };
        hash.push((file_name, data));
    }
    hash
}

pub fn files_to_bytes(files: Vec<&str>, max_file_size: usize) -> Result<Vec<u8>, EncryptionError>
{
    let hash = files_to_dir_structure(files, max_file_size);
    if hash.is_empty() {
        return Ok(vec![]);
    }
    let add_bytes = bincode::serialize(&hash)
        .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;
    Ok(add_bytes)
}

pub fn bytes_to_dir(
    directory: &str,
    data: Vec<u8>,
    from: &str,
    max_file_size: usize,
) -> Result<Vec<PathBuf>, io::Error>
{
    if !Path::new(directory).exists() {
        fs::create_dir_all(directory)?;
    }

    let mut files_created = vec![];
    if let Ok(hash) = bincode::deserialize::<DirStructure>(&data) {
        for (file_name, data) in hash {
            let path = Path::new(directory).join(file_name.clone());
            if data.len() > max_file_size {
                warn!(
                    "Ignoring file {} because it contains more data {} than expected {}",
                    file_name,
                    data.len(),
                    max_file_size
                );
                continue;
            }
            write_file(&path, data, 0o600)?;
            files_created.push(path);
        }
        return Ok(files_created);
    }
    if data.len() > max_file_size {
        warn!(
            "Ignoring file {} because it contains more data {} than expected {}",
            from,
            data.len(),
            max_file_size
        );
        return Ok(vec![]);
    }
    let path = Path::new(directory).join(from);
    write_file(&path, data, 0o600)?;
    files_created.push(path);
    Ok(files_created)
}

pub fn encode_path(path: impl AsRef<Path>) -> Option<String>
{
    let enc_path: Result<PathBuf, ()> = path
        .as_ref()
        .components()
        .map(|c| {
            let cpath = c.as_os_str().to_str().ok_or(())?;
            let pc = if let Component::RootDir = c {
                cpath.to_owned()
            } else {
                encode(cpath).to_string()
            };
            Ok(pc)
        })
        .collect();
    enc_path.map(|b| b.to_string_lossy().to_string()).ok()
}

pub fn decode_path(path: impl AsRef<Path>) -> Result<String, String>
{
    let enc_path: Result<PathBuf, String> = path
        .as_ref()
        .components()
        .map(|c| {
            let cpath = c.as_os_str().to_str().ok_or_else(|| {
                format!(
                    "Invalid path {}",
                    path.as_ref().to_string_lossy().to_string()
                )
            })?;
            let pc = if let Component::RootDir = c {
                cpath.to_owned()
            } else {
                decode(cpath).map_err(|e| e.to_string())?.to_string()
            };
            Ok(pc)
        })
        .collect();
    enc_path.map(|b| b.to_string_lossy().to_string())
}

#[cfg(test)]
mod filesystemtest
{
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_read_file()
    {
        let d: Vec<u8> = Vec::new();
        assert_eq!((d, false), read_file("./tests/temp1", 0).unwrap());
        assert_eq!((vec![116], false), read_file("./tests/temp1", 1).unwrap());
        assert_eq!(
            (vec![116, 101, 109, 112, 49], false),
            read_file("./tests/temp1", 5).unwrap()
        );
        assert_eq!(
            (vec![116, 101, 109, 112, 49, 32, 102, 105, 108, 101], true),
            read_file("./tests/temp1", 20).unwrap()
        );
        assert_eq!(false, read_file("./tests/t1", 20).is_ok());
    }

    #[test]
    fn test_read_to_string()
    {
        assert_eq!(
            ("".to_owned(), false),
            read_file_to_string("./tests/temp1", 0).unwrap()
        );
        assert_eq!(
            ("temp1".to_owned(), false),
            read_file_to_string("./tests/temp1", 5).unwrap()
        );
        assert_eq!(
            ("temp1 file".to_owned(), true),
            read_file_to_string("./tests/temp1", 20).unwrap()
        );
        assert_eq!(false, read_file_to_string("./tests/t1", 20).is_ok());
    }

    fn dir_to_bytes_provider() -> Vec<(&'static str, Vec<u8>)>
    {
        fs::create_dir("./tests/empty/").unwrap_or(());
        return vec![
            ("./tests/empty/", vec![]),
            (
                "./tests/test-dir",
                vec![
                    2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 97, 1, 0, 0, 0, 0, 0, 0, 0, 97,
                    1, 0, 0, 0, 0, 0, 0, 0, 98, 1, 0, 0, 0, 0, 0, 0, 0, 98,
                ],
            ),
        ];
    }

    fn bytes_to_dir_provider() -> Vec<(Vec<PathBuf>, &'static str, Vec<u8>)>
    {
        return vec![
            (
                vec![
                    PathBuf::from_str("/tmp/test-dir/a").unwrap(),
                    PathBuf::from_str("/tmp/test-dir/b").unwrap(),
                ],
                "/tmp/test-dir",
                vec![
                    2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 97, 1, 0, 0, 0, 0, 0, 0, 0, 97,
                    1, 0, 0, 0, 0, 0, 0, 0, 98, 1, 0, 0, 0, 0, 0, 0, 0, 98,
                ],
            ),
            (
                vec![PathBuf::from_str("/tmp/no-dir/unknown").unwrap()],
                "/tmp/no-dir",
                vec![2, 0, 0, 0, 0, 0, 0, 0, 97],
            ),
        ];
    }

    #[test]
    fn test_dir_to_bytes()
    {
        for (path, expected_data) in dir_to_bytes_provider() {
            assert_eq!(expected_data, dir_to_bytes(path, 100).unwrap());
        }
        assert_eq!(false, dir_to_bytes("./tests/empt", 100).is_ok());
    }

    #[test]
    fn test_bytes_to_dir()
    {
        for (expected_data, path, data_to_use) in bytes_to_dir_provider() {
            assert_eq!(
                expected_data,
                bytes_to_dir(path, data_to_use, "unknown", 100).unwrap()
            );
        }
        assert_eq!(
            true,
            bytes_to_dir("/tmp/all/deep/a", vec![3], "unknown", 100).is_ok()
        );
    }

    #[test]
    fn test_encode_path()
    {
        let data = [
            ("hello/amigo/1", "hello/amigo/1"),
            // prefix is not supported
            ("file:///hello/amigo/1", "file%3A/hello/amigo/1"),
            ("/hello/amigo/1", "/hello/amigo/1"),
            ("///hello/amigo/1", "/hello/amigo/1"),
            (
                "/hello with spaces/amigo/1",
                "/hello%20with%20spaces/amigo/1",
            ),
            ("^,&%$%20hello/", "%5E%2C%26%25%24%2520hello"),
        ];

        for (path, expected) in data {
            let encoded = encode_path(Path::new(path));
            assert_eq!(Some(expected.to_string()), encoded);
        }
    }

    #[test]
    fn test_decode_path()
    {
        let data = [
            ("hello/amigo/1", "hello/amigo/1"),
            ("file:/hello/amigo/1", "file%3A/hello/amigo/1"),
            ("/hello/amigo/1", "/hello/amigo/1"),
            ("/hello/amigo/1", "///hello/amigo/1"),
            (
                "/hello with spaces/amigo/1",
                "/hello%20with%20spaces/amigo/1",
            ),
            ("^,&%$ hello", "^,&%$%20hello/"),
            ("^,&%$%20hello", "%5E%2C%26%25%24%2520hello"),
        ];

        for (expected, path) in data {
            let decoded = decode_path(&path);
            assert_eq!(expected.to_string(), decoded.unwrap());
        }
    }
}
