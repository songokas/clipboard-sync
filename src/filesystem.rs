use bincode;
use log::warn;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::defaults::*;
use crate::errors::*;

type DirStructure = Vec<(String, Vec<u8>)>;

pub fn read_file<P: AsRef<Path>>(path: P, max_size: usize) -> Result<Vec<u8>, io::Error>
{
    let mut f = File::open(path)?;
    let mut buffer = vec![0; max_size];
    let size_read = f.read(&mut buffer)?;
    buffer.resize_with(size_read, Default::default);
    return Ok(buffer);
}

#[allow(unused_variables)]
pub fn write_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>, mode: u32) -> io::Result<()>
{
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(target_os = "linux")]
    opts.mode(mode);

    opts.open(path.as_ref())?.write_all(contents.as_ref())
}

pub fn read_file_to_string<P: AsRef<Path>>(path: P, max_size: usize) -> Result<String, io::Error>
{
    let buffer = read_file(path, max_size)?;
    return Ok(String::from_utf8_lossy(&buffer).to_string());
}

pub fn dir_to_bytes(directory: &str) -> Result<Vec<u8>, EncryptionError>
{
    if !Path::new(directory).exists() {
        return Err(EncryptionError::InvalidMessage(format!(
            "Directory {} does not exist",
            directory
        )));
    }
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
        let data = match read_file(&full_path, MAX_FILE_SIZE) {
            Ok(d) => d,
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
    if hash.is_empty() {
        return Ok(vec![]);
    }
    let add_bytes = bincode::serialize(&hash)
        .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;
    return Ok(add_bytes);
}

pub fn bytes_to_dir(directory: &str, data: Vec<u8>, from: &str) -> Result<Vec<PathBuf>, io::Error>
{
    if !Path::new(directory).exists() {
        fs::create_dir(directory)?;
    }

    let mut files_created = vec![];
    if let Ok(hash) = bincode::deserialize::<DirStructure>(&data) {
        for (file_name, data) in hash {
            let path = Path::new(directory).join(file_name);
            fs::write(&path, data)?;
            files_created.push(path);
        }
        return Ok(files_created);
    }
    let path = Path::new(directory).join(from);
    fs::write(&path, data)?;
    files_created.push(path);
    return Ok(files_created);
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
        assert_eq!(d, read_file("./tests/temp1", 0).unwrap());
        assert_eq!(vec![116], read_file("./tests/temp1", 1).unwrap());
        assert_eq!(
            vec![116, 101, 109, 112, 49],
            read_file("./tests/temp1", 5).unwrap()
        );
        assert_eq!(
            vec![116, 101, 109, 112, 49, 32, 102, 105, 108, 101],
            read_file("./tests/temp1", 20).unwrap()
        );
        assert_eq!(false, read_file("./tests/t1", 20).is_ok());
    }

    #[test]
    fn test_read_to_string()
    {
        assert_eq!("", read_file_to_string("./tests/temp1", 0).unwrap());
        assert_eq!("temp1", read_file_to_string("./tests/temp1", 5).unwrap());
        assert_eq!(
            "temp1 file",
            read_file_to_string("./tests/temp1", 20).unwrap()
        );
        assert_eq!(
            "temp1 file",
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
            assert_eq!(expected_data, dir_to_bytes(path).unwrap());
        }
        assert_eq!(false, dir_to_bytes("./tests/empt").is_ok());
    }

    #[test]
    fn test_bytes_to_dir()
    {
        for (expected_data, path, data_to_use) in bytes_to_dir_provider() {
            assert_eq!(
                expected_data,
                bytes_to_dir(path, data_to_use, "unknown").unwrap()
            );
        }
        assert_eq!(
            false,
            bytes_to_dir("/tmp/all/deep/a", vec![3], "unknown").is_ok()
        );
    }
}
