use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use log::warn;
use sanitise_file_name::sanitise;
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
pub fn read_file<P: AsRef<Path>>(path: P, max_size: usize) -> Result<(Vec<u8>, bool), io::Error> {
    let mut f = File::open(path)?;
    let mut read_bufer = [0; 65000];
    let mut buffer = Vec::new();

    loop {
        let size_read = f.read(&mut read_bufer)?;
        if size_read == 0 {
            break;
        }
        if buffer.len() + size_read > max_size {
            buffer.extend_from_slice(&read_bufer[..max_size - buffer.len()]);
            return Ok((buffer, false));
        }
        buffer.extend_from_slice(&read_bufer[..size_read]);
    }

    Ok((buffer, true))
}

#[allow(unused_variables)]
pub fn write_file(path: &Path, contents: impl AsRef<[u8]>, mode: u32) -> io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(target_os = "linux")]
    opts.mode(mode);
    opts.open(path)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unable to write to {} {}", path.to_string_lossy(), e),
            )
        })?
        .write_all(contents.as_ref())
}

pub fn read_file_to_string<P: AsRef<Path>>(
    path: P,
    max_size: usize,
) -> Result<(String, bool), io::Error> {
    let (buffer, full) = read_file(path, max_size)?;
    Ok((String::from_utf8_lossy(&buffer).to_string(), full))
}

pub fn dir_to_dir_structure(directory: &Path, max_file_size: usize) -> DirStructure {
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
        let data = match read_file(full_path, max_file_size) {
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

pub fn dir_to_bytes(directory: &Path, max_file_size: usize) -> Result<Bytes, FilesystemError> {
    if !Path::new(directory).exists() {
        return Err(FilesystemError::NoDirectory(directory.to_path_buf()));
    }
    let files = dir_to_dir_structure(directory, max_file_size);
    if files.is_empty() {
        return Ok(Bytes::new());
    }
    Ok(serialize_files(files))
}

pub fn files_to_dir_structure(files: Vec<&Path>, max_file_size: usize) -> DirStructure {
    let mut hash = DirStructure::new();
    for file_path in files {
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
        let data = match read_file(file_path, max_file_size) {
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

pub fn files_to_bytes(files: Vec<&Path>, max_file_size: usize) -> Result<Bytes, FilesystemError> {
    let files = files_to_dir_structure(files, max_file_size);
    if files.is_empty() {
        return Ok(Bytes::new());
    }
    Ok(serialize_files(files))
}

pub fn bytes_to_dir(
    path: &Path,
    data: Bytes,
    from: &str,
    max_file_size: usize,
) -> Result<Vec<PathBuf>, FilesystemError> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }

    let mut files_created = vec![];
    if let Ok(files) = deserialize_files(data.clone()) {
        if path.is_file() {
            if files.len() > 1 {
                warn!(
                    "Using only 1 file out off {} received, since file={} is specified",
                    files.len(),
                    path.to_string_lossy()
                );
            }
            if let Some((_, data)) = files.into_iter().next() {
                write_file(path, data, 0o600)?;
                files_created.push(path.to_path_buf());
            }
        } else {
            for (file_name, data) in files {
                let path = path.join(sanitise(&file_name));
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
    let path = path.join(sanitise(from));
    write_file(&path, data, 0o600)?;
    files_created.push(path);
    Ok(files_created)
}

pub fn encode_path(path: impl AsRef<Path>) -> Option<String> {
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

pub fn decode_path(path: impl AsRef<Path>) -> Result<PathBuf, String> {
    path.as_ref()
        .components()
        .map(|c| {
            let cpath = c
                .as_os_str()
                .to_str()
                .ok_or_else(|| format!("Invalid path {}", path.as_ref().to_string_lossy()))?;
            let pc = if let Component::RootDir = c {
                cpath.to_owned()
            } else {
                decode(cpath).map_err(|e| e.to_string())?.to_string()
            };
            Ok(pc)
        })
        .collect()
}

pub fn serialize_files(files: DirStructure) -> Bytes {
    let mut bytes = BytesMut::new();
    for (file_name, data) in files {
        bytes.put_u32(file_name.len() as u32);
        bytes.put(Bytes::from(file_name));
        bytes.put_u64(data.len() as u64);
        bytes.put(Bytes::from(data));
    }
    bytes.into()
}

fn deserialize_files(mut bytes: Bytes) -> Result<Vec<(String, Bytes)>, ()> {
    let mut files = Vec::new();
    loop {
        if bytes.remaining() < size_of::<u32>() {
            return Err(());
        }
        let file_name_len = bytes.get_u32() as usize;
        if bytes.remaining() < file_name_len {
            return Err(());
        }
        let file_name_bytes = bytes.copy_to_bytes(file_name_len);
        let file_name = String::from_utf8_lossy(&file_name_bytes).to_string();
        if bytes.remaining() < size_of::<u64>() {
            return Err(());
        }
        let data_len = bytes.get_u64() as usize;
        if bytes.remaining() < file_name_len {
            return Err(());
        }
        let data = bytes.copy_to_bytes(data_len);
        files.push((file_name, data));
        if bytes.remaining() == 0 {
            break;
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_join() {
        let path = Path::new("/tmp/2level");
        assert_eq!(
            Some("/tmp/2level/file"),
            path.join(sanitise("file")).to_str()
        );
        assert_eq!(
            Some("/tmp/2level/.file"),
            path.join(sanitise("../file")).to_str()
        );
        assert_eq!(
            Some("/tmp/2level/file"),
            path.join(sanitise("/file")).to_str()
        );
        assert_eq!(
            Some("/tmp/2level/.file"),
            path.join(sanitise("./file")).to_str()
        );
        assert_eq!(Some("/tmp/2level/_"), path.join(sanitise("")).to_str());
    }

    #[test]
    fn test_read_file() {
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
        assert!(read_file("./tests/t1", 20).is_err());
    }

    #[test]
    fn test_read_to_string() {
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
        assert!(read_file_to_string("./tests/t1", 20).is_err());
    }

    #[test]
    fn test_dir_to_bytes() {
        for (path, expected_data) in dir_to_bytes_provider() {
            assert_eq!(expected_data, dir_to_bytes(Path::new(path), 100).unwrap());
        }
        assert!(dir_to_bytes(Path::new("./tests/empt"), 100).is_err());
    }

    #[test]
    fn test_bytes_to_dir() {
        for (expected_data, path, data_to_use) in bytes_to_dir_provider() {
            assert_eq!(
                expected_data,
                bytes_to_dir(Path::new(path), Bytes::from(data_to_use), "unknown", 100).unwrap()
            );
        }
        assert!(bytes_to_dir(
            Path::new("/tmp/all/deep/a"),
            Bytes::from(vec![3]),
            "unknown",
            100
        )
        .is_ok());
    }

    #[test]
    fn test_encode_path() {
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
    fn test_decode_path() {
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
            let decoded = decode_path(path);
            assert_eq!(Path::new(expected).to_path_buf(), decoded.unwrap());
        }
    }

    fn dir_to_bytes_provider() -> Vec<(&'static str, Vec<u8>)> {
        fs::create_dir("./tests/empty/").unwrap_or(());
        vec![
            ("./tests/empty/", vec![]),
            (
                "./tests/test-dir",
                b"\0\0\0\x01a\0\0\0\0\0\0\0\x01a\0\0\0\x01b\0\0\0\0\0\0\0\x01b".to_vec(),
            ),
        ]
    }

    fn bytes_to_dir_provider() -> Vec<(Vec<PathBuf>, &'static str, &'static [u8])> {
        vec![
            (
                vec![
                    PathBuf::from_str("/tmp/test-dir/a").unwrap(),
                    PathBuf::from_str("/tmp/test-dir/b").unwrap(),
                ],
                "/tmp/test-dir",
                b"\0\0\0\x01a\0\0\0\0\0\0\0\x01a\0\0\0\x01b\0\0\0\0\0\0\0\x01b",
            ),
            (
                vec![PathBuf::from_str("/tmp/no-dir/a").unwrap()],
                "/tmp/no-dir",
                b"\0\0\0\x01a\0\0\0\0\0\0\0\x01a",
            ),
        ]
    }
}
