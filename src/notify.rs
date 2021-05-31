use log::{debug, warn};
use notify::{DebouncedEvent, Error, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

pub fn create_watch_paths<T>(
    paths_to_watch: &HashMap<PathBuf, T>,
) -> Result<(RecommendedWatcher, Receiver<DebouncedEvent>), Error>
{
    if !(paths_to_watch.len() > 0) {
        return Err(Error::PathNotFound);
    }
    let (fs_sender, fs_receiver) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new(fs_sender, Duration::from_secs(1))?;
    watch_paths(&mut watcher, paths_to_watch);
    return Ok((watcher, fs_receiver));
}

pub fn watch_changed_paths<'a, T>(
    watcher: &mut RecommendedWatcher,
    receiver: &Receiver<DebouncedEvent>,
    paths_to_watch: &'a HashMap<PathBuf, T>,
) -> HashMap<PathBuf, &'a T>
{
    let mut changed_paths = HashMap::new();

    loop {
        match receiver.try_recv() {
            Ok(DebouncedEvent::NoticeWrite(path)) => {
                let paths = paths_to_watch.iter().filter(|(expected_path, _)| {
                    expected_path == &&path || path.starts_with(expected_path)
                });
                for (t, p) in paths {
                    changed_paths.insert(t.clone(), p);
                }
            }
            // if expected directory is created lets watch it
            Ok(DebouncedEvent::Create(path)) => {
                if let Some(_) = paths_to_watch.get(&path) {
                    match watcher.watch(&path, RecursiveMode::NonRecursive) {
                        Ok(_) => {
                            debug!("watching for filesystem changes {}", path.to_string_lossy());
                            if let Some(p) = path.parent() {
                                if let Err(e) = watcher.unwatch(p) {
                                    warn!(
                                        "failed to unwatch parent directory {} {}",
                                        p.to_string_lossy(),
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => warn!("watching for changes error occured {}", e),
                    }
                }

                if path.is_dir() {
                    continue;
                }

                let paths = paths_to_watch.iter().filter(|(expected_path, _)| {
                    expected_path == &&path || path.starts_with(expected_path)
                });
                for (t, p) in paths {
                    changed_paths.insert(t.clone(), p);
                }
            }
            // if expected directory is removed lets watch parent
            Ok(DebouncedEvent::NoticeRemove(path)) => {
                if let Some(p) = paths_to_watch.get(&path).and(path.parent()) {
                    match watcher.watch(p, RecursiveMode::NonRecursive) {
                        Ok(_) => {
                            debug!(
                                "directory removed {} watching for filesystem changes {}",
                                path.to_string_lossy(),
                                p.to_string_lossy()
                            )
                        }
                        Err(e) => warn!("watching for changes error occured {}", e),
                    };
                }
            }
            Ok(DebouncedEvent::Rescan) => warn!("watching for changes rescan is needed"),
            Ok(DebouncedEvent::Error(e, p)) => {
                warn!("watching for changes error occured {} {:?}", e, p)
            }
            // Ok(event) => debug!("filesystem watch unhandled event {:?}", event),
            Ok(_) => (),
            _ => break,
        };
    }
    return changed_paths;
}

fn watch_paths<T>(watcher: &mut RecommendedWatcher, paths_to_watch: &HashMap<PathBuf, T>)
{
    for (path, _) in paths_to_watch {
        match watcher.watch(path, RecursiveMode::NonRecursive) {
            Ok(_) => debug!("watching for filesystem changes {}", path.to_string_lossy()),
            Err(e) => {
                // if no dir/file exists try parent
                let presult = if let Some(p) = path.parent() {
                    watcher.watch(p, RecursiveMode::NonRecursive).map(|_| p)
                } else {
                    Err(e)
                };
                match presult {
                    Ok(parent_path) => {
                        debug!(
                            "watching for filesystem changes in parent {} of {}",
                            parent_path.to_string_lossy(),
                            path.to_string_lossy(),
                        )
                    }
                    Err(e) => warn!(
                        "failed to watch filesystem changes for {} {}",
                        path.to_string_lossy(),
                        e
                    ),
                };
            }
        };
    }
}

#[cfg(test)]
mod notifytest
{
    use super::*;
    use std::fs::{create_dir_all, remove_dir, remove_file, write};
    use std::thread::sleep;

    #[test]
    fn test_file_watching()
    {
        let dir = "/tmp/test_file_watching";
        create_dir_all(dir).unwrap();
        let file = format!("{}/test_file_watching", dir);
        remove_file(&file).unwrap_or(());
        write(&file, b"testdata1").unwrap();
        let path = PathBuf::from(&file);

        let mut paths: HashMap<PathBuf, String> = HashMap::new();
        paths.insert(path.clone(), "file1".to_owned());

        let (mut watcher, receiver) = create_watch_paths(&paths).unwrap();

        write(&file, b"anyghintelse").unwrap();
        sleep(Duration::from_millis(300));

        let changed = watch_changed_paths(&mut watcher, &receiver, &paths);

        assert_eq!("file1", changed.get(&path).unwrap().as_str());

        remove_file(&file).unwrap_or(());
        remove_dir(&dir).unwrap_or(());
    }

    #[test]
    fn test_non_existing_file_watching()
    {
        let dir = "/tmp/test_non_existing_file_watching";
        create_dir_all(dir).unwrap();
        let file = format!("{}/test_non_existing_file_watching", dir);
        remove_file(&file).unwrap_or(());

        let path = PathBuf::from(&file);
        let mut paths: HashMap<PathBuf, String> = HashMap::new();
        paths.insert(path.clone(), "file1".to_owned());

        let (mut watcher, receiver) = create_watch_paths(&paths).unwrap();

        write(&file, b"data1").unwrap();
        sleep(Duration::from_millis(2000));

        let changed = watch_changed_paths(&mut watcher, &receiver, &paths);

        assert_eq!("file1", changed.get(&path).unwrap().as_str());

        remove_file(&file).unwrap_or(());
        remove_dir(&dir).unwrap_or(());
    }

    #[test]
    fn test_dir_watching()
    {
        let dir = "/tmp/test_dir_watching";
        create_dir_all(dir).unwrap();
        let file1 = format!("{}/test_dir_watching1", dir);
        let file2 = format!("{}/test_dir_watching2", dir);
        write(&file1, b"testdata1").unwrap();

        let path = PathBuf::from(&dir);
        let mut paths: HashMap<PathBuf, Vec<&str>> = HashMap::new();
        paths.insert(path.clone(), vec!["file1", "file2"]);

        let (mut watcher, receiver) = create_watch_paths(&paths).unwrap();

        write(&file1, b"testdata2").unwrap();
        write(&file2, b"testdata2").unwrap();
        sleep(Duration::from_millis(1500));

        let changed = watch_changed_paths(&mut watcher, &receiver, &paths);
        let expected = vec!["file1", "file2"];

        assert_eq!(&expected, *(changed.get(&path).unwrap()));
        remove_file(&file1).unwrap_or(());
        remove_file(&file2).unwrap_or(());
        remove_dir(&dir).unwrap_or(());
    }

    #[test]
    fn test_non_existing_dir_watching()
    {
        let dir = "/tmp/test_non_existing_dir_watching";
        let file1 = format!("{}/file1", dir);
        let file2 = format!("{}/file2", dir);
        remove_file(&file1).unwrap_or(());
        remove_file(&file2).unwrap_or(());
        remove_dir(&dir).unwrap_or(());

        let path = PathBuf::from(&dir);
        let mut paths: HashMap<PathBuf, Vec<&str>> = HashMap::new();
        paths.insert(path.clone(), vec!["file1", "file2"]);

        let (mut watcher, receiver) = create_watch_paths(&paths).unwrap();

        create_dir_all(dir).unwrap();
        sleep(Duration::from_millis(2000));
        let changed = watch_changed_paths(&mut watcher, &receiver, &paths);
        assert_eq!(changed.len(), 0);

        sleep(Duration::from_millis(1000));
        write(&file1, b"testdata2").unwrap();
        sleep(Duration::from_millis(2000));

        let changed = watch_changed_paths(&mut watcher, &receiver, &paths);
        let expected = vec!["file1", "file2"];
        assert_eq!(&expected, *(changed.get(&path).unwrap()));

        remove_file(&file1).unwrap_or(());
        remove_file(&file2).unwrap_or(());
        remove_dir(&dir).unwrap_or(());
    }
}
