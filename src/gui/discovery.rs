//! Cache directory listings, never vault contents or operation results.
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

#[derive(PartialEq)]
enum Stamp {
    Missing,
    Directory { modified: SystemTime, len: u64 },
}
fn stamp(path: &Path) -> Option<Stamp> {
    match std::fs::metadata(path) {
        Ok(metadata) => Some(Stamp::Directory {
            modified: metadata.modified().ok()?,
            len: metadata.len(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(Stamp::Missing),
        // Don't hide permission failures or assume unsupported timestamps work.
        Err(_) => None,
    }
}
struct Cached<T> {
    path: PathBuf,
    scope: u16,
    stamp: Stamp,
    loaded: Instant,
    value: T,
}
pub(super) struct DirectoryCache<T> {
    cached: Option<Cached<T>>,
}
impl<T> Default for DirectoryCache<T> {
    fn default() -> Self {
        Self { cached: None }
    }
}
impl<T: Clone> DirectoryCache<T> {
    pub fn invalidate(&mut self) {
        self.cached = None;
    }
    pub fn read<E>(
        &mut self,
        path: &Path,
        scope: u16,
        force: bool,
        load: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let stamp = stamp(path);
        if !force
            && let Some(cached) = &self.cached
            && cached.path == path
            && cached.scope == scope
            && Some(&cached.stamp) == stamp.as_ref()
            && cached.loaded.elapsed() < Duration::from_secs(30)
        {
            return Ok(cached.value.clone());
        }
        // A failed refresh must never make an old successful listing valid again.
        self.invalidate();
        let value = load()?;
        if let Some(stamp) = stamp {
            self.cached = Some(Cached {
                path: path.into(),
                scope,
                stamp,
                loaded: Instant::now(),
                value: value.clone(),
            });
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unchanged_directories_reuse_listings_but_changes_scopes_and_refresh_do_not() {
        let directory = tempfile::tempdir().unwrap();
        let mut cache = DirectoryCache::default();
        let mut loads = 0;
        let mut read = |cache: &mut DirectoryCache<usize>, scope, force| {
            cache
                .read(directory.path(), scope, force, || {
                    loads += 1;
                    Ok::<_, ()>(loads)
                })
                .unwrap()
        };
        assert_eq!(read(&mut cache, 1, false), 1);
        assert_eq!(read(&mut cache, 1, false), 1);
        assert_eq!(read(&mut cache, 2, false), 2);
        assert_eq!(read(&mut cache, 2, true), 3);
        cache.invalidate();
        assert_eq!(read(&mut cache, 2, false), 4);
        cache.cached.as_mut().unwrap().loaded = Instant::now() - Duration::from_secs(31);
        assert_eq!(read(&mut cache, 2, false), 5);
        // Missing -> existing detection is independent of filesystem timestamp resolution.
        let missing = directory.path().join("new");
        assert_eq!(cache.read(&missing, 1, false, || Ok::<_, ()>(5)), Ok(5));
        std::fs::create_dir(&missing).unwrap();
        assert_eq!(cache.read(&missing, 1, false, || Ok::<_, ()>(6)), Ok(6));
        assert!(
            cache
                .read(&missing, 1, true, || Err::<usize, _>(()))
                .is_err()
        );
        assert_eq!(cache.read(&missing, 1, false, || Ok::<_, ()>(7)), Ok(7));
    }
}

#[cfg(test)]
mod benchmarks {
    use super::*;
    use crate::benchmarks::Config;
    #[test]
    #[ignore = "opt-in directory performance workload; run npm run bench"]
    fn performance_benchmarks() {
        let config = Config::read();
        for &size in &config.sizes {
            let directory = tempfile::tempdir().unwrap();
            for id in 0..size {
                std::fs::write(directory.path().join(format!("{id:032x}.enc")), []).unwrap();
            }
            let scans = std::cell::Cell::new(0);
            let load = || {
                scans.set(scans.get() + 1);
                password_manager::file::list_vault_files(directory.path())
            };
            let mut cache = DirectoryCache::default();
            assert_eq!(
                cache.read(directory.path(), 1, false, load).unwrap().len(),
                size
            );
            config.measure(
                "desktop",
                "directory_forced_scan",
                size,
                || (),
                |_| cache.read(directory.path(), 1, true, load).unwrap(),
            );
            let scans_before_hits = scans.get();
            config.measure(
                "desktop",
                "directory_cached",
                size,
                || (),
                |_| cache.read(directory.path(), 1, false, load).unwrap(),
            );
            assert_eq!(
                scans.get(),
                scans_before_hits,
                "cache expired during hit benchmark; use fewer samples"
            );
        }
    }
}
