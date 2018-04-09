#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

pub trait PathExt {
    fn len(&self) -> usize;
    fn is_root(&self) -> bool;
}

impl PathExt for Path {
    #[cfg(any(unix, target_os = "redox"))]
    fn len(&self) -> usize {
        self.as_os_str().as_bytes().len()
    }

    #[cfg(windows)]
    fn len(&self) -> usize {
        p.as_os_str().to_str().map(|s| s.as_bytes()).unwrap().len()
    }

    fn is_root(&self) -> bool {
        let mut components = self.components();
        components.next() == Some(Component::RootDir) && components.next() == None
    }
}
