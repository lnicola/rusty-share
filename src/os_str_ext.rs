#[cfg(not(target_os = "windows"))]
pub use std::os::unix::ffi::OsStrExt;

#[cfg(target_os = "windows")]
use std::ffi::OsStr;

#[cfg(target_os = "windows")]
pub trait OsStrExt {
    fn from_bytes(b: &[u8]) -> &Self;
    fn as_bytes(&self) -> &[u8];
}

#[cfg(target_os = "windows")]
impl OsStrExt for OsStr {
    fn from_bytes(b: &[u8]) -> &Self {
        unsafe { &*(b as *const [u8] as *const std::ffi::OsStr) }
    }
    fn as_bytes(&self) -> &[u8] {
        self.to_str().map(|s| s.as_bytes()).unwrap()
    }
}
