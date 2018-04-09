#[cfg(not(target_os = "windows"))]
pub use std::os::unix::ffi::OsStrExt as OsStrExt3;

#[cfg(target_os = "windows")]
use std::ffi::OsStr;

#[cfg(target_os = "windows")]
pub trait OsStrExt3 {
    fn from_bytes(b: &[u8]) -> &Self;
    fn as_bytes(&self) -> &[u8];
}

#[cfg(target_os = "windows")]
impl OsStrExt3 for OsStr {
    fn from_bytes(b: &[u8]) -> &Self {
        use std::mem;
        unsafe { mem::transmute(b) }
    }
    fn as_bytes(&self) -> &[u8] {
        self.to_str().map(|s| s.as_bytes()).unwrap()
    }
}
