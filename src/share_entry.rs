use crate::error::Error;
#[cfg(target_os = "windows")]
use crate::os_str_ext::OsStrExt;
use bytesize::ByteSize;
use chrono::{DateTime, Local};
use chrono_humanize::HumanTime;
use std::ffi::OsStr;
use std::fs::{self, DirEntry};
#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;

#[derive(Debug)]
pub struct ShareEntry {
    display_name: String,
    link: String,
    is_dir: bool,
    size: String,
    date: DateTime<Local>,
    date_string: String,
}

impl ShareEntry {
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn link(&self) -> &str {
        &self.link
    }

    pub fn is_dir(&self) -> bool {
        self.is_dir
    }

    pub fn size(&self) -> &str {
        &self.size
    }

    pub fn date(&self) -> DateTime<Local> {
        self.date
    }

    pub fn date_string(&self) -> &str {
        &self.date_string
    }

    pub fn try_from(value: &DirEntry) -> Result<Self, Error> {
        let mut metadata = value
            .metadata()
            .map_err(|e| Error::from_io(e, value.path().to_path_buf()))?;
        if metadata.file_type().is_symlink() {
            metadata = fs::metadata(value.path())
                .map_err(|e| Error::from_io(e, value.path().to_path_buf()))?;
        }

        let is_dir = metadata.file_type().is_dir();
        let name = value.file_name();
        let link = encode_link(&name, is_dir);
        let display_name = display_name(&name, is_dir);
        let size = if !is_dir {
            ByteSize::b(metadata.len()).to_string_as(false)
        } else {
            String::new()
        };
        let date = metadata
            .modified()
            .map_err(|e| Error::from_io(e, value.path().to_path_buf()))?
            .into();
        let date_string = HumanTime::from(date).to_string();
        Ok(Self {
            display_name,
            link,
            is_dir,
            size,
            date,
            date_string,
        })
    }
}

fn display_name(name: &OsStr, is_dir: bool) -> String {
    let mut s = name.to_string_lossy().into_owned();
    if is_dir {
        s.push('/');
    }
    s
}

fn encode_link(name: &OsStr, is_dir: bool) -> String {
    let mut s =
        percent_encoding::percent_encode(name.as_bytes(), percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    if is_dir {
        s.push('/');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::{display_name, encode_link};
    use std::ffi::OsStr;

    #[test]
    fn link_encoding() {
        assert_eq!(encode_link(&OsStr::new("foo"), false), "foo");
        assert_eq!(encode_link(&OsStr::new("foo bar"), false), "foo%20bar");
        assert_eq!(encode_link(&OsStr::new("foo bar"), true), "foo%20bar/");
    }

    #[test]
    fn friendly_names() {
        assert_eq!(display_name(&OsStr::new("foo"), false), "foo");
        assert_eq!(display_name(&OsStr::new("foo bar"), false), "foo bar");
        assert_eq!(display_name(&OsStr::new("foo bar"), true), "foo bar/");
    }
}
