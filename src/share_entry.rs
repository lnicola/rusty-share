use crate::error::Error;
use bytesize::ByteSize;
use chrono::{DateTime, Local};
use chrono_humanize::HumanTime;
use std::fs::{self, DirEntry};
#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;
use url::percent_encoding;
#[cfg(target_os = "windows")]
use OsStrExt;

#[derive(Debug)]
pub struct ShareEntry {
    name: String,
    link: String,
    is_dir: bool,
    size: String,
    date: DateTime<Local>,
    date_string: String,
}

impl ShareEntry {
    pub fn name(&self) -> &str {
        &self.name
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
        let metadata = value
            .metadata()
            .map_err(|e| Error::from_io(e, value.path().to_path_buf()))?;
        let file_type = metadata.file_type();
        let is_dir =
            file_type.is_dir() || file_type.is_symlink() && fs::metadata(value.path())?.is_dir();
        let mut name = value.file_name();
        if is_dir {
            name.push("/");
        }
        let link =
            percent_encoding::percent_encode(name.as_bytes(), percent_encoding::DEFAULT_ENCODE_SET)
                .to_string();
        let name = name.to_string_lossy().into_owned();
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
            name,
            link,
            is_dir,
            size,
            date,
            date_string,
        })
    }
}
