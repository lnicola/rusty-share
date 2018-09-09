use bytesize::ByteSize;
use chrono::{DateTime, Local};
use chrono_humanize::HumanTime;
use std::fs::DirEntry;
use std::io::Error;
#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;
use url::percent_encoding;
#[cfg(target_os = "windows")]
use OsStrExt3;

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
        let metadata = value.metadata()?;
        let is_dir = metadata.is_dir();
        let mut name = value.file_name();
        if metadata.is_dir() {
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
        let date = metadata.modified()?.into();
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
