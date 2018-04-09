use chrono::{DateTime, Local};
use std::convert::TryFrom;
use std::ffi::OsString;
use std::fs::DirEntry;
use std::io::Error;

#[derive(Debug)]
pub struct ShareEntry {
    pub name: OsString,
    pub is_dir: bool,
    pub size: u64,
    pub date: DateTime<Local>,
}

impl<'a> TryFrom<&'a DirEntry> for ShareEntry {
    type Error = Error;

    fn try_from(value: &DirEntry) -> Result<Self, Self::Error> {
        let metadata = value.metadata()?;
        Ok(ShareEntry {
            name: value.file_name(),
            is_dir: metadata.is_dir(),
            size: metadata.len(),
            date: metadata.modified()?.into(),
        })
    }
}
