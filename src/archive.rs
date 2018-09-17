use crate::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use tar::Builder;
use walkdir::DirEntry;

pub struct ArchiveEntry {
    path: PathBuf,
    relative_path: String,
    is_dir: bool,
}

impl ArchiveEntry {
    pub fn write_to<W>(&self, builder: &mut Builder<W>) -> Result<(), Error>
    where
        W: Write,
    {
        if self.is_dir {
            builder
                .append_dir(&self.relative_path, &self.path)
                .map_err(|e| Error::from_io(e, self.path.clone()))?;
        } else {
            let mut file =
                File::open(&self.path).map_err(|e| Error::from_io(e, self.path.clone()))?;
            builder
                .append_file(&self.relative_path, &mut file)
                .map_err(|e| Error::from_io(e, self.path.clone()))?;
        }

        Ok(())
    }
}

pub struct Archive {
    size: u64,
    entries: Vec<ArchiveEntry>,
}

impl Archive {
    pub fn new() -> Self {
        Self {
            size: 1024,
            entries: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, root: &Path, entry: DirEntry) -> Result<(), Error> {
        let is_dir = entry.file_type().is_dir();
        let relative_path = entry
            .path()
            .strip_prefix(&root)
            .map_err(|e| {
                Error::from_strip_prefix(e, entry.path().to_path_buf(), root.to_path_buf())
            })?.to_string_lossy()
            .into_owned();

        let mut entry_len = 512;
        let path_len = relative_path.len() as u64;
        if path_len > 100 {
            entry_len += 512 + path_len;
            if path_len % 512 > 0 {
                entry_len += 512 - path_len % 512;
            }
        }
        if !is_dir {
            let metadata = entry.metadata()?;
            entry_len += (metadata.len() + 511) / 512 * 512;
        }
        self.size += entry_len;

        let entry = ArchiveEntry {
            path: entry.into_path(),
            relative_path,
            is_dir,
        };
        self.entries.push(entry);

        Ok(())
    }

    pub fn entries(&self) -> &[ArchiveEntry] {
        &self.entries
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}
