use super::is_hidden;
use failure::{Error, ResultExt};
use path_ext::PathExt;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use tar::Builder;
use walkdir::{DirEntry, WalkDir};

fn entry_size(root: &Path, entry: &DirEntry) -> Result<u64, Error> {
    let metadata = entry
        .metadata()
        .with_context(|_| format!("Unable to read metadata for {}", entry.path().display()))?;
    let relative_path = entry.path().strip_prefix(&root).with_context(|_| {
        format!(
            "Unable to make path {} relative from {}",
            entry.path().display(),
            root.display()
        )
    })?;
    let mut header_len = 512;
    let path_len = relative_path.len() as u64;
    if path_len > 100 {
        header_len += 512 + path_len;
        if path_len % 512 > 0 {
            header_len += 512 - path_len % 512;
        }
    }
    if !metadata.is_dir() {
        let mut len = metadata.len();
        if len % 512 > 0 {
            len += 512 - len % 512;
        }
        header_len += len;
    }
    Ok(header_len)
}

fn write_entry<W>(builder: &mut Builder<W>, root: &Path, entry: &DirEntry) -> Result<(), Error>
where
    W: Write,
{
    let metadata = entry
        .metadata()
        .with_context(|_| format!("Unable to read metadata for {}", entry.path().display()))?;
    let relative_path = entry.path().strip_prefix(&root).with_context(|_| {
        format!(
            "Unable to make path {} relative from {}",
            entry.path().display(),
            root.display()
        )
    })?;
    if metadata.is_dir() {
        builder
            .append_dir(&relative_path, entry.path())
            .with_context(|_| format!("Unable to add {} to archive", entry.path().display()))?;
    } else {
        let mut file = File::open(&entry.path())
            .with_context(|_| format!("Unable to open {}", entry.path().display()))?;
        builder
            .append_file(&relative_path, &mut file)
            .with_context(|_| format!("Unable to add {} to archive", entry.path().display()))?;
    }

    Ok(())
}

pub fn add_to_archive<W>(builder: &mut Builder<W>, root: &Path, entry: &Path)
where
    W: Write,
{
    let entries = WalkDir::new(root.join(&entry))
        .into_iter()
        .filter_entry(|e| !is_hidden(e.file_name()));
    for e in entries {
        match e {
            Ok(e) => if let Err(e) = write_entry(builder, root.as_ref(), &e) {
                error!("{}", e);
            },
            Err(e) => error!("{}", e),
        }
    }
}

pub fn get_archive_size(path: &Path, files: &[PathBuf]) -> Result<u64, Error> {
    let mut archive_size = 1024;
    for file in files {
        let entries = WalkDir::new(path.join(&file))
            .into_iter()
            .filter_entry(|e| !is_hidden(e.file_name()));
        for e in entries {
            let e = e?;
            archive_size += entry_size(path, &e)?;
        }
    }
    Ok(archive_size)
}
