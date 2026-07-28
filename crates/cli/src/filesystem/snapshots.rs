// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Optional-file snapshots and stable backup-file management.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::atomic_write_with_permissions;
#[cfg(windows)]
use super::{atomic_write_with_windows_dacl, read_windows_dacl};

pub(crate) fn backup(path: &Path) -> Result<(), String> {
    let backup = backup_path(path);
    if backup.exists() {
        return Ok(());
    }
    if path.exists() {
        let bytes = fs::read(path)
            .map_err(|error| format!("failed to read {} for backup: {error}", path.display()))?;
        #[cfg(windows)]
        {
            let dacl = read_windows_dacl(path).map_err(|error| {
                format!(
                    "failed to read access control for {}: {error}",
                    path.display()
                )
            })?;
            atomic_write_with_windows_dacl(&backup, &bytes, &dacl)?;
        }
        #[cfg(not(windows))]
        {
            let permissions = fs::metadata(path)
                .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?
                .permissions();
            atomic_write_with_permissions(&backup, &bytes, Some(&permissions))?;
        }
    }
    Ok(())
}

pub(crate) fn remove_backup(path: &Path) -> Result<(), String> {
    let backup = backup_path(path);
    match fs::remove_file(&backup) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to remove {}: {error}", backup.display())),
    }
}

pub(crate) fn backup_path(path: &Path) -> PathBuf {
    let mut extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string();
    if extension.is_empty() {
        extension = "nemo-relay.bak".into();
    } else {
        extension.push_str(".nemo-relay.bak");
    }
    path.with_extension(extension)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct FileSnapshot {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    #[serde(default)]
    unix_mode: Option<u32>,
    #[cfg(windows)]
    #[serde(default)]
    dacl: Option<Vec<u8>>,
}

const DIRECTORY_SNAPSHOT_MAX_ENTRIES: usize = 4_096;
const DIRECTORY_SNAPSHOT_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct DirectorySnapshot {
    root: PathBuf,
    existed: bool,
    #[serde(default)]
    root_unix_mode: Option<u32>,
    directories: Vec<DirectoryEntrySnapshot>,
    files: Vec<DirectoryFileSnapshot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DirectoryEntrySnapshot {
    relative_path: PathBuf,
    #[serde(default)]
    unix_mode: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DirectoryFileSnapshot {
    relative_path: PathBuf,
    bytes: Vec<u8>,
    #[serde(default)]
    unix_mode: Option<u32>,
    #[cfg(windows)]
    #[serde(default)]
    dacl: Option<Vec<u8>>,
}

impl DirectorySnapshot {
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn capture(root: &Path) -> Result<Self, String> {
        require_absolute_snapshot_root(root)?;
        let metadata = match fs::symlink_metadata(root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    root: root.to_path_buf(),
                    existed: false,
                    root_unix_mode: None,
                    directories: Vec::new(),
                    files: Vec::new(),
                });
            }
            Err(error) => {
                return Err(format!("failed to inspect {}: {error}", root.display()));
            }
        };
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "refusing to snapshot non-directory or symbolic-link path {}",
                root.display()
            ));
        }
        let mut snapshot = Self {
            root: root.to_path_buf(),
            existed: true,
            root_unix_mode: unix_mode(root)?,
            directories: Vec::new(),
            files: Vec::new(),
        };
        let mut total_bytes = 0;
        snapshot.capture_directory(root, Path::new(""), &mut total_bytes)?;
        Ok(snapshot)
    }

    pub(crate) fn restore(&self) -> Result<(), String> {
        self.validate()?;
        remove_snapshot_root_if_present(&self.root)?;
        if !self.existed {
            return Ok(());
        }
        fs::create_dir_all(&self.root)
            .map_err(|error| format!("failed to create {}: {error}", self.root.display()))?;
        for directory in &self.directories {
            let path = self.root.join(&directory.relative_path);
            fs::create_dir(&path)
                .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
        }
        for file in &self.files {
            let path = self.root.join(&file.relative_path);
            #[cfg(windows)]
            if let Some(dacl) = file.dacl.as_deref() {
                atomic_write_with_windows_dacl(&path, &file.bytes, dacl)?;
                continue;
            }
            #[cfg(unix)]
            let permissions = file
                .unix_mode
                .map(std::os::unix::fs::PermissionsExt::from_mode);
            #[cfg(not(unix))]
            let permissions: Option<fs::Permissions> = None;
            atomic_write_with_permissions(&path, &file.bytes, permissions.as_ref())?;
        }
        for directory in self.directories.iter().rev() {
            set_unix_mode(
                &self.root.join(&directory.relative_path),
                directory.unix_mode,
            )?;
        }
        set_unix_mode(&self.root, self.root_unix_mode)?;
        Ok(())
    }

    fn capture_directory(
        &mut self,
        directory: &Path,
        relative: &Path,
        total_bytes: &mut usize,
    ) -> Result<(), String> {
        let mut entries = fs::read_dir(directory)
            .map_err(|error| format!("failed to inspect {}: {error}", directory.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("failed to inspect {}: {error}", directory.display()))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            self.ensure_entry_budget()?;
            let name = entry.file_name();
            let child_relative = relative.join(name);
            validate_relative_snapshot_path(&child_relative)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "refusing to snapshot symbolic link {}",
                    path.display()
                ));
            }
            if metadata.file_type().is_dir() {
                self.directories.push(DirectoryEntrySnapshot {
                    relative_path: child_relative.clone(),
                    unix_mode: unix_mode(&path)?,
                });
                self.capture_directory(&path, &child_relative, total_bytes)?;
                continue;
            }
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "refusing to snapshot non-regular file {}",
                    path.display()
                ));
            }
            let bytes =
                super::bounded::read_bounded_regular_file(&path, "directory snapshot entry")?;
            *total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or_else(directory_snapshot_limit_error)?;
            if *total_bytes > DIRECTORY_SNAPSHOT_MAX_BYTES {
                return Err(directory_snapshot_limit_error());
            }
            self.files.push(DirectoryFileSnapshot {
                relative_path: child_relative,
                bytes,
                unix_mode: unix_mode(&path)?,
                #[cfg(windows)]
                dacl: Some(read_windows_dacl(&path).map_err(|error| {
                    format!(
                        "failed to read access control for {}: {error}",
                        path.display()
                    )
                })?),
            });
        }
        Ok(())
    }

    fn ensure_entry_budget(&self) -> Result<(), String> {
        if self.directories.len() + self.files.len() >= DIRECTORY_SNAPSHOT_MAX_ENTRIES {
            return Err(directory_snapshot_limit_error());
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        require_absolute_snapshot_root(&self.root)?;
        if !self.existed
            && (self.root_unix_mode.is_some()
                || !self.directories.is_empty()
                || !self.files.is_empty())
        {
            return Err("absent directory snapshot unexpectedly contains entries".into());
        }
        if self.directories.len() + self.files.len() > DIRECTORY_SNAPSHOT_MAX_ENTRIES {
            return Err(directory_snapshot_limit_error());
        }
        let bytes = self
            .files
            .iter()
            .try_fold(0usize, |total, file| total.checked_add(file.bytes.len()));
        if bytes.is_none_or(|bytes| bytes > DIRECTORY_SNAPSHOT_MAX_BYTES) {
            return Err(directory_snapshot_limit_error());
        }
        for relative in self
            .directories
            .iter()
            .map(|entry| &entry.relative_path)
            .chain(self.files.iter().map(|entry| &entry.relative_path))
        {
            validate_relative_snapshot_path(relative)?;
        }
        Ok(())
    }
}

impl FileSnapshot {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }

    pub(crate) fn is_current(&self) -> Result<bool, String> {
        snapshot_optional_file(&self.path).map(|current| current == *self)
    }

    pub(crate) fn require_current(&self) -> Result<(), String> {
        if self.is_current()? {
            return Ok(());
        }
        Err(format!(
            "{} changed while Relay was preparing an update; retained the current file",
            self.path.display()
        ))
    }
}

fn require_absolute_snapshot_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() || root.parent().is_none() {
        return Err(format!(
            "directory snapshot root must be an absolute child path, got {}",
            root.display()
        ));
    }
    Ok(())
}

fn validate_relative_snapshot_path(relative: &Path) -> Result<(), String> {
    use std::path::Component;

    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "directory snapshot contains unsafe relative path {}",
            relative.display()
        ));
    }
    Ok(())
}

fn remove_snapshot_root_if_present(root: &Path) -> Result<(), String> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(root)
            .map_err(|error| format!("failed to remove {}: {error}", root.display())),
        Ok(_) => Err(format!(
            "refusing to replace non-directory or symbolic-link path {}",
            root.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to inspect {}: {error}", root.display())),
    }
}

fn directory_snapshot_limit_error() -> String {
    format!(
        "directory snapshot exceeds the {} entry or {} byte safety limit",
        DIRECTORY_SNAPSHOT_MAX_ENTRIES, DIRECTORY_SNAPSHOT_MAX_BYTES
    )
}

fn set_unix_mode(path: &Path, mode: Option<u32>) -> Result<(), String> {
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("failed to set permissions on {}: {error}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

pub(crate) fn snapshot_optional_file(path: &Path) -> Result<FileSnapshot, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let bytes = super::bounded::read_bounded_regular_file(path, "snapshot source file")?;
            Ok(FileSnapshot {
                path: path.to_path_buf(),
                bytes: Some(bytes),
                unix_mode: unix_mode(path)?,
                #[cfg(windows)]
                dacl: Some(read_windows_dacl(path).map_err(|error| {
                    format!(
                        "failed to read access control for {}: {error}",
                        path.display()
                    )
                })?),
            })
        }
        Ok(_) => Err(format!(
            "refusing to snapshot non-regular or symbolic-link path {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(FileSnapshot {
            path: path.to_path_buf(),
            bytes: None,
            unix_mode: None,
            #[cfg(windows)]
            dacl: None,
        }),
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}

pub(crate) fn restore_file_snapshot(snapshot: &FileSnapshot) -> Result<(), String> {
    if let Some(bytes) = snapshot.bytes.as_deref() {
        #[cfg(windows)]
        if let Some(dacl) = snapshot.dacl.as_deref() {
            return atomic_write_with_windows_dacl(&snapshot.path, bytes, dacl);
        }
        #[cfg(unix)]
        let permissions = snapshot
            .unix_mode
            .map(std::os::unix::fs::PermissionsExt::from_mode);
        #[cfg(not(unix))]
        let permissions: Option<fs::Permissions> = None;
        return atomic_write_with_permissions(&snapshot.path, bytes, permissions.as_ref());
    }
    match fs::remove_file(&snapshot.path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to remove {}: {error}",
            snapshot.path.display()
        )),
    }
}

pub(crate) fn restore_file_snapshot_cas(
    snapshot: &FileSnapshot,
    expected_current: Option<&FileSnapshot>,
) -> Result<(), String> {
    let current = snapshot_optional_file(snapshot.path())?;
    if current == *snapshot {
        return Ok(());
    }
    if expected_current != Some(&current) {
        return Err(format!(
            "{} changed outside this Relay transaction; retained the current file",
            snapshot.path.display()
        ));
    }
    current.require_current()?;
    restore_file_snapshot(snapshot)
}

fn unix_mode(path: &Path) -> Result<Option<u32>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::metadata(path)
            .map(|metadata| Some(metadata.permissions().mode()))
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(None)
    }
}
