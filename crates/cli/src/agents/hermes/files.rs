// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serialized, rollback-capable filesystem operations for the Hermes integration.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::CliError;
use crate::filesystem::{LockAttempt, try_lock_exclusive};
use crate::installation::generation::GENERATION_FILE_NAME;

const ALLOWLIST_FILE_NAME: &str = "shell-hooks-allowlist.json";
const ENV_FILE_NAME: &str = ".env";
const ENV_STATE_FILE_NAME: &str = ".nemo-relay-proxy-env.json";
const CA_BUNDLE_FILE_NAME: &str = ".nemo-relay-ca-bundle.pem";
const INSTALL_LOCK_FILE_NAME: &str = ".nemo-relay-operation.lock";
const INSTALL_LOCK_RETRY: Duration = Duration::from_millis(25);
pub(super) const INSTALL_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PersistentPaths {
    pub(super) config: PathBuf,
    pub(super) allowlist: PathBuf,
    pub(super) generation: PathBuf,
    pub(super) env: PathBuf,
    pub(super) env_state: PathBuf,
    pub(super) ca_bundle: PathBuf,
}

impl PersistentPaths {
    pub(super) fn for_config(config: PathBuf) -> Result<Self, CliError> {
        let home = config.parent().ok_or_else(|| {
            CliError::Install(format!(
                "Hermes config path {} has no parent directory",
                config.display()
            ))
        })?;
        Ok(Self {
            allowlist: home.join(ALLOWLIST_FILE_NAME),
            generation: home.join(GENERATION_FILE_NAME),
            env: home.join(ENV_FILE_NAME),
            env_state: home.join(ENV_STATE_FILE_NAME),
            ca_bundle: home.join(CA_BUNDLE_FILE_NAME),
            config,
        })
    }

    pub(super) fn all(&self) -> Vec<PathBuf> {
        vec![
            self.config.clone(),
            self.allowlist.clone(),
            self.generation.clone(),
            self.env.clone(),
            self.env_state.clone(),
            self.ca_bundle.clone(),
        ]
    }
}

pub(super) fn acquire_install_lock(config: &Path, timeout: Duration) -> Result<File, String> {
    let home = config.parent().ok_or_else(|| {
        format!(
            "Hermes config path {} has no parent directory",
            config.display()
        )
    })?;
    acquire_lock_file(
        &home.join(INSTALL_LOCK_FILE_NAME),
        timeout,
        "another Hermes integration update",
    )
}

/// Uses Hermes's own sibling allowlist lock so Relay cannot lose an unrelated approval that
/// Hermes records concurrently.
pub(super) fn acquire_allowlist_lock(allowlist: &Path, timeout: Duration) -> Result<File, String> {
    let mut lock = allowlist.as_os_str().to_os_string();
    lock.push(".lock");
    acquire_lock_file(
        &PathBuf::from(lock),
        timeout,
        "a Hermes shell-hook approval update",
    )
}

fn acquire_lock_file(path: &Path, timeout: Duration, contention: &str) -> Result<File, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|error| {
        format!(
            "failed to open Hermes install lock {}: {error}",
            path.display()
        )
    })?;
    let deadline = Instant::now() + timeout;
    loop {
        match try_lock_exclusive(&file) {
            Ok(LockAttempt::Acquired) => return Ok(file),
            Ok(LockAttempt::Contended) if Instant::now() < deadline => {
                thread::sleep(
                    INSTALL_LOCK_RETRY.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Ok(LockAttempt::Contended) => {
                return Err(format!(
                    "timed out waiting for {contention} at {}; wait for it to finish and retry",
                    path.display()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "failed to lock Hermes integration state {}: {error}",
                    path.display()
                ));
            }
        }
    }
}

pub(super) fn read_optional_utf8(path: &Path) -> Result<Option<String>, CliError> {
    match fs::read_to_string(path) {
        Ok(raw) => Ok(Some(raw)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::Install(format!(
            "failed to read {}: {error}",
            path.display()
        ))),
    }
}

pub(super) fn remove_optional_file(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to remove {}: {error}", path.display())),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub(super) struct FileSnapshot {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    #[serde(default)]
    unix_mode: Option<u32>,
}

impl FileSnapshot {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn capture(path: &Path) -> Result<Self, CliError> {
        match fs::read(path) {
            Ok(bytes) => {
                let unix_mode = file_unix_mode(path).map_err(|error| {
                    CliError::Install(format!(
                        "failed to snapshot permissions on {}: {error}",
                        path.display()
                    ))
                })?;
                Ok(Self {
                    path: path.to_path_buf(),
                    bytes: Some(bytes),
                    unix_mode,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: path.to_path_buf(),
                bytes: None,
                unix_mode: None,
            }),
            Err(error) => Err(CliError::Install(format!(
                "failed to snapshot {}: {error}",
                path.display()
            ))),
        }
    }

    pub(super) fn restore_in<W>(&self, transaction: &mut FileTransaction<W>) -> Result<(), String>
    where
        W: FnMut(&Path, &[u8]) -> Result<(), String>,
    {
        transaction.replace(&self.path, self.bytes.as_deref())?;
        #[cfg(unix)]
        if let Some(mode) = self.unix_mode {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&self.path, fs::Permissions::from_mode(mode)).map_err(|error| {
                format!(
                    "failed to restore permissions on {}: {error}",
                    self.path.display()
                )
            })?;
            transaction.refresh_applied(&self.path)?;
        }
        Ok(())
    }

    fn is_current(&self) -> Result<bool, String> {
        Self::capture(&self.path)
            .map(|current| current == *self)
            .map_err(|error| error.to_string())
    }

    pub(super) fn require_current(&self) -> Result<(), String> {
        if self.is_current()? {
            return Ok(());
        }
        Err(format!(
            "{} changed while Relay was preparing a Hermes update; retained the current file",
            self.path.display()
        ))
    }

    pub(super) fn restore<W>(&self, write: &mut W) -> Result<(), String>
    where
        W: FnMut(&Path, &[u8]) -> Result<(), String>,
    {
        if let Some(bytes) = self.bytes.as_deref() {
            write(&self.path, bytes)?;
            #[cfg(unix)]
            if let Some(mode) = self.unix_mode {
                use std::os::unix::fs::PermissionsExt;

                fs::set_permissions(&self.path, fs::Permissions::from_mode(mode)).map_err(
                    |error| {
                        format!(
                            "failed to restore permissions on {}: {error}",
                            self.path.display()
                        )
                    },
                )?;
            }
            return Ok(());
        }
        remove_optional_file(&self.path)
    }
}

pub(super) struct FileTransaction<W>
where
    W: FnMut(&Path, &[u8]) -> Result<(), String>,
{
    originals: BTreeMap<PathBuf, FileSnapshot>,
    applied: Vec<(PathBuf, FileSnapshot)>,
    write: W,
}

impl<W> FileTransaction<W>
where
    W: FnMut(&Path, &[u8]) -> Result<(), String>,
{
    pub(super) fn new(originals: Vec<FileSnapshot>, write: W) -> Self {
        Self {
            originals: originals
                .into_iter()
                .map(|snapshot| (snapshot.path.clone(), snapshot))
                .collect(),
            applied: Vec::new(),
            write,
        }
    }

    pub(super) fn write(&mut self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        let original = self.original(path)?;
        original.require_current()?;
        let result = (self.write)(path, bytes);
        self.record_if_changed(path, &original)?;
        result
    }

    pub(super) fn remove(&mut self, path: &Path) -> Result<(), String> {
        let original = self.original(path)?;
        original.require_current()?;
        let result = remove_optional_file(path);
        self.record_if_changed(path, &original)?;
        result
    }

    pub(super) fn replace(&mut self, path: &Path, bytes: Option<&[u8]>) -> Result<(), String> {
        match bytes {
            Some(bytes) => self.write(path, bytes),
            None => self.remove(path),
        }
    }

    pub(super) fn rollback(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        for (path, expected) in std::mem::take(&mut self.applied).into_iter().rev() {
            let Some(original) = self.originals.get(&path).cloned() else {
                errors.push(format!(
                    "Hermes transaction lost snapshot for {}",
                    path.display()
                ));
                continue;
            };
            if let Err(error) = expected
                .require_current()
                .and_then(|()| original.restore(&mut self.write))
            {
                errors.push(error);
            }
        }
        errors
    }

    fn original(&self, path: &Path) -> Result<FileSnapshot, String> {
        self.originals.get(path).cloned().ok_or_else(|| {
            format!(
                "Hermes transaction has no original snapshot for {}",
                path.display()
            )
        })
    }

    fn record_if_changed(&mut self, path: &Path, original: &FileSnapshot) -> Result<(), String> {
        let current = FileSnapshot::capture(path).map_err(|error| error.to_string())?;
        if current == *original {
            return Ok(());
        }
        self.applied.retain(|(applied, _)| applied != path);
        self.applied.push((path.to_path_buf(), current));
        Ok(())
    }

    fn refresh_applied(&mut self, path: &Path) -> Result<(), String> {
        let original = self.original(path)?;
        self.record_if_changed(path, &original)
    }
}

fn file_unix_mode(path: &Path) -> Result<Option<u32>, std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::metadata(path).map(|metadata| Some(metadata.permissions().mode()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(None)
    }
}
