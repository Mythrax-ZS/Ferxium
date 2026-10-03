//! Private per-user storage. ACL setup fails closed before secrets are written.
use anyhow::{Context, Result, ensure};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub fn data_dir() -> Result<PathBuf> {
    let current = directories::ProjectDirs::from("org", "FerXium", "FerXium")
        .context("Could not resolve current user's data directory")?
        .data_local_dir()
        .to_path_buf();
    // Keep existing encrypted quarantine and its key together after the rename.
    // Reuse the earlier preview's state in place; never move it implicitly.
    let legacy = directories::ProjectDirs::from("org", "AegisGuard", "AegisGuard")
        .context("Could not resolve legacy data directory")?
        .data_local_dir()
        .to_path_buf();
    select_data_dir(current, legacy)
}

fn select_data_dir(current: PathBuf, legacy: PathBuf) -> Result<PathBuf> {
    ensure!(
        !(current.exists() && legacy.exists()),
        "Both FerXium and legacy AegisGuard state directories exist. Stop both services and back up both vaults before reconciling state; see docs/SECURITY_MODEL.md."
    );
    Ok(if legacy.exists() { legacy } else { current })
}

pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "State directory must not be a symlink"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    windows_private_acl(path)?;
    Ok(())
}

#[cfg(windows)]
fn windows_private_acl(path: &Path) -> Result<()> {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree},
        Security::Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SE_FILE_OBJECT, SetNamedSecurityInfoW,
        },
        Security::{
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
            PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    // SAFETY: all Windows pointers below reference owned buffers; handles and
    // LocalAlloc strings are released, and each API result is checked before use.
    unsafe {
        let mut token = ptr::null_mut();
        ensure!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0,
            "OpenProcessToken failed"
        );
        let result = (|| -> Result<()> {
            let mut bytes = 0;
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut bytes);
            ensure!(bytes > 0, "TokenUser size unavailable");
            // usize storage guarantees TOKEN_USER alignment.
            let mut buffer = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
            ensure!(
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    bytes,
                    &mut bytes
                ) != 0,
                "TokenUser unavailable"
            );
            let user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
            let mut sid_text = ptr::null_mut();
            ensure!(
                ConvertSidToStringSidW(user.User.Sid, &mut sid_text) != 0,
                "SID conversion failed"
            );
            let mut len = 0;
            while *sid_text.add(len) != 0 {
                len += 1;
            }
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid_text, len));
            LocalFree(sid_text.cast());
            let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)")
                .encode_utf16()
                .chain([0])
                .collect();
            let mut descriptor = ptr::null_mut();
            ensure!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    ptr::null_mut()
                ) != 0,
                "ACL descriptor failed"
            );
            let mut present = 0;
            let mut defaulted = 0;
            let mut acl = ptr::null_mut();
            let descriptor_ok =
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted);
            let name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
            let code = if descriptor_ok != 0 && present != 0 {
                SetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl,
                    ptr::null_mut(),
                )
            } else {
                1
            };
            LocalFree(descriptor);
            ensure!(code == 0, "Private state ACL failed: {code}");
            Ok(())
        })();
        CloseHandle(token);
        result
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("Missing parent directory")?;
    let temp = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(not(windows))]
        fs::rename(&temp, path)?;
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
            };
            let from: Vec<u16> = temp.as_os_str().encode_wide().chain([0]).collect();
            let to: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
            // SAFETY: both paths are valid null-terminated UTF-16 buffers.
            let moved = unsafe {
                MoveFileExW(
                    from.as_ptr(),
                    to.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            ensure!(
                moved != 0,
                "Atomic replace failed: {}",
                std::io::Error::last_os_error()
            );
        }
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Open a regular lock file without following a final symlink/reparse point.
/// The caller owns the advisory lock; this helper never truncates lock state.
pub fn lock_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    ensure!(file.metadata()?.is_file(), "Lock must be a regular file");
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        ensure!(
            file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "Reparse-point lock rejected"
        );
    }
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Symlink lock rejected"
    );
    Ok(file)
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(bytes.len() <= 5 * 1024 * 1024, "JSON state exceeds limit");
    atomic_write(path, &bytes)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let mut bytes = Vec::new();
    open_regular(path)?
        .take(5 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 5 * 1024 * 1024, "JSON file exceeds limit");
    Ok(serde_json::from_slice(&bytes)?)
}

/// Refuse symlinks/reparse points and special files. Bound all reads separately.
pub fn open_regular(path: &Path) -> Result<File> {
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Symlink skipped"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "Not a regular file");
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "Reparse point skipped"
        );
    }
    Ok(file)
}

/// Identify the opened object, rather than trusting a reusable pathname.
pub fn file_identity(file: &File) -> Result<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        // SAFETY: this Win32 plain-data output structure permits zero initialization.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the handle belongs to the live File and info is an initialized,
        // writable structure; the checked API call does not retain pointers.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn opened_file_identity_survives_rename_and_distinguishes_a_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("inert.txt");
        fs::write(&path, b"ordinary fixture").unwrap();
        let file = open_regular(&path).unwrap();
        let identity = file_identity(&file).unwrap();
        fs::rename(&path, root.path().join("renamed.txt")).unwrap();
        fs::write(&path, b"ordinary fixture").unwrap();
        assert_eq!(file_identity(&file).unwrap(), identity);
        assert_ne!(
            file_identity(&open_regular(&path).unwrap()).unwrap(),
            identity
        );
    }

    #[test]
    fn rename_preserves_legacy_state_and_refuses_ambiguous_vaults() -> Result<()> {
        let root = tempfile::tempdir()?;
        let current = root.path().join("FerXium");
        let legacy = root.path().join("AegisGuard");
        assert_eq!(select_data_dir(current.clone(), legacy.clone())?, current);
        fs::create_dir(&legacy)?;
        fs::write(legacy.join("key.bin"), b"existing-vault-key")?;
        assert_eq!(select_data_dir(current.clone(), legacy.clone())?, legacy);
        assert!(!current.exists());
        fs::create_dir(&current)?;
        assert!(select_data_dir(current, legacy.clone()).is_err());
        assert_eq!(fs::read(legacy.join("key.bin"))?, b"existing-vault-key");
        Ok(())
    }
}
