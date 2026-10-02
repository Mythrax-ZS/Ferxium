//! Fail closed: a current-user service must not silently become an admin broker.
use anyhow::Result;

pub fn require_regular_user() -> Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no arguments and does not expose owned pointers.
        let uid = unsafe { libc::geteuid() };
        anyhow::ensure!(uid != 0, "Run FerXium as a regular user, not root");
    }
    #[cfg(windows)]
    {
        use std::ptr;
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };
        let mut token = ptr::null_mut();
        // SAFETY: output handle is initialized; returned handle is closed below.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        anyhow::ensure!(opened != 0, "Cannot inspect process privileges");
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0;
        // SAFETY: elevation points to a correctly sized TOKEN_ELEVATION and the
        // token is valid until CloseHandle; no pointer escapes this function.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        };
        // SAFETY: token is the owned handle returned by OpenProcessToken.
        unsafe { CloseHandle(token) };
        anyhow::ensure!(ok != 0, "Cannot inspect token elevation");
        anyhow::ensure!(
            elevation.TokenIsElevated == 0,
            "Run FerXium as your normal user, not from an elevated terminal"
        );
    }
    Ok(())
}
