//! Best-effort hardening for the supervisor process.
//!
//! `PR_SET_DUMPABLE=0` stops the child (and any other same-user process) from
//! ptracing the supervisor or reading `/proc/<pid>/mem`. It must be applied
//! *after* `fork` when the child still needs the parent to write `uid_map`:
//! a non-dumpable child cannot have its id maps written by the parent.
//!
//! `mlock` is applied to the secret bytes themselves. `mlockall(MCL_FUTURE)`
//! is intentionally not used: unprivileged processes typically have a small
//! `RLIMIT_MEMLOCK` (often 8 MiB) and cannot raise the hard limit, so locking
//! every future allocation would make the proxy fail once that cap is hit.

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// Mark this process as non-dumpable. Returns the previous prctl result code
/// (`0` on success) without failing the caller: some sandboxes block prctl.
pub fn set_dumpable_off() -> i32 {
    // SAFETY: prctl(PR_SET_DUMPABLE) is a process-wide flag with no pointer
    // arguments. The remaining args are documented as unused and must be zero.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }
}

/// Lock the pages that currently hold `bytes`. Failure is ignored; the caller
/// still zeroizes on drop.
pub fn mlock_slice(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    // SAFETY: mlock rounds the address down to a page and the length up. The
    // slice is a valid live allocation for the duration of the call.
    unsafe {
        libc::mlock(bytes.as_ptr() as *const libc::c_void, bytes.len());
    }
}

pub fn mlock_secret(secret: &SecretString) {
    mlock_slice(secret.expose_secret().as_bytes());
}

/// A byte buffer that is wiped on drop and locked while it is alive.
pub struct LockedBytes {
    bytes: Zeroizing<Vec<u8>>,
}

impl LockedBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        mlock_slice(&bytes);
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for LockedBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
