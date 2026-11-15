//! Linux user and mount namespace jail.
//!
//! Before `exec`, the child calls `unshare(CLONE_NEWUSER | CLONE_NEWNS)` and
//! bind-mounts a tmpfs copy of each env file over the workspace original.
//! Reads such as `cat .env` return phantom values. The host mount namespace
//! is unchanged, so the real files stay intact.
//!
//! macOS has no mount namespaces. Containers that block `CLONE_NEWUSER` also
//! cannot do this. Both cases print a warning and continue with phantom
//! environment variables plus the egress proxy only.

use crate::{Error, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

#[derive(Debug, Clone)]
pub struct Overlay {
    pub target: PathBuf,
    pub contents: String,
}

#[derive(Debug, Clone)]
pub struct JailPlan {
    pub workspace: PathBuf,
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub overlays: Vec<Overlay>,
    pub masks: Vec<PathBuf>,
    pub capture: bool,
}

pub struct Launch {
    pub pid: i32,
    pub namespaced: bool,
    pub warning: Option<String>,
    stdout: Option<i32>,
    stderr: Option<i32>,
}

pub struct Captured {
    pub namespaced: bool,
    pub warning: Option<String>,
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

enum SpawnError {
    Unsupported(String),
    Fatal(Error),
}

impl SpawnError {
    fn into_error(self) -> Error {
        match self {
            Self::Unsupported(reason) => Error::new(reason),
            Self::Fatal(err) => err,
        }
    }
}

pub fn launch(plan: JailPlan) -> Result<Launch> {
    let plan = prepare(plan)?;
    #[cfg(target_os = "linux")]
    {
        match try_spawn(&plan, true) {
            Ok(mut child) => {
                child.namespaced = true;
                Ok(child)
            }
            Err(SpawnError::Unsupported(reason)) => {
                let warning = format!(
                    "user/mount namespaces are unavailable ({reason}). Continuing in env+proxy mode; workspace env files and credential files are not masked."
                );
                eprintln!("keyalibi: {warning}");
                let mut child = try_spawn(&plan, false).map_err(SpawnError::into_error)?;
                child.namespaced = false;
                child.warning = Some(warning);
                Ok(child)
            }
            Err(SpawnError::Fatal(err)) => Err(err),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let warning = "mount namespaces are a Linux feature. Continuing in env+proxy mode; workspace env files and credential files are not masked.".to_string();
        eprintln!("keyalibi: {warning}");
        let mut child = try_spawn(&plan, false).map_err(SpawnError::into_error)?;
        child.namespaced = false;
        child.warning = Some(warning);
        Ok(child)
    }
}

pub fn capture(mut plan: JailPlan) -> Result<Captured> {
    plan.capture = true;
    let child = launch(plan)?;
    let namespaced = child.namespaced;
    let warning = child.warning.clone();
    let output = child.wait_with_output()?;
    Ok(Captured {
        namespaced,
        warning,
        status: output.0,
        stdout: output.1,
        stderr: output.2,
    })
}

impl Launch {
    pub fn wait(mut self) -> Result<ExitStatus> {
        let status = wait_pid(self.pid)?;
        self.pid = -1;
        Ok(status)
    }

    pub fn wait_with_output(mut self) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
        let stdout = read_fd_thread(self.stdout.take());
        let stderr = read_fd_thread(self.stderr.take());
        let status = wait_pid(self.pid)?;
        self.pid = -1;
        let stdout = join_reader(stdout);
        let stderr = join_reader(stderr);
        Ok((status, stdout, stderr))
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        if self.pid > 0 {
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(self.pid, &mut status, 0);
            }
            self.pid = -1;
        }
        close_fd(self.stdout.take());
        close_fd(self.stderr.take());
    }
}

fn prepare(mut plan: JailPlan) -> Result<JailPlan> {
    if plan.argv.is_empty() {
        return Err(Error::new("jail command is empty"));
    }
    plan.workspace = plan
        .workspace
        .canonicalize()
        .map_err(|err| Error::new(format!("workspace: {err}")))?;
    for overlay in &mut plan.overlays {
        if overlay.target.is_relative() {
            overlay.target = plan.workspace.join(&overlay.target);
        }
    }
    Ok(plan)
}

fn try_spawn(plan: &JailPlan, attempt_namespace: bool) -> std::result::Result<Launch, SpawnError> {
    #[cfg(not(target_os = "linux"))]
    {
        if attempt_namespace {
            return Err(SpawnError::Unsupported("not Linux".to_string()));
        }
    }
    let (stdout_r, stdout_w, stderr_r, stderr_w) = if plan.capture {
        let (out_r, out_w) =
            pipe().map_err(|err| SpawnError::Fatal(Error::new(err.to_string())))?;
        let (err_r, err_w) =
            pipe().map_err(|err| SpawnError::Fatal(Error::new(err.to_string())))?;
        (Some(out_r), Some(out_w), Some(err_r), Some(err_w))
    } else {
        (None, None, None, None)
    };
    let (c2p_r, c2p_w) = pipe().map_err(|err| SpawnError::Fatal(Error::new(err.to_string())))?;
    let (p2c_r, p2c_w) = pipe().map_err(|err| SpawnError::Fatal(Error::new(err.to_string())))?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        close_fd(Some(c2p_r));
        close_fd(Some(c2p_w));
        close_fd(Some(p2c_r));
        close_fd(Some(p2c_w));
        close_fd(stdout_r);
        close_fd(stdout_w);
        close_fd(stderr_r);
        close_fd(stderr_w);
        return Err(SpawnError::Fatal(Error::new(
            std::io::Error::last_os_error().to_string(),
        )));
    }
    if pid == 0 {
        close_fd(Some(c2p_r));
        close_fd(Some(p2c_w));
        close_fd(stdout_r);
        close_fd(stderr_r);
        let code = child_main(plan, attempt_namespace, c2p_w, p2c_r, stdout_w, stderr_w);
        unsafe { libc::_exit(code) };
    }

    unsafe {
        libc::setpgid(pid, pid);
    }
    close_fd(Some(c2p_w));
    close_fd(Some(p2c_r));
    close_fd(stdout_w);
    close_fd(stderr_w);

    let first = read_line(c2p_r).unwrap_or_default();
    if first.starts_with('E') || first.is_empty() {
        let _ = wait_pid(pid);
        close_fd(Some(c2p_r));
        close_fd(Some(p2c_w));
        close_fd(stdout_r);
        close_fd(stderr_r);
        let reason = match first.strip_prefix('E') {
            Some(rest) => rest.to_string(),
            None => "child exited before entering the namespace".to_string(),
        };
        return Err(SpawnError::Unsupported(reason));
    }

    crate::harden::set_dumpable_off();
    if first.starts_with('U') {
        if let Err(err) = write_id_maps(pid) {
            let _ = write_all(p2c_w, b"X\n");
            let _ = wait_pid(pid);
            close_fd(Some(c2p_r));
            close_fd(Some(p2c_w));
            close_fd(stdout_r);
            close_fd(stderr_r);
            return Err(SpawnError::Unsupported(format!("uid_map: {err}")));
        }
    }
    if write_all(p2c_w, b"G\n").is_err() {
        let _ = wait_pid(pid);
        close_fd(Some(c2p_r));
        close_fd(Some(p2c_w));
        close_fd(stdout_r);
        close_fd(stderr_r);
        return Err(SpawnError::Fatal(Error::new(
            "failed to release the jailed child",
        )));
    }
    let second = read_line(c2p_r).unwrap_or_default();
    close_fd(Some(c2p_r));
    close_fd(Some(p2c_w));
    if second.starts_with('F') || second.is_empty() || !second.starts_with('R') {
        let _ = wait_pid(pid);
        close_fd(stdout_r);
        close_fd(stderr_r);
        let reason = if let Some(stripped) = second.strip_prefix('F') {
            stripped.to_string()
        } else {
            "namespace setup failed".to_string()
        };
        if is_unsupported(&reason) || second.is_empty() {
            return Err(SpawnError::Unsupported(reason));
        }
        return Err(SpawnError::Fatal(Error::new(reason)));
    }

    Ok(Launch {
        pid,
        namespaced: attempt_namespace,
        warning: None,
        stdout: stdout_r,
        stderr: stderr_r,
    })
}

fn is_unsupported(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("not permitted")
        || lower.contains("operation not supported")
        || lower.contains("eperm")
        || lower.contains("eopnotsupp")
        || lower.contains("user namespace")
}

fn child_main(
    plan: &JailPlan,
    attempt_namespace: bool,
    c2p_w: i32,
    p2c_r: i32,
    stdout_w: Option<i32>,
    stderr_w: Option<i32>,
) -> i32 {
    if attempt_namespace {
        #[cfg(target_os = "linux")]
        {
            let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                let _ = write_all(c2p_w, format!("E{err}\n").as_bytes());
                return 111;
            }
            let _ = write_all(c2p_w, b"U\n");
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = write_all(c2p_w, b"Enot Linux\n");
            return 111;
        }
    } else {
        let _ = write_all(c2p_w, b"P\n");
    }
    let go = read_line(p2c_r).unwrap_or_default();
    if go != "G" {
        return 111;
    }
    if attempt_namespace {
        #[cfg(target_os = "linux")]
        if let Err(err) = setup_mounts(plan) {
            let _ = write_all(c2p_w, format!("F{err}\n").as_bytes());
            return 112;
        }
    }
    let _ = write_all(c2p_w, b"R\n");
    if let Some(fd) = stdout_w {
        unsafe {
            libc::dup2(fd, libc::STDOUT_FILENO);
            libc::close(fd);
        }
    }
    if let Some(fd) = stderr_w {
        unsafe {
            libc::dup2(fd, libc::STDERR_FILENO);
            libc::close(fd);
        }
    }
    unsafe {
        libc::close(c2p_w);
        libc::close(p2c_r);
        libc::setpgid(0, 0);
    }
    let mut command = std::process::Command::new(&plan.argv[0]);
    command
        .args(&plan.argv[1..])
        .env_clear()
        .envs(plan.env.iter().cloned())
        .current_dir(&plan.workspace);
    use std::os::unix::process::CommandExt;
    let err = command.exec();
    let message = format!("keyalibi: exec failed: {err}\n");
    let _ = std::io::stderr().write_all(message.as_bytes());
    127
}

#[cfg(target_os = "linux")]
fn setup_mounts(plan: &JailPlan) -> std::io::Result<()> {
    use nix::mount::{mount, MsFlags};
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|err| std::io::Error::other(err.to_string()))?;

    let base = std::env::temp_dir().join(format!("keyalibi-ns-{}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    mount(
        Some("tmpfs"),
        &base,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=0700"),
    )
    .map_err(|err| std::io::Error::other(err.to_string()))?;

    for (index, overlay) in plan.overlays.iter().enumerate() {
        if !overlay.target.is_file() {
            continue;
        }
        let src = base.join(format!("overlay-{index}"));
        std::fs::write(&src, &overlay.contents)?;
        mount(
            Some(&src),
            overlay.target.as_path(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    }
    for (index, mask) in plan.masks.iter().enumerate() {
        if !mask.is_file() {
            continue;
        }
        let src = base.join(format!("mask-{index}"));
        std::fs::write(
            &src,
            "# Replaced by KeyAlibi for this session. The host file is unchanged.\n",
        )?;
        mount(
            Some(&src),
            mask.as_path(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_id_maps(pid: i32) -> std::io::Result<()> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    std::fs::write(format!("/proc/{pid}/setgroups"), "deny")?;
    std::fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1\n"))?;
    std::fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1\n"))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn write_id_maps(_pid: i32) -> std::io::Result<()> {
    Err(std::io::Error::other("user namespaces are Linux-only"))
}

fn pipe() -> std::io::Result<(i32, i32)> {
    let mut fds = [0; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

fn read_line(fd: i32) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = unsafe { libc::read(fd, byte.as_mut_ptr() as *mut libc::c_void, 1) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > 4000 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn write_all(fd: i32, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(std::io::Error::other("short write"));
        }
        data = &data[n as usize..];
    }
    Ok(())
}

fn close_fd(fd: Option<i32>) {
    if let Some(fd) = fd {
        unsafe { libc::close(fd) };
    }
}

fn wait_pid(pid: i32) -> Result<ExitStatus> {
    let mut status = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::new(err.to_string()));
        }
        break;
    }
    Ok(ExitStatus::from_raw(status))
}

fn read_fd_thread(fd: Option<i32>) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    fd.map(|fd| {
        std::thread::spawn(move || {
            let mut file = unsafe { File::from_raw_fd(fd) };
            let mut buf = Vec::new();
            let _ = file.read_to_end(&mut buf);
            buf
        })
    })
}

fn join_reader(handle: Option<std::thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default()
}

use std::os::unix::io::FromRawFd;

/// Helper used by `keyalibi run` when a mask path uses `~`.
pub fn existing_file(path: &Path) -> bool {
    path.is_file()
}
