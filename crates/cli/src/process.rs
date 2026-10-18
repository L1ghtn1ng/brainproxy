//! Background processes (proxy, OOB listener, jobs, browsers): detaching, telling a live
//! process from a later one reusing its pid, and stopping one cleanly.
//!
//! A stop is requested through the project database (`request_stop`), which the process
//! polls (`shutdown`); on Unix it also gets SIGTERM. Windows has no SIGTERM, so the
//! database flag is how it learns to flush and exit there.

use std::process::Command;
use std::time::{Duration, Instant};

use brainproxy_core::store::Store;
use brainproxy_core::Error;

/// Starts `cmd` detached from this process: its own process group (no signals or Ctrl-C
/// from our terminal) and, on Windows, no console window.
pub(crate) fn detach(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
        use windows_sys::Win32::System::Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
        // A child inherits every inheritable handle we hold, including our own stdout pipe:
        // whoever reads our output (the app, a script) would then wait until the child exits.
        // The child's stdio is given explicitly, as inheritable copies, so it still gets those.
        for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            unsafe {
                let h = GetStdHandle(id);
                if !h.is_null() {
                    SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
                }
            }
        }
    }
}

/// Asks the process recorded as `pid` under `key` to stop; see [`shutdown`].
pub(crate) fn request_stop(store: &Store, key: &str, pid: u32) -> Result<(), Error> {
    store.meta_set(key, Some(&pid.to_string()))
}

/// Resolves on Ctrl-C, SIGTERM (Unix), or once `request_stop(store, key, our pid)` was called.
/// Clears a stale request for our pid first.
pub(crate) async fn shutdown(store: &Store, key: &str) {
    let me = std::process::id().to_string();
    let _ = store.meta_set(key, None);
    let flagged = async {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if store.meta_get(key).ok().flatten().as_deref() == Some(me.as_str()) {
                let _ = store.meta_set(key, None);
                return;
            }
        }
    };
    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut t) => {
                t.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term => {}
        _ = flagged => {}
    }
}

/// Whether `pid` is a live process we may stop.
pub(crate) fn alive(pid: u32) -> bool {
    sys::alive(pid)
}

/// When `pid` started, as an opaque number: tells a process from a later one reusing its pid.
pub(crate) fn start_time(pid: u32) -> Option<u64> {
    sys::start_time(pid)
}

/// Whether the process recorded as `pid`, started at `start`, still runs: `Some(false)`
/// when it is gone or the pid now belongs to another process, `None` when the pid is
/// alive but there is no start time to compare (state from an older version).
pub(crate) fn still_running(pid: u32, start: Option<u64>) -> Option<bool> {
    if !alive(pid) {
        return Some(false);
    }
    start.map(|s| start_time(pid) == Some(s))
}

/// Stops the process recorded as (`pid`, `start`), after the caller's `request_stop`: on
/// Unix SIGTERM too, then a forced kill after 5 s. Returns whether the kill was needed. A
/// process that can't be verified is never killed.
pub(crate) fn terminate(pid: u32, start: Option<u64>, what: &str) -> Result<bool, Error> {
    let gone = || still_running(pid, start) == Some(false);
    if gone() {
        return Ok(false);
    }
    sys::ask_to_exit(pid);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !gone() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if gone() {
        return Ok(false);
    }
    if start.is_none() {
        return Err(Error::Conflict(format!(
            "pid {pid} is still running after being asked to stop. Its {what} state comes from an older brainproxy \
             without a process start time, so it can't be verified as the {what}; not sending SIGKILL. Check pid \
             {pid} yourself and stop it if it is the {what}"
        )));
    }
    sys::kill(pid);
    Ok(true)
}

#[cfg(unix)]
mod sys {
    /// `pid` as a pid_t that is safe to signal: 0, 1 and anything that turns negative
    /// (`kill(0|-1|-n)` hits a process group or every process) are refused.
    fn pid_t(pid: u32) -> Option<libc::pid_t> {
        libc::pid_t::try_from(pid).ok().filter(|&p| p > 1)
    }

    /// Signal 0 checks without delivering anything; EPERM means another user's process,
    /// which is not ours.
    pub fn alive(pid: u32) -> bool {
        pid_t(pid).is_some_and(|p| unsafe { libc::kill(p, 0) } == 0)
    }

    pub fn ask_to_exit(pid: u32) {
        if let Some(p) = pid_t(pid) {
            unsafe { libc::kill(p, libc::SIGTERM) };
        }
    }

    pub fn kill(pid: u32) {
        if let Some(p) = pid_t(pid) {
            unsafe { libc::kill(p, libc::SIGKILL) };
        }
    }

    #[cfg(target_os = "macos")]
    pub fn start_time(pid: u32) -> Option<u64> {
        let p = pid_t(pid)?;
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let ptr = (&mut info as *mut libc::proc_bsdinfo).cast();
        let n = unsafe { libc::proc_pidinfo(p, libc::PROC_PIDTBSDINFO, 0, ptr, size) };
        (n == size).then(|| info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
    }

    #[cfg(target_os = "linux")]
    pub fn start_time(pid: u32) -> Option<u64> {
        // Field 22 (clock ticks since boot); the fields after `(comm)` start at 3.
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid_t(pid)?)).ok()?;
        stat.rsplit_once(')')?.1.split_whitespace().nth(19)?.parse().ok()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub fn start_time(_: u32) -> Option<u64> {
        None
    }
}

#[cfg(windows)]
mod sys {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_TERMINATE,
    };

    const STILL_ACTIVE: u32 = 259;

    /// An open process handle, closed on drop. Pids 0 (idle) and 4 (System) are refused.
    struct Process(HANDLE);

    impl Process {
        fn open(pid: u32, access: u32) -> Option<Self> {
            if pid <= 4 {
                return None;
            }
            let h = unsafe { OpenProcess(access, 0, pid) };
            (!h.is_null()).then_some(Self(h))
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn alive(pid: u32) -> bool {
        let Some(p) = Process::open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else { return false };
        let mut code = 0u32;
        (unsafe { GetExitCodeProcess(p.0, &mut code) } != 0) && code == STILL_ACTIVE
    }

    /// Nothing to send: the caller's `request_stop` flag is how a Windows process is asked.
    pub fn ask_to_exit(_: u32) {}

    pub fn kill(pid: u32) {
        if let Some(p) = Process::open(pid, PROCESS_TERMINATE) {
            unsafe { TerminateProcess(p.0, 1) };
        }
    }

    pub fn start_time(pid: u32) -> Option<u64> {
        let p = Process::open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        let ok = unsafe { GetProcessTimes(p.0, &mut created, &mut exited, &mut kernel, &mut user) };
        (ok != 0).then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_identity() {
        for bad in [0, 1, u32::MAX, i32::MAX as u32 + 1] {
            assert!(!alive(bad) && start_time(bad).is_none(), "{bad}");
        }
        let me = std::process::id();
        let start = start_time(me);
        assert!(start.is_some() && start == start_time(me));
        assert_eq!(still_running(me, start), Some(true));
        assert_eq!(still_running(me, start.map(|s| s + 1)), Some(false));
        assert_eq!(still_running(me, None), None);
    }
}
