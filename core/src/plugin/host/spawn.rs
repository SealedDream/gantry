//! Starting `bastion-plugin-host` with exactly its two pipe ends and an empty environment
//! (spec section 5; PLUG-01 decisions 9 and 10, question 14).
//!
//! - macOS and Linux: `posix_spawn`, the two pipe ends on the helper's descriptors 0 and 1,
//!   descriptor 2 on `/dev/null`, nothing else (`CLOEXEC_DEFAULT` on macOS, a `closefrom(3)`
//!   action on Linux), working directory `/`, signals reset. The core's own pipe ends are close-on-exec, made
//!   so under `SPAWN_LOCK` (macOS has no `pipe2`).
//! - Windows: the pipe ends are never inheritable. The helper starts suspended; the core
//!   duplicates the two ends into it, writes their values into a one-shot start-up pipe (the only
//!   handle the helper inherits), puts it in a job object (one process, a memory cap, killed when
//!   the core's handle closes) and resumes it. It starts inside an AppContainer with no
//!   capabilities (PLUG-05), so it has no network and cannot open the user's files. Windows will
//!   not start an AppContainer process with an empty environment (error 203), so the block holds
//!   `LOCALAPPDATA` only, which Windows then points at the AppContainer's own folder.
//!
//! The macOS sandbox (`sandbox_init`) is applied by the helper itself (PLUG-05). On macOS the
//! memory cap goes to the helper as `--memory-cap=<bytes>` (PLUG-01 part 2, `plugin-host/src/limits.rs`).

use std::fs::File;
use std::io;
use std::path::Path;

use bastion_plugin_host::proto::Role;

/// A started helper: its pid, the core's two pipe ends and the process.
pub struct Child {
    pub pid: u32,
    /// Core writes, helper reads. Taken by the running helper's writer.
    pub to_helper: Option<File>,
    /// Helper writes, core reads. Taken by the running helper's reader thread.
    pub from_helper: Option<File>,
    process: imp::Process,
}

impl Child {
    /// Ends the helper at once. Safe to call more than once.
    pub fn kill(&mut self) {
        self.process.kill();
    }

    /// `Some(code)` once the helper has exited (a negative code is the signal on macOS).
    pub fn try_wait(&mut self) -> Option<i32> {
        self.process.try_wait()
    }
}

fn args(role: Role) -> &'static [&'static str] {
    match role {
        Role::View => &[],
        Role::Compile => &["--compile"],
    }
}

/// Starts the helper at `program` in `role`. `memory_cap` is the process's memory cap: committed
/// memory in the Windows job object; physical footprint on macOS, enforced by the helper's
/// watchdog and checked by the core from outside.
pub fn spawn(program: &Path, role: Role, memory_cap: u64) -> io::Result<Child> {
    imp::spawn(program, args(role), memory_cap)
}

/// macOS: ends (SIGKILL) every process running `program` that belongs to this user and whose
/// parent is launchd (pid 1), that is, a helper whose core is gone. Returns how many it ended.
/// A helper leaves by itself when its pipe closes, but one that escaped Wasmtime may not (T18.4).
#[cfg(target_os = "macos")]
pub fn kill_orphaned_helpers(program: &Path) -> usize {
    let Ok(target) = program.canonicalize() else { return 0 };
    // SAFETY: a null buffer with size 0 asks for the count only.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return 0;
    }
    let mut pids = vec![0 as libc::pid_t; count as usize + 64];
    let bytes = (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
    // SAFETY: the buffer holds `bytes` bytes.
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    // SAFETY: a plain syscall.
    let uid = unsafe { libc::getuid() };
    let mut ended = 0;
    for &pid in pids.iter().take(n.max(0) as usize) {
        // SAFETY: a plain syscall; the signal cannot be caught.
        if pid > 1 && is_orphaned_copy(pid, uid, &target) && unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
            ended += 1;
        }
    }
    ended
}

#[cfg(target_os = "macos")]
fn is_orphaned_copy(pid: libc::pid_t, uid: libc::uid_t, target: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: all-zero is a valid proc_bsdinfo.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` is a proc_bsdinfo, the flavour asked for.
    let got = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size) };
    if got != size || info.pbi_ppid != 1 || info.pbi_uid != uid {
        return false;
    }
    let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer holds the maximum path size.
    let len = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    if len <= 0 {
        return false;
    }
    path.truncate(len as usize);
    Path::new(std::ffi::OsStr::from_bytes(&path)).canonicalize().is_ok_and(|p| p == target)
}

/// Elsewhere the OS ends the helper with the core (the Windows job object), or no app ships.
#[cfg(not(target_os = "macos"))]
pub fn kill_orphaned_helpers(_program: &Path) -> usize {
    0
}

#[cfg(unix)]
pub use imp::SPAWN_LOCK;

/// Windows has no fork window, but `spawn_guard` is called on every platform, so the lock
/// exists here too and still keeps child starts from overlapping.
#[cfg(not(unix))]
pub static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Takes `SPAWN_LOCK` for the start of any other child of the core (PLUG-02b part 2): while a
/// helper's pipe is being made, no other child may start, or it could inherit a pipe end before
/// the end is close-on-exec. Hold the guard only across the spawn call itself.
pub fn spawn_guard() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(windows)]
pub(crate) use imp::is_app_container;

#[cfg(unix)]
mod imp {
    use super::Child;
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::Mutex;

    /// Held from `pipe` until both new ends are close-on-exec. Any core code that starts a child
    /// with `fork`/`exec` or a plain `posix_spawn` must hold it too, or that child can inherit a
    /// helper's pipe end in the window (PLUG-01 question 14).
    pub static SPAWN_LOCK: Mutex<()> = Mutex::new(());

    pub struct Process {
        pid: libc::pid_t,
        exited: Option<i32>,
    }

    impl Process {
        pub fn kill(&mut self) {
            if self.exited.is_none() {
                // SAFETY: a plain syscall on a pid we started and have not reaped.
                unsafe { libc::kill(self.pid, libc::SIGKILL) };
            }
        }

        pub fn try_wait(&mut self) -> Option<i32> {
            if self.exited.is_none() {
                let mut status = 0;
                // SAFETY: a valid out-pointer; WNOHANG never blocks.
                let reaped = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
                if reaped == self.pid {
                    self.exited = Some(if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -libc::WTERMSIG(status) });
                }
            }
            self.exited
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            self.kill();
            // Reap it so no zombie is left; after SIGKILL this returns at once.
            if self.exited.is_none() {
                let mut status = 0;
                // SAFETY: as in `try_wait`, blocking this time.
                unsafe { libc::waitpid(self.pid, &mut status, 0) };
            }
        }
    }

    /// A pipe whose two ends are close-on-exec in the core.
    fn pipe() -> io::Result<(libc::c_int, libc::c_int)> {
        let _window = SPAWN_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut fds = [0; 2];
        // SAFETY: `fds` holds two ints, as pipe(2) requires.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for fd in fds {
            // SAFETY: both descriptors were just created and are ours.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
                let error = io::Error::last_os_error();
                close(&fds);
                return Err(error);
            }
        }
        Ok((fds[0], fds[1]))
    }

    fn close(fds: &[libc::c_int]) {
        for fd in fds {
            // SAFETY: each descriptor is open and owned here.
            unsafe { libc::close(*fd) };
        }
    }

    const DEV_NULL: &std::ffi::CStr = c"/dev/null";
    const ROOT: &std::ffi::CStr = c"/";

    /// Everything the helper starts with besides its two pipe ends: descriptor 2 on `/dev/null`,
    /// every other descriptor closed, `/` as its working directory, no blocked signals and every
    /// signal at its default (the core ignores `SIGPIPE`; the helper must not inherit that).
    /// Returns the first non-zero result. File actions run in order, after the two `dup2`s.
    ///
    /// SAFETY: `actions` and `attr` are initialised by the caller.
    unsafe fn prepare(actions: &mut libc::posix_spawn_file_actions_t, attr: &mut libc::posix_spawnattr_t) -> libc::c_int {
        unsafe {
            let mut none: libc::sigset_t = std::mem::zeroed();
            let mut all: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut none);
            libc::sigfillset(&mut all);
            #[allow(unused_mut)]
            let mut flags = libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF;
            // macOS: every descriptor not named by a file action is closed in the helper.
            #[cfg(target_os = "macos")]
            {
                flags |= libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
            }
            let steps = [
                libc::posix_spawn_file_actions_addopen(actions, 2, DEV_NULL.as_ptr(), libc::O_WRONLY, 0),
                libc::posix_spawn_file_actions_addchdir_np(actions, ROOT.as_ptr()),
                // Linux (glibc 2.34+; dev and test hosts only, no app ships there): close the rest.
                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                libc::posix_spawn_file_actions_addclosefrom_np(actions, 3),
                libc::posix_spawnattr_setsigmask(attr, &none),
                libc::posix_spawnattr_setsigdefault(attr, &all),
                libc::posix_spawnattr_setflags(attr, flags as libc::c_short),
            ];
            steps.into_iter().find(|rc| *rc != 0).unwrap_or(0)
        }
    }

    #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
    pub fn spawn(_program: &Path, _args: &[&str], _memory_cap: u64) -> io::Result<Child> {
        // No way to close inherited descriptors is wired up here; refuse rather than leak.
        Err(io::Error::new(io::ErrorKind::Unsupported, "plugin helpers are not supported on this OS"))
    }

    #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
    pub fn spawn(program: &Path, args: &[&str], memory_cap: u64) -> io::Result<Child> {
        let path = CString::new(program.as_os_str().as_bytes())?;
        let mut owned = vec![path.clone()];
        for arg in args {
            owned.push(CString::new(*arg)?);
        }
        // The helper enforces this itself (its footprint watchdog) and the core checks it from
        // outside (`helper.rs`, `watch`): macOS has no job object (PLUG-01 part 2).
        owned.push(CString::new(format!("--memory-cap={}", memory_cap.max(1)))?);
        let mut argv: Vec<*mut libc::c_char> = owned.iter().map(|a| a.as_ptr() as *mut _).collect();
        argv.push(std::ptr::null_mut());
        // An empty environment: the array holds only its terminator.
        let envp: [*mut libc::c_char; 1] = [std::ptr::null_mut()];

        let (helper_in, core_out) = pipe()?;
        let (core_in, helper_out) = match pipe() {
            Ok(p) => p,
            Err(e) => {
                close(&[helper_in, core_out]);
                return Err(e);
            }
        };
        let mut pid: libc::pid_t = 0;
        // SAFETY: the action and attribute objects are initialised before use and destroyed
        // after; argv and envp are NUL-terminated arrays of C strings that outlive the call.
        let rc = unsafe {
            let mut actions: libc::posix_spawn_file_actions_t = std::mem::zeroed();
            let mut attr: libc::posix_spawnattr_t = std::mem::zeroed();
            libc::posix_spawn_file_actions_init(&mut actions);
            libc::posix_spawnattr_init(&mut attr);
            libc::posix_spawn_file_actions_adddup2(&mut actions, helper_in, 0);
            libc::posix_spawn_file_actions_adddup2(&mut actions, helper_out, 1);
            let prepared = prepare(&mut actions, &mut attr);
            let rc = if prepared != 0 { prepared } else { libc::posix_spawn(&mut pid, path.as_ptr(), &actions, &attr, argv.as_ptr(), envp.as_ptr()) };
            libc::posix_spawn_file_actions_destroy(&mut actions);
            libc::posix_spawnattr_destroy(&mut attr);
            rc
        };
        close(&[helper_in, helper_out]);
        if rc != 0 {
            close(&[core_out, core_in]);
            return Err(io::Error::from_raw_os_error(rc));
        }
        // SAFETY: both descriptors are open, owned here and used nowhere else.
        let (to_helper, from_helper) = unsafe { (File::from_raw_fd(core_out), File::from_raw_fd(core_in)) };
        Ok(Child { pid: pid as u32, to_helper: Some(to_helper), from_helper: Some(from_helper), process: Process { pid, exited: None } })
    }
}

#[cfg(windows)]
mod imp {
    use super::Child;
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, SetHandleInformation, DUPLICATE_SAME_ACCESS, HANDLE, HANDLE_FLAG_INHERIT, STILL_ACTIVE};
    use windows_sys::Win32::Security::Isolation::{CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName};
    use windows_sys::Win32::Security::{FreeSid, GetTokenInformation, TokenIsAppContainer, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, TOKEN_QUERY};
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess, InitializeProcThreadAttributeList, OpenProcess,
        OpenProcessToken, ResumeThread, TerminateProcess, UpdateProcThreadAttribute, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };

    /// The helper's AppContainer. One profile for every helper; it has no capabilities.
    pub const APP_CONTAINER_NAME: &str = "Bastion.PluginHelper";
    const ERROR_ALREADY_EXISTS_HRESULT: i32 = 0x800700B7u32 as i32;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Sid(PSID);
    impl Drop for Sid {
        fn drop(&mut self) {
            // SAFETY: a SID from CreateAppContainerProfile or DeriveAppContainerSidFromAppContainerName.
            unsafe { FreeSid(self.0) };
        }
    }

    /// Creates the AppContainer profile once per app start. Calls from several threads at once
    /// fail with E_UNEXPECTED or "path not found" even when it exists (PLUG-01, question 8).
    fn ensure_profile() -> io::Result<()> {
        static PROFILE: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
        PROFILE
            .get_or_init(|| {
                let name = wide(APP_CONTAINER_NAME);
                let mut sid: PSID = null_mut();
                // SAFETY: valid NUL-terminated strings and out-pointer; no capabilities.
                let hr = unsafe { CreateAppContainerProfile(name.as_ptr(), name.as_ptr(), name.as_ptr(), null(), 0, &mut sid) };
                match hr {
                    0 => {
                        drop(Sid(sid));
                        Ok(())
                    }
                    ERROR_ALREADY_EXISTS_HRESULT => Ok(()),
                    _ => Err(format!("CreateAppContainerProfile: HRESULT {hr:#010x}")),
                }
            })
            .clone()
            .map_err(io::Error::other)
    }

    /// The AppContainer's SID, computed from its name.
    fn app_container_sid() -> io::Result<Sid> {
        ensure_profile()?;
        let name = wide(APP_CONTAINER_NAME);
        let mut sid: PSID = null_mut();
        // SAFETY: valid NUL-terminated string and out-pointer.
        let hr = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if hr != 0 {
            return Err(io::Error::other(format!("DeriveAppContainerSidFromAppContainerName: HRESULT {hr:#010x}")));
        }
        Ok(Sid(sid))
    }

    /// `LOCALAPPDATA=<the app's value>` and nothing else, as a sorted Unicode environment block.
    fn environment_block() -> Vec<u16> {
        let mut block: Vec<u16> = Vec::new();
        if let Some(value) = std::env::var_os("LOCALAPPDATA") {
            block.extend("LOCALAPPDATA=".encode_utf16());
            block.extend(value.encode_wide());
            block.push(0);
        }
        if block.is_empty() {
            block.push(0);
        }
        block.push(0);
        block
    }

    /// Whether process `pid` runs with an AppContainer token, read from outside. `None` when
    /// the process or its token cannot be opened.
    pub fn is_app_container(pid: u32) -> Option<bool> {
        // SAFETY: each handle is checked and closed; the out-pointers are valid.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return None;
            }
            let mut token: HANDLE = null_mut();
            let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token) != 0;
            CloseHandle(process);
            if !opened {
                return None;
            }
            let (mut flag, mut len) = (0u32, 0u32);
            let ok = GetTokenInformation(token, TokenIsAppContainer, (&mut flag as *mut u32).cast(), 4, &mut len) != 0;
            CloseHandle(token);
            ok.then_some(flag != 0)
        }
    }

    pub struct Process {
        process: HANDLE,
        job: HANDLE,
        exited: Option<i32>,
    }

    // SAFETY: the two handles are process-wide kernel handles, usable from any thread.
    unsafe impl Send for Process {}

    impl Process {
        pub fn kill(&mut self) {
            if self.exited.is_none() {
                // SAFETY: a live process handle we own.
                unsafe { TerminateProcess(self.process, 1) };
            }
        }

        pub fn try_wait(&mut self) -> Option<i32> {
            if self.exited.is_none() {
                let mut code = 0u32;
                // SAFETY: a live process handle and a valid out-pointer.
                if unsafe { GetExitCodeProcess(self.process, &mut code) } != 0 && code != STILL_ACTIVE as u32 {
                    self.exited = Some(code as i32);
                }
            }
            self.exited
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            self.kill();
            // SAFETY: both handles are ours; closing the job also ends the helper.
            unsafe {
                CloseHandle(self.job);
                CloseHandle(self.process);
            }
        }
    }

    fn last_error(what: &str) -> io::Error {
        let e = io::Error::last_os_error();
        io::Error::new(e.kind(), format!("{what}: {e}"))
    }

    fn pipe(inheritable: bool) -> io::Result<(HANDLE, HANDLE)> {
        let attributes = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: null_mut(), bInheritHandle: inheritable as i32 };
        let (mut read, mut write) = (null_mut(), null_mut());
        // SAFETY: valid out-pointers and attributes.
        if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
            return Err(last_error("CreatePipe"));
        }
        Ok((read, write))
    }

    fn close(handles: &[HANDLE]) {
        for h in handles {
            // SAFETY: each handle is open and owned here.
            unsafe { CloseHandle(*h) };
        }
    }

    pub fn spawn(program: &Path, args: &[&str], memory_cap: u64) -> io::Result<Child> {
        // The real pipes: no end is ever inheritable.
        let (helper_in, core_out) = pipe(false)?;
        let (core_in, helper_out) = match pipe(false) {
            Ok(p) => p,
            Err(e) => {
                close(&[helper_in, core_out]);
                return Err(e);
            }
        };
        // The start-up pipe: its read end is the only handle the helper inherits. It carries two
        // numbers that mean nothing outside the helper.
        let (boot_read, boot_write) = match pipe(true) {
            Ok(p) => p,
            Err(e) => {
                close(&[helper_in, core_out, core_in, helper_out]);
                return Err(e);
            }
        };
        // SAFETY: a handle we own.
        unsafe { SetHandleInformation(boot_write, HANDLE_FLAG_INHERIT, 0) };
        let close_all = || close(&[helper_in, core_out, core_in, helper_out, boot_read, boot_write]);

        // PLUG-05: no helper starts outside the AppContainer.
        let sid = match app_container_sid() {
            Ok(sid) => sid,
            Err(e) => {
                close_all();
                return Err(e);
            }
        };
        let mut capabilities = SECURITY_CAPABILITIES { AppContainerSid: sid.0, Capabilities: null_mut(), CapabilityCount: 0, Reserved: 0 };

        let mut size = 0usize;
        // SAFETY: the first call only reports the size needed.
        unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size) };
        let mut buffer = vec![0u8; size];
        let list: LPPROC_THREAD_ATTRIBUTE_LIST = buffer.as_mut_ptr().cast();
        // SAFETY: `buffer` is the size the system asked for.
        if unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut size) } == 0 {
            let e = last_error("InitializeProcThreadAttributeList");
            close_all();
            return Err(e);
        }
        let mut inherited: [HANDLE; 1] = [boot_read];
        // SAFETY: the list, the handle array and the capabilities outlive CreateProcessW.
        let ok = unsafe {
            UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize, inherited.as_mut_ptr().cast(), std::mem::size_of::<HANDLE>(), null_mut(), null()) != 0
                && UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    (&mut capabilities as *mut SECURITY_CAPABILITIES).cast(),
                    std::mem::size_of::<SECURITY_CAPABILITIES>(),
                    null_mut(),
                    null(),
                ) != 0
        };
        if !ok {
            let e = last_error("UpdateProcThreadAttribute");
            unsafe { DeleteProcThreadAttributeList(list) };
            close_all();
            return Err(e);
        }
        // SAFETY: zeroed STARTUPINFOEXW is the documented starting state.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = boot_read;
        startup.StartupInfo.hStdOutput = null_mut();
        startup.StartupInfo.hStdError = null_mut();
        startup.lpAttributeList = list;

        let mut command = format!("\"{}\" --handles-from-stdin", program.display());
        for arg in args {
            command.push(' ');
            command.push_str(arg);
        }
        let mut command: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
        let application: Vec<u16> = program.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // LOCALAPPDATA only: an AppContainer process will not start with an empty block.
        let environment = environment_block();
        // SAFETY: zeroed PROCESS_INFORMATION is an out-parameter.
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every pointer is valid for the call; the attribute list outlives it.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                environment.as_ptr().cast(),
                null(),
                &startup.StartupInfo,
                &mut info,
            )
        };
        let create_error = last_error("CreateProcessW");
        unsafe { DeleteProcThreadAttributeList(list) };
        if created == 0 {
            close_all();
            return Err(create_error);
        }

        // The job: one process, a memory cap, and death when the core's handle closes.
        // SAFETY: plain calls with valid arguments; the limits struct outlives the call.
        let job = unsafe { CreateJobObjectW(null(), null()) };
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.ProcessMemoryLimit = usize::try_from(memory_cap).unwrap_or(usize::MAX);
        let in_job = !job.is_null()
            && unsafe {
                SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(), std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32)
            } != 0
            && unsafe { AssignProcessToJobObject(job, info.hProcess) } != 0;

        // Hand the suspended helper its two pipe ends and tell it their values.
        let (mut in_child, mut out_child): (HANDLE, HANDLE) = (null_mut(), null_mut());
        // SAFETY: valid handles in this process and a process handle with full access.
        let handed_over = in_job
            && unsafe {
                let me = GetCurrentProcess();
                DuplicateHandle(me, helper_in, info.hProcess, &mut in_child, 0, 0, DUPLICATE_SAME_ACCESS) != 0
                    && DuplicateHandle(me, helper_out, info.hProcess, &mut out_child, 0, 0, DUPLICATE_SAME_ACCESS) != 0
            }
            && {
                let mut message = [0u8; 16];
                message[..8].copy_from_slice(&(in_child as usize as u64).to_le_bytes());
                message[8..].copy_from_slice(&(out_child as usize as u64).to_le_bytes());
                let mut written = 0u32;
                // SAFETY: a valid buffer of 16 bytes and a pipe handle we own.
                unsafe { WriteFile(boot_write, message.as_ptr(), 16, &mut written, null_mut()) != 0 && written == 16 }
            };
        let handover_error = last_error(if in_job { "handing the pipe ends to the helper" } else { "job object" });
        close(&[helper_in, helper_out, boot_read, boot_write]);
        if !handed_over {
            // SAFETY: handles from CreateProcessW and CreateJobObjectW, owned here.
            unsafe {
                TerminateProcess(info.hProcess, 1);
                CloseHandle(info.hThread);
                CloseHandle(info.hProcess);
                if !job.is_null() {
                    CloseHandle(job);
                }
            }
            close(&[core_out, core_in]);
            return Err(handover_error);
        }
        // SAFETY: the thread handle from CreateProcessW.
        unsafe {
            ResumeThread(info.hThread);
            CloseHandle(info.hThread);
        }
        // SAFETY: both handles are open, owned here and used nowhere else.
        let (to_helper, from_helper) = unsafe { (File::from_raw_handle(core_out.cast()), File::from_raw_handle(core_in.cast())) };
        Ok(Child { pid: info.dwProcessId, to_helper: Some(to_helper), from_helper: Some(from_helper), process: Process { process: info.hProcess, job, exited: None } })
    }
}
