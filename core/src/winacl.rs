//! Owner-only file permissions on Windows (the counterpart of Unix 0600/0700).
//!
//! Files that hold the library, backups, the audit log and SFTP downloads get a *protected*
//! DACL (no inheritance from the user profile) with a single allow entry: full control for the
//! current user. Directories get the same entry marked inheritable, so files created inside
//! are born owner-only.
//!
//! SYSTEM and Administrators are deliberately not granted anything. Nothing Bastion does needs
//! them: the process runs as the user. They can still override the DACL through privileges
//! (take-ownership, backup), so listing them would add no protection against them, only
//! exposure to anything that runs as them or uses their default grants. If a deployment needs
//! a service account (backup agent, AV scanning that does not use backup semantics) it must be
//! added explicitly rather than by default.
#![cfg(windows)]

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, GetSecurityInfo, SetNamedSecurityInfoW, SE_FILE_OBJECT, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{
    AddAccessAllowedAceEx, EqualSid, GetLengthSid, InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl, TokenUser,
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

/// FILE_ALL_ACCESS.
const FULL_CONTROL: u32 = 0x001F_01FF;
/// OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE.
const INHERIT_BOTH: u32 = 0x1 | 0x2;

fn win32(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// The current user's SID, kept in an 8-byte aligned buffer.
struct UserSid {
    buf: Vec<u64>,
}

impl UserSid {
    fn current() -> io::Result<UserSid> {
        Self::of_process(unsafe { GetCurrentProcess() })
    }

    /// The user a process runs as (`process` needs PROCESS_QUERY_LIMITED_INFORMATION).
    fn of_process(process: HANDLE) -> io::Result<UserSid> {
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut needed = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
            let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, needed, &mut needed);
            let err = io::Error::last_os_error();
            CloseHandle(token);
            if ok == 0 {
                return Err(err);
            }
            Ok(UserSid { buf })
        }
    }

    fn psid(&self) -> PSID {
        unsafe { (*(self.buf.as_ptr() as *const TOKEN_USER)).User.Sid }
    }
}

fn sid_to_string(sid: PSID) -> io::Result<String> {
    unsafe {
        let mut s: *mut u16 = null_mut();
        if ConvertSidToStringSidW(sid, &mut s) == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = (0..).take_while(|&i| *s.add(i) != 0).count();
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, len));
        LocalFree(s as *mut c_void);
        Ok(out)
    }
}

/// The current user's SID as `S-1-5-21-…`.
pub fn current_user_sid() -> io::Result<String> {
    sid_to_string(UserSid::current()?.psid())
}

/// An ACL with exactly one allow entry (full control for `sid`).
fn owner_only_acl(sid: PSID, inherit: bool) -> io::Result<Vec<u32>> {
    unsafe {
        let sid_len = GetLengthSid(sid) as usize;
        // ACL header + one ACCESS_ALLOWED_ACE whose trailing SidStart is replaced by the full SID.
        let size = (size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid_len + 3) & !3;
        let mut buf = vec![0u32; size / 4];
        let acl = buf.as_mut_ptr() as *mut ACL;
        if InitializeAcl(acl, size as u32, ACL_REVISION) == 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = if inherit { INHERIT_BOTH } else { 0 };
        if AddAccessAllowedAceEx(acl, ACL_REVISION, flags, FULL_CONTROL, sid) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buf)
    }
}

/// Make `path` owner-only: a protected DACL granting only the current user full control.
/// For directories (`is_dir`) the entry is inheritable by new children. Call this on a file
/// right after creating it and before writing secrets into it.
pub fn restrict_path(path: &Path, is_dir: bool) -> io::Result<()> {
    let user = UserSid::current()?;
    let acl = owner_only_acl(user.psid(), is_dir)?;
    let name = wide(path);
    let rc = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl.as_ptr() as *const ACL,
            null(),
        )
    };
    if rc != 0 {
        return Err(win32(rc));
    }
    Ok(())
}

/// One entry of a DACL, for inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// 0 = access allowed, 1 = access denied, others are object/callback variants.
    pub ace_type: u8,
    pub flags: u8,
    pub mask: u32,
    pub sid: String,
}

/// What a path's DACL currently says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaclReport {
    /// True when the DACL does not inherit from the parent (SE_DACL_PROTECTED).
    pub protected: bool,
    pub aces: Vec<Ace>,
}

/// Read a path's DACL back (used by tests and diagnostics).
pub fn dacl_report(path: &Path) -> io::Result<DaclReport> {
    let name = wide(path);
    unsafe {
        let mut dacl: *mut ACL = null_mut();
        let mut sd: *mut c_void = null_mut();
        let rc = GetNamedSecurityInfoW(name.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), &mut dacl, null_mut(), &mut sd);
        if rc != 0 {
            return Err(win32(rc));
        }
        parse_dacl(dacl, sd)
    }
}

/// Read the DACL of an open kernel object, such as a named pipe (tests and diagnostics).
pub fn handle_dacl_report(handle: HANDLE) -> io::Result<DaclReport> {
    unsafe {
        let mut dacl: *mut ACL = null_mut();
        let mut sd: *mut c_void = null_mut();
        let rc = GetSecurityInfo(handle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), &mut dacl, null_mut(), &mut sd);
        if rc != 0 {
            return Err(win32(rc));
        }
        parse_dacl(dacl, sd)
    }
}

/// Decode `dacl` (which points into `sd`) and free `sd`.
unsafe fn parse_dacl(dacl: *mut ACL, sd: *mut c_void) -> io::Result<DaclReport> {
    let result = (|| {
        let mut control = 0u16;
        let mut revision = 0u32;
        if GetSecurityDescriptorControl(sd, &mut control, &mut revision) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut aces = Vec::new();
        if !dacl.is_null() {
            // ACEs are laid out back to back after the 8-byte ACL header.
            let mut p = (dacl as *const u8).add(size_of::<ACL>());
            for _ in 0..(*dacl).AceCount {
                let ace = p as *const ACCESS_ALLOWED_ACE;
                let sid = &(*ace).SidStart as *const u32 as PSID;
                aces.push(Ace { ace_type: (*ace).Header.AceType, flags: (*ace).Header.AceFlags, mask: (*ace).Mask, sid: sid_to_string(sid)? });
                p = p.add((*ace).Header.AceSize as usize);
            }
        }
        Ok(DaclReport { protected: control & SE_DACL_PROTECTED != 0, aces })
    })();
    LocalFree(sd);
    result
}

/// Run `f` with a `SECURITY_ATTRIBUTES` (passed as a raw pointer, as tokio's named-pipe API takes it)
/// whose DACL has one entry: full control for the current user. Used for the IPC named pipe, so
/// other local users cannot open it at all. The attributes live only for the call.
pub fn with_owner_only_attributes<R>(f: impl FnOnce(*mut c_void) -> R) -> io::Result<R> {
    let user = UserSid::current()?;
    let acl = owner_only_acl(user.psid(), false)?;
    unsafe {
        let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
        let psd = &mut sd as *mut SECURITY_DESCRIPTOR as *mut c_void;
        // SECURITY_DESCRIPTOR_REVISION is 1.
        if InitializeSecurityDescriptor(psd, 1) == 0 {
            return Err(io::Error::last_os_error());
        }
        if SetSecurityDescriptorDacl(psd, 1, acl.as_ptr() as *const ACL, 0) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: psd, bInheritHandle: 0 };
        Ok(f(&mut sa as *mut SECURITY_ATTRIBUTES as *mut c_void))
    }
}

/// True when the process at the other end of the named pipe `pipe` runs as the current user.
/// `peer_is_client`: true on the server side (ask for the client), false on the client side.
pub fn pipe_peer_is_current_user(pipe: HANDLE, peer_is_client: bool) -> io::Result<bool> {
    unsafe {
        let mut pid = 0u32;
        let ok = if peer_is_client { GetNamedPipeClientProcessId(pipe, &mut pid) } else { GetNamedPipeServerProcessId(pipe, &mut pid) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            // A process we may not even query does not run as us.
            return Ok(false);
        }
        let peer = UserSid::of_process(process);
        CloseHandle(process);
        let me = UserSid::current()?;
        Ok(EqualSid(peer?.psid(), me.psid()) != 0)
    }
}

/// Well-known SIDs allowed to own or modify machine-wide files: SYSTEM, Administrators and
/// TrustedInstaller.
const ADMIN_SIDS: [&str; 3] = ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];
/// INHERIT_ONLY_ACE: the entry applies to children only, not to the object itself.
const INHERIT_ONLY: u8 = 0x8;
/// ACCESS_DENIED_ACE_TYPE.
const DENY_ACE: u8 = 1;
/// Rights that let a holder change, replace or re-permission an object: FILE_WRITE_DATA
/// (also ADD_FILE), FILE_APPEND_DATA (also ADD_SUBDIRECTORY), FILE_WRITE_EA,
/// FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL,
/// GENERIC_WRITE.
const WRITE_RIGHTS: u32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;

/// The owner SID of `path` as `S-1-…`.
pub fn owner_sid(path: &Path) -> io::Result<String> {
    use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
    let name = wide(path);
    unsafe {
        let mut owner: PSID = null_mut();
        let mut sd: *mut c_void = null_mut();
        let rc = GetNamedSecurityInfoW(name.as_ptr(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &mut owner, null_mut(), null_mut(), null_mut(), &mut sd);
        if rc != 0 {
            return Err(win32(rc));
        }
        let out = sid_to_string(owner);
        LocalFree(sd);
        out
    }
}

/// Why `owner` and `report` do not describe an admin-controlled object, or `None` when they
/// do: owned by SYSTEM/Administrators/TrustedInstaller and no allow entry that applies to the
/// object grants write rights to anyone else. Unknown (object/callback) entries count as
/// grants, so anything unusual fails closed.
pub fn admin_only_violation(owner: &str, report: &DaclReport) -> Option<String> {
    if !ADMIN_SIDS.contains(&owner) {
        return Some(format!("owned by {owner}, not SYSTEM or Administrators"));
    }
    report
        .aces
        .iter()
        .find(|a| a.ace_type != DENY_ACE && a.flags & INHERIT_ONLY == 0 && a.mask & WRITE_RIGHTS != 0 && !ADMIN_SIDS.contains(&a.sid.as_str()))
        .map(|a| format!("{} may modify it", a.sid))
}

/// Check that `path` can be changed only by administrators (see [`admin_only_violation`]).
/// A NULL DACL (everyone has full access) is rejected too.
pub fn check_admin_only(path: &Path) -> io::Result<()> {
    let report = dacl_report(path)?;
    let owner = owner_sid(path)?;
    let denied = |why: String| Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{}: {why}", path.display())));
    if report.aces.is_empty() && null_dacl(path)? {
        return denied("no DACL (everyone has full access)".into());
    }
    match admin_only_violation(&owner, &report) {
        Some(why) => denied(why),
        None => Ok(()),
    }
}

fn null_dacl(path: &Path) -> io::Result<bool> {
    let name = wide(path);
    unsafe {
        let mut dacl: *mut ACL = null_mut();
        let mut sd: *mut c_void = null_mut();
        let rc = GetNamedSecurityInfoW(name.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), &mut dacl, null_mut(), &mut sd);
        if rc != 0 {
            return Err(win32(rc));
        }
        let is_null = dacl.is_null();
        LocalFree(sd);
        Ok(is_null)
    }
}
