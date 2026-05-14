//! Process-hardening primitives invoked at the secret-handling boundary.
//!
//! This module bundles the platform-specific calls that reduce the
//! attack surface for any operation that holds plaintext secrets in
//! memory. It is called once at the start of `Store::copy` (the only
//! verb that reads *and* writes a secret in the same invocation) and
//! once at CLI process start.
//!
//! The dominant historical leak vector for secret CLIs is logs and
//! crash reports, not in-process memory inspection. The primitives
//! here target both: they make the process resistant to debugger
//! attach / dump (`PR_SET_DUMPABLE`, WER suppression, Hardened Runtime
//! at build time) AND refuse to start when the environment carries a
//! recognized injection signal (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`).
//!
//! Calls are idempotent and best-effort. A failure to install one
//! mitigation never aborts the process — the caller may still proceed
//! with a recorded `Mitigation` outcome and decide what to log.

use std::env;

/// Outcome of a single mitigation attempt.
#[derive(Debug, Clone)]
pub struct MitigationOutcome {
    pub name: &'static str,
    pub applied: bool,
    pub note: Option<String>,
}

/// Reasons to refuse to start. These represent active injection signals
/// or privilege configurations a secret-handling CLI must not run under.
#[derive(Debug, Clone, thiserror::Error)]
pub enum HardenRefusal {
    #[error("refusing to run setuid (effective uid {euid} != real uid {uid})")]
    Setuid { euid: u32, uid: u32 },
    #[error("refusing to run with injection-style environment variable set: {0}")]
    InjectionEnv(&'static str),
}

/// Environment variables whose mere presence is treated as an
/// injection signal. Hardened Runtime / `AT_SECURE` already ignore
/// most of these for trusted callers, but their presence in `environ`
/// suggests the launching shell expected them to take effect.
const REFUSAL_ENV_VARS: &[&str] = &[
    // Linux dynamic linker
    "LD_PRELOAD",
    "LD_AUDIT",
    // macOS dyld (Hardened Runtime blocks the load, but presence is a
    // credible attack signal regardless)
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
];

/// Refuse to start if any injection-style env var is set or the
/// process is running setuid.
///
/// Returns `Err(HardenRefusal)` on the first matching condition so the
/// caller can map it to a non-zero exit before any secret material is
/// loaded into memory.
pub fn check_refusal_conditions() -> Result<(), HardenRefusal> {
    #[cfg(unix)]
    {
        // SAFETY: both libc calls are infallible and have no side effects.
        let euid = unsafe { libc::geteuid() } as u32;
        let uid = unsafe { libc::getuid() } as u32;
        if euid != uid {
            return Err(HardenRefusal::Setuid { euid, uid });
        }
    }

    for name in REFUSAL_ENV_VARS {
        if env::var_os(name).is_some() {
            return Err(HardenRefusal::InjectionEnv(name));
        }
    }

    Ok(())
}

/// Apply platform process-hardening best-effort.
///
/// Returns one `MitigationOutcome` per attempted mitigation so the
/// caller can decide whether to emit a `--verbose` summary. None of
/// the outcomes are fatal; a `MitigationOutcome { applied: false, .. }`
/// simply means the platform refused (e.g., insufficient privilege)
/// and downstream secrets handling proceeds anyway.
pub fn apply_mitigations() -> Vec<MitigationOutcome> {
    let mut out = Vec::new();

    #[cfg(target_os = "linux")]
    {
        out.push(linux::set_dumpable_zero());
        out.push(linux::set_core_rlimit_zero());
    }

    #[cfg(target_os = "macos")]
    {
        out.push(macos::set_core_rlimit_zero());
    }

    #[cfg(windows)]
    {
        out.push(win::set_error_mode());
        out.push(win::set_default_dll_directories());
        out.push(win::set_dynamic_code_policy());
        out.push(win::set_extension_point_policy());
        out.push(win::wer_add_excluded_application());
    }

    out
}

/// Combined entry point: refuse on injection signals, then apply
/// best-effort mitigations. Returns `Ok(outcomes)` on success.
pub fn harden_process() -> Result<Vec<MitigationOutcome>, HardenRefusal> {
    check_refusal_conditions()?;
    Ok(apply_mitigations())
}

/// Attempt to lock the memory pages backing `bytes` into physical RAM
/// and configure them so they are excluded from core dumps, process
/// forks, and crash reports.
///
/// This function is only compiled when the `memory-lock` Cargo feature
/// is enabled. When it is, call it immediately after creating a
/// `SecretString` to reduce the window during which the secret resides
/// in swappable, dumpable pages.
///
/// ## Graceful degrade
///
/// Platform calls are best-effort: `mlock` returns `EAGAIN` when
/// `RLIMIT_MEMLOCK` is exhausted (defaults to 64 KiB on stock Linux),
/// and `VirtualLock` can fail when the working-set ceiling is not
/// raised. In both cases the secret remains in memory — just without
/// the additional residency guarantee. The returned `MitigationOutcome`
/// records whether each call succeeded.
///
/// ## Alignment
///
/// `mlock` / `VirtualLock` operate on page-granularity regions. The
/// implementation computes the enclosing page range (page-floor of the
/// base, page-ceiling of the end) using `sysconf(_SC_PAGESIZE)` /
/// `GetSystemInfo` rather than a compile-time constant, so it is
/// correct on platforms where the page size differs from 4 KiB.
#[cfg(feature = "memory-lock")]
pub fn lock_secret_pages(bytes: &[u8]) -> Vec<MitigationOutcome> {
    #[cfg(target_os = "linux")]
    return linux::lock_pages(bytes);
    #[cfg(target_os = "macos")]
    return macos::lock_pages(bytes);
    #[cfg(windows)]
    return win::lock_pages(bytes);
    // Other Unix platforms get mlock if libc has it.
    #[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
    return generic_unix::lock_pages(bytes);
    #[cfg(not(any(unix, windows)))]
    vec![MitigationOutcome {
        name: "memory-lock:unsupported-platform",
        applied: false,
        note: Some("memory-lock is not implemented for this platform".into()),
    }]
}

#[cfg(target_os = "linux")]
mod linux {
    use super::MitigationOutcome;

    pub fn set_dumpable_zero() -> MitigationOutcome {
        // PR_SET_DUMPABLE = 4 in linux/prctl.h. Suppresses core dumps,
        // blocks ptrace-attach from same-uid peers, and makes
        // /proc/<pid>/{mem,maps,environ} root-owned.
        const PR_SET_DUMPABLE: libc::c_int = 4;
        // SAFETY: prctl with PR_SET_DUMPABLE takes a single integer arg
        // and has no memory effects.
        let rc = unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
        MitigationOutcome {
            name: "linux:prctl(PR_SET_DUMPABLE,0)",
            applied: rc == 0,
            note: if rc == 0 {
                None
            } else {
                Some(format!("errno={}", std::io::Error::last_os_error()))
            },
        }
    }

    pub fn set_core_rlimit_zero() -> MitigationOutcome {
        let rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit with RLIMIT_CORE and a stack-allocated
        // rlimit pointer is well-defined; we own the buffer.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rl) };
        MitigationOutcome {
            name: "linux:setrlimit(RLIMIT_CORE,0)",
            applied: rc == 0,
            note: if rc == 0 {
                None
            } else {
                Some(format!("errno={}", std::io::Error::last_os_error()))
            },
        }
    }

    #[cfg(feature = "memory-lock")]
    pub fn lock_pages(bytes: &[u8]) -> Vec<super::MitigationOutcome> {
        let mut out = Vec::new();
        if bytes.is_empty() {
            return out;
        }
        let (base, len) = page_range(bytes);
        // SAFETY: `base` is page-aligned, `len` covers the page range
        // enclosing `bytes`. mlock does not dereference the pointer —
        // it instructs the kernel to pin the pages.
        let rc = unsafe { libc::mlock(base as *const libc::c_void, len) };
        out.push(super::MitigationOutcome {
            name: "linux:mlock",
            applied: rc == 0,
            note: if rc == 0 {
                None
            } else {
                Some(format!("errno={}", std::io::Error::last_os_error()))
            },
        });

        // MADV_DONTDUMP: exclude these pages from core dumps.
        // SAFETY: same pointer/len as above; madvise is advisory-only.
        let rc2 = unsafe { libc::madvise(base as *mut libc::c_void, len, libc::MADV_DONTDUMP) };
        out.push(super::MitigationOutcome {
            name: "linux:madvise(MADV_DONTDUMP)",
            applied: rc2 == 0,
            note: if rc2 == 0 {
                None
            } else {
                Some(format!("errno={}", std::io::Error::last_os_error()))
            },
        });

        // MADV_WIPEONFORK: zero the pages in the child after fork,
        // preventing secrets from leaking into a forked process.
        // SAFETY: same reasoning as above.
        let rc3 = unsafe { libc::madvise(base as *mut libc::c_void, len, libc::MADV_WIPEONFORK) };
        out.push(super::MitigationOutcome {
            name: "linux:madvise(MADV_WIPEONFORK)",
            applied: rc3 == 0,
            note: if rc3 == 0 {
                None
            } else {
                Some(format!("errno={}", std::io::Error::last_os_error()))
            },
        });

        out
    }

    /// Compute the page-aligned address and length covering `bytes`.
    #[cfg(feature = "memory-lock")]
    fn page_range(bytes: &[u8]) -> (usize, usize) {
        // SAFETY: sysconf is infallible for _SC_PAGESIZE on Linux.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let page_size = if page_size == 0 { 4096 } else { page_size };
        let addr = bytes.as_ptr() as usize;
        let base = addr & !(page_size - 1);
        let end = (addr + bytes.len() + page_size - 1) & !(page_size - 1);
        (base, end - base)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::MitigationOutcome;

    pub fn set_core_rlimit_zero() -> MitigationOutcome {
        // macOS soft RLIMIT_CORE is 0 by default for user processes,
        // but a parent that raised it (e.g., a developer environment)
        // is the failure case this re-zeroes. Note: ReportCrash writes
        // .ips files independently of this limit; the only mitigation
        // for those is "do not crash on the secret path."
        let rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: same as Linux variant.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rl) };
        MitigationOutcome {
            name: "macos:setrlimit(RLIMIT_CORE,0)",
            applied: rc == 0,
            note: if rc == 0 {
                None
            } else {
                Some(format!("errno={}", std::io::Error::last_os_error()))
            },
        }
    }

    #[cfg(feature = "memory-lock")]
    pub fn lock_pages(bytes: &[u8]) -> Vec<super::MitigationOutcome> {
        if bytes.is_empty() {
            return vec![];
        }
        let (base, len) = page_range(bytes);
        // SAFETY: base is page-aligned, len covers the enclosing
        // pages. mlock is advisory — does not dereference.
        let rc = unsafe { libc::mlock(base as *const libc::c_void, len) };
        vec![super::MitigationOutcome {
            name: "macos:mlock",
            applied: rc == 0,
            note: if rc == 0 {
                None
            } else {
                Some(format!("errno={}", std::io::Error::last_os_error()))
            },
        }]
    }

    #[cfg(feature = "memory-lock")]
    fn page_range(bytes: &[u8]) -> (usize, usize) {
        // SAFETY: sysconf is infallible for _SC_PAGESIZE.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let page_size = if page_size == 0 { 16384 } else { page_size }; // M-series default
        let addr = bytes.as_ptr() as usize;
        let base = addr & !(page_size - 1);
        let end = (addr + bytes.len() + page_size - 1) & !(page_size - 1);
        (base, end - base)
    }
}

/// Generic Unix fallback for other platforms (FreeBSD, illumos, etc.)
/// that have `mlock` via libc but no Linux-specific `madvise` flags.
#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
mod generic_unix {
    #[cfg(feature = "memory-lock")]
    pub fn lock_pages(bytes: &[u8]) -> Vec<super::MitigationOutcome> {
        if bytes.is_empty() {
            return vec![];
        }
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let page_size = if page_size == 0 { 4096 } else { page_size };
        let addr = bytes.as_ptr() as usize;
        let base = addr & !(page_size - 1);
        let end = (addr + bytes.len() + page_size - 1) & !(page_size - 1);
        let len = end - base;
        // SAFETY: base is page-aligned, len covers the enclosing pages.
        let rc = unsafe { libc::mlock(base as *const libc::c_void, len) };
        vec![super::MitigationOutcome {
            name: "unix:mlock",
            applied: rc == 0,
            note: if rc == 0 {
                None
            } else {
                Some(format!("errno={}", std::io::Error::last_os_error()))
            },
        }]
    }
}

#[cfg(windows)]
mod win {
    use super::MitigationOutcome;

    #[cfg(feature = "memory-lock")]
    pub fn lock_pages(bytes: &[u8]) -> Vec<MitigationOutcome> {
        use windows_sys::Win32::System::Memory::VirtualLock;
        if bytes.is_empty() {
            return vec![];
        }
        // SAFETY: `bytes.as_ptr()` is valid for `bytes.len()` bytes.
        // VirtualLock takes a base address and byte count; the kernel
        // maps the enclosing pages into the working set. Fails with
        // ERROR_WORKING_SET_QUOTA when the working-set ceiling is
        // exhausted — that is the graceful-degrade path.
        let ok = unsafe { VirtualLock(bytes.as_ptr().cast(), bytes.len()) };
        vec![MitigationOutcome {
            name: "windows:VirtualLock",
            applied: ok != 0,
            note: if ok != 0 {
                None
            } else {
                Some(format!("GetLastError={}", std::io::Error::last_os_error()))
            },
        }]
    }

    use windows_sys::Win32::System::Diagnostics::Debug::{
        SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
    };
    use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;
    use windows_sys::Win32::System::LibraryLoader::{
        SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    use windows_sys::Win32::System::Threading::{
        ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, SetProcessMitigationPolicy,
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
    };

    pub fn set_error_mode() -> MitigationOutcome {
        // Read-modify-write so we do not clobber inherited flags.
        // SAFETY: SetErrorMode is a stateless setter; the previous
        // value is returned and re-applied with the additional flags.
        let prev = unsafe { SetErrorMode(0) };
        let mask = SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX;
        // SAFETY: same.
        unsafe { SetErrorMode(prev | mask) };
        MitigationOutcome {
            name: "windows:SetErrorMode(NOGPFAULTERRORBOX|FAILCRITICALERRORS|NOOPENFILEERRORBOX)",
            applied: true,
            note: None,
        }
    }

    pub fn set_default_dll_directories() -> MitigationOutcome {
        // SAFETY: SetDefaultDllDirectories takes a flags integer; no
        // memory effects. Available on Windows 8+ / Server 2012+, also
        // backported to Windows 7 via KB2533623.
        let ok = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
        MitigationOutcome {
            name: "windows:SetDefaultDllDirectories(SEARCH_SYSTEM32)",
            applied: ok != 0,
            note: if ok != 0 {
                None
            } else {
                Some(format!("GetLastError={}", std::io::Error::last_os_error()))
            },
        }
    }

    pub fn set_dynamic_code_policy() -> MitigationOutcome {
        let policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY {
            Anonymous:
                windows_sys::Win32::System::Threading::PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_0 {
                    Flags: 1, // ProhibitDynamicCode = 1
                },
        };
        // SAFETY: SetProcessMitigationPolicy reads from a stack-owned
        // buffer of the documented size; the policy enum and struct
        // type are matched. Safe for an unprivileged process to set
        // on itself.
        let ok = unsafe {
            SetProcessMitigationPolicy(
                ProcessDynamicCodePolicy,
                &policy as *const _ as *const _,
                std::mem::size_of::<PROCESS_MITIGATION_DYNAMIC_CODE_POLICY>(),
            )
        };
        MitigationOutcome {
            name: "windows:SetProcessMitigationPolicy(ProcessDynamicCodePolicy)",
            applied: ok != 0,
            note: if ok != 0 {
                None
            } else {
                Some(format!("GetLastError={}", std::io::Error::last_os_error()))
            },
        }
    }

    pub fn set_extension_point_policy() -> MitigationOutcome {
        let policy = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY {
            Anonymous: windows_sys::Win32::System::Threading::PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_0 {
                Flags: 1, // DisableExtensionPoints = 1
            },
        };
        // SAFETY: same shape as above; matched policy enum + struct.
        let ok = unsafe {
            SetProcessMitigationPolicy(
                ProcessExtensionPointDisablePolicy,
                &policy as *const _ as *const _,
                std::mem::size_of::<PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY>(),
            )
        };
        MitigationOutcome {
            name: "windows:SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy)",
            applied: ok != 0,
            note: if ok != 0 {
                None
            } else {
                Some(format!("GetLastError={}", std::io::Error::last_os_error()))
            },
        }
    }

    pub fn wer_add_excluded_application() -> MitigationOutcome {
        // Compute the binary's filename (no path) and pass as UTF-16
        // null-terminated. Affects future invocations for this user;
        // the registry write is benign and idempotent.
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                return MitigationOutcome {
                    name: "windows:WerAddExcludedApplication",
                    applied: false,
                    note: Some(format!("current_exe failed: {e}")),
                }
            }
        };
        let name = match exe.file_name().and_then(|s| s.to_str()) {
            Some(s) => s.to_owned(),
            None => {
                return MitigationOutcome {
                    name: "windows:WerAddExcludedApplication",
                    applied: false,
                    note: Some("could not derive exe basename".into()),
                }
            }
        };
        let mut wide: Vec<u16> = name.encode_utf16().collect();
        wide.push(0);
        // SAFETY: pointer is to a stack-owned null-terminated UTF-16
        // buffer; the API copies it before returning.
        let hr = unsafe { WerAddExcludedApplication(wide.as_ptr(), 0) };
        MitigationOutcome {
            name: "windows:WerAddExcludedApplication",
            applied: hr >= 0,
            note: if hr >= 0 {
                None
            } else {
                Some(format!("HRESULT={hr:#010x}"))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_mitigations_returns_at_least_one_outcome_per_supported_platform() {
        let outcomes = apply_mitigations();
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        assert!(!outcomes.is_empty());
        // Other platforms (e.g., illumos, freebsd) currently get no
        // mitigations and an empty Vec is fine.
        let _ = outcomes;
    }

    // Tests in this module mutate process-wide environment variables.
    // Serialize them with the shared ENV_LOCK so parallel test threads
    // can't observe each other's transient state.
    use crate::test_utils::ENV_LOCK;

    #[test]
    fn check_refusal_rejects_ld_preload() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: serialized by ENV_LOCK; we restore on the way out.
        unsafe { std::env::set_var("LD_PRELOAD", "/tmp/nonexistent.so") };
        let result = check_refusal_conditions();
        unsafe { std::env::remove_var("LD_PRELOAD") };
        match result {
            Err(HardenRefusal::InjectionEnv("LD_PRELOAD")) => {}
            other => panic!("expected LD_PRELOAD refusal, got {other:?}"),
        }
    }

    #[test]
    fn check_refusal_rejects_dyld_insert_libraries() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: serialized by ENV_LOCK; we restore on the way out.
        unsafe { std::env::set_var("DYLD_INSERT_LIBRARIES", "/tmp/x.dylib") };
        let result = check_refusal_conditions();
        unsafe { std::env::remove_var("DYLD_INSERT_LIBRARIES") };
        match result {
            Err(HardenRefusal::InjectionEnv("DYLD_INSERT_LIBRARIES")) => {}
            other => panic!("expected DYLD_INSERT_LIBRARIES refusal, got {other:?}"),
        }
    }
}
