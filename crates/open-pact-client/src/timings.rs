//! Wall time and CPU time of one run, for `check --dry-run --timings`. IT reads these numbers to
//! decide how often a fleet may check. A run writes nothing and sends nothing.

use std::fmt;
use std::time::Duration;

/// CPU time spent in user mode and in the kernel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Cpu {
    pub(crate) user: Duration,
    pub(crate) system: Duration,
}

impl Cpu {
    fn total(self) -> Duration {
        self.user + self.system
    }
}

/// What one run cost. A part that this OS cannot measure is `None`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Timings {
    pub(crate) wall: Duration,
    pub(crate) own: Option<Cpu>,
    pub(crate) children: Option<Cpu>,
}

/// The cost of this process and the child processes it waited for, since it started.
pub(crate) fn measure(wall: Duration) -> Timings {
    Timings {
        wall,
        own: own_cpu(),
        children: children_cpu(),
    }
}

fn seconds(duration: Duration) -> String {
    format!("{:.2} s", duration.as_secs_f64())
}

fn cpu_line(label: &str, cpu: Option<Cpu>) -> String {
    match cpu {
        Some(cpu) => format!(
            "  CPU of {label}: {} (user {}, system {})",
            seconds(cpu.total()),
            seconds(cpu.user),
            seconds(cpu.system)
        ),
        None => format!("  CPU of {label}: not available on this OS"),
    }
}

impl fmt::Display for Timings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Timings: wall time of the whole run {}",
            seconds(self.wall)
        )?;
        writeln!(f, "{}", cpu_line("the client process", self.own))?;
        writeln!(f, "{}", cpu_line("its child processes", self.children))?;
        match (self.own, self.children) {
            (Some(own), Some(children)) => write!(
                f,
                "  CPU in all: {}",
                seconds(own.total() + children.total())
            ),
            _ => write!(f, "  CPU in all: not available on this OS"),
        }
    }
}

#[cfg(unix)]
fn rusage(who: libc::c_int) -> Option<Cpu> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given and reads nothing from it.
    if unsafe { libc::getrusage(who, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: a successful call initialised it, and zeroed memory is valid for this plain struct.
    let usage = unsafe { usage.assume_init() };
    let time = |value: libc::timeval| {
        Duration::new(
            u64::try_from(value.tv_sec).unwrap_or(0),
            u32::try_from(value.tv_usec)
                .unwrap_or(0)
                .saturating_mul(1000),
        )
    };
    Some(Cpu {
        user: time(usage.ru_utime),
        system: time(usage.ru_stime),
    })
}

#[cfg(unix)]
fn own_cpu() -> Option<Cpu> {
    rusage(libc::RUSAGE_SELF)
}

/// Children that this process waited for: every check command that finished.
#[cfg(unix)]
fn children_cpu() -> Option<Cpu> {
    rusage(libc::RUSAGE_CHILDREN)
}

#[cfg(windows)]
mod windows {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    use super::Cpu;

    /// CPU time of the children that the checks started, in units of 100 ns.
    static CHILD_USER: AtomicU64 = AtomicU64::new(0);
    static CHILD_KERNEL: AtomicU64 = AtomicU64::new(0);

    fn ticks(time: FILETIME) -> u64 {
        (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
    }

    fn duration(ticks: u64) -> Duration {
        Duration::from_nanos(ticks.saturating_mul(100))
    }

    fn times(process: windows_sys::Win32::Foundation::HANDLE) -> Option<(u64, u64)> {
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: the handle is a live process handle and every pointer is to a local FILETIME.
        let ok =
            unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) };
        (ok != 0).then(|| (ticks(user), ticks(kernel)))
    }

    pub(super) fn own() -> Option<Cpu> {
        // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing.
        let (user, kernel) = times(unsafe { GetCurrentProcess() })?;
        Some(Cpu {
            user: duration(user),
            system: duration(kernel),
        })
    }

    pub(super) fn children() -> Option<Cpu> {
        Some(Cpu {
            user: duration(CHILD_USER.load(Ordering::Relaxed)),
            system: duration(CHILD_KERNEL.load(Ordering::Relaxed)),
        })
    }

    /// Adds the CPU time of a child that has exited. Windows keeps no running total of children.
    pub(crate) fn note_child(child: &std::process::Child) {
        use std::os::windows::io::AsRawHandle;
        if let Some((user, kernel)) = times(child.as_raw_handle()) {
            CHILD_USER.fetch_add(user, Ordering::Relaxed);
            CHILD_KERNEL.fetch_add(kernel, Ordering::Relaxed);
        }
    }
}

#[cfg(windows)]
pub(crate) use windows::note_child;

#[cfg(windows)]
fn own_cpu() -> Option<Cpu> {
    windows::own()
}

/// On Windows only the commands that the checks start are counted (the PowerShell batch).
#[cfg(windows)]
fn children_cpu() -> Option<Cpu> {
    windows::children()
}

#[cfg(not(any(unix, windows)))]
fn own_cpu() -> Option<Cpu> {
    None
}

#[cfg(not(any(unix, windows)))]
fn children_cpu() -> Option<Cpu> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_names_wall_time_and_both_cpu_times() {
        let timings = Timings {
            wall: Duration::from_millis(1_234),
            own: Some(Cpu {
                user: Duration::from_millis(60),
                system: Duration::from_millis(70),
            }),
            children: Some(Cpu {
                user: Duration::from_millis(300),
                system: Duration::from_millis(100),
            }),
        };
        assert_eq!(
            timings.to_string(),
            "Timings: wall time of the whole run 1.23 s\n  CPU of the client process: 0.13 s (user 0.06 s, system 0.07 s)\n  CPU of its child processes: 0.40 s (user 0.30 s, system 0.10 s)\n  CPU in all: 0.53 s"
        );
    }

    #[test]
    fn a_part_that_cannot_be_measured_is_said_so() {
        let timings = Timings {
            wall: Duration::from_secs(2),
            own: None,
            children: None,
        };
        let text = timings.to_string();
        assert!(
            text.contains("CPU of the client process: not available"),
            "{text}"
        );
        assert!(text.contains("CPU in all: not available"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn this_process_and_its_waited_children_report_cpu_time() {
        let before = own_cpu().unwrap().total();
        let mut spin = 0u64;
        while own_cpu().unwrap().total() <= before && spin < 50_000_000 {
            spin = std::hint::black_box(spin + 1);
        }
        assert!(own_cpu().unwrap().total() > before);
        let child_before = children_cpu().unwrap().total();
        let status = std::process::Command::new("sh")
            .args(["-c", "i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done"])
            .status()
            .unwrap();
        assert!(status.success());
        assert!(children_cpu().unwrap().total() > child_before);
    }
}
