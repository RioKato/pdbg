use std::{
    io::{Error, Result},
    mem::MaybeUninit,
};

use libc::{
    c_int, c_uint, pid_t, siginfo_t, EINVAL, PTRACE_CONT, PTRACE_EVENT_CLONE, PTRACE_EVENT_EXEC,
    PTRACE_EVENT_EXIT, PTRACE_EVENT_FORK, PTRACE_EVENT_SECCOMP, PTRACE_EVENT_STOP,
    PTRACE_EVENT_VFORK, PTRACE_EVENT_VFORK_DONE, PTRACE_GETSIGINFO, PTRACE_O_TRACECLONE,
    PTRACE_O_TRACEEXEC, PTRACE_O_TRACEEXIT, PTRACE_O_TRACEFORK, PTRACE_O_TRACESECCOMP,
    PTRACE_O_TRACESYSGOOD, PTRACE_O_TRACEVFORKDONE, PTRACE_SEIZE, SIGSTOP, SIGTRAP, SIGTSTP,
    SIGTTIN, SIGTTOU, WIFEXITED, WIFSIGNALED, WIFSTOPPED, WSTOPSIG, __WALL,
};
use log::warn;

pub fn handle_signal(pid: pid_t, attach: c_uint, options: c_int) -> Result<c_int> {
    fn waitpid(pid: pid_t) -> Result<c_int> {
        let mut status = 0;
        let err = unsafe { libc::waitpid(pid, &mut status, __WALL) };
        if err == -1 {
            return Err(Error::last_os_error());
        }

        Ok(status)
    }

    fn get_siginfo(pid: pid_t) -> Result<siginfo_t> {
        let mut siginfo = unsafe { MaybeUninit::<siginfo_t>::zeroed().assume_init() };
        let err = unsafe { libc::ptrace(PTRACE_GETSIGINFO, pid, 0, &mut siginfo) };
        if err == -1 {
            return Err(Error::last_os_error());
        }

        Ok(siginfo)
    }

    fn cont(pid: pid_t, sig: c_int) -> Result<()> {
        let err = unsafe { libc::ptrace(PTRACE_CONT, pid, 0, sig) };
        if err == -1 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }

    let status = waitpid(pid)?;

    if WIFSTOPPED(status) {
        let signal = WSTOPSIG(status);

        const SYSCALL_SIGTRAP: c_int = SIGTRAP | 0x80;
        match signal {
            SIGTRAP => match signal >> 16 {
                PTRACE_EVENT_VFORK if options & PTRACE_O_TRACEFORK != 0 => {
                    return Ok(status);
                }

                PTRACE_EVENT_FORK if options & PTRACE_O_TRACEFORK != 0 => {
                    return Ok(status);
                }

                PTRACE_EVENT_CLONE if options & PTRACE_O_TRACECLONE != 0 => {
                    return Ok(status);
                }

                PTRACE_EVENT_VFORK_DONE if options & PTRACE_O_TRACEVFORKDONE != 0 => {
                    return Ok(status);
                }

                PTRACE_EVENT_EXEC if options & PTRACE_O_TRACEEXEC != 0 => {
                    return Ok(status);
                }

                PTRACE_EVENT_EXIT if options & PTRACE_O_TRACEEXIT != 0 => {
                    return Ok(status);
                }

                PTRACE_EVENT_STOP if attach == PTRACE_SEIZE => {
                    return Ok(status);
                }

                PTRACE_EVENT_SECCOMP if options & PTRACE_O_TRACESECCOMP != 0 => {
                    return Ok(status);
                }

                0 => {
                    let siginfo = get_siginfo(pid)?;
                    let si_code = siginfo.si_code;
                    if options & PTRACE_O_TRACESYSGOOD == 0 {
                        assert!(si_code != SYSCALL_SIGTRAP);

                        if si_code == SIGTRAP {
                            return Ok(SYSCALL_SIGTRAP);
                        }
                    }
                }

                _ => {
                    warn!("unknown event (signal = {signal:?})");
                    return Ok(status);
                }
            },

            SYSCALL_SIGTRAP if options & PTRACE_O_TRACESYSGOOD != 0 => {
                return Ok(status);
            }

            SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => {
                match status >> 16 {
                    PTRACE_EVENT_STOP if attach == PTRACE_SEIZE => {
                        return Ok(status);
                    }

                    0 => {}

                    _ => {
                        warn!("unknown event (signal = {signal:?})");
                        return Ok(status);
                    }
                }

                if attach != PTRACE_SEIZE {
                    if let Err(err) = get_siginfo(pid) {
                        if err.kind() == Error::from_raw_os_error(EINVAL).kind() {
                            return Ok(status);
                        } else {
                            return Err(err);
                        }
                    }
                }
            }

            _ => {}
        }

        cont(pid, signal)?;
    }

    if WIFEXITED(status) || WIFSIGNALED(status) {
        return Ok(status);
    }

    unreachable!();
}
