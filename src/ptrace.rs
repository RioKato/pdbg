use std::{
    io::{Error, Result},
    mem::MaybeUninit,
};

use libc::{
    c_int, c_uint, epoll_event, pid_t, siginfo_t, EINVAL, EPOLLIN, EPOLL_CTL_ADD, PTRACE_CONT,
    PTRACE_EVENT_CLONE, PTRACE_EVENT_EXEC, PTRACE_EVENT_EXIT, PTRACE_EVENT_FORK,
    PTRACE_EVENT_SECCOMP, PTRACE_EVENT_STOP, PTRACE_EVENT_VFORK, PTRACE_EVENT_VFORK_DONE,
    PTRACE_GETSIGINFO, PTRACE_O_TRACECLONE, PTRACE_O_TRACEEXEC, PTRACE_O_TRACEEXIT,
    PTRACE_O_TRACEFORK, PTRACE_O_TRACESECCOMP, PTRACE_O_TRACESYSGOOD, PTRACE_O_TRACEVFORKDONE,
    PTRACE_SEIZE, SIGSTOP, SIGTRAP, SIGTSTP, SIGTTIN, SIGTTOU, WIFEXITED, WIFSIGNALED, WIFSTOPPED,
    WSTOPSIG, __WALL,
};
use log::warn;

pub fn handle_signal(
    pid: pid_t,
    pidfd: c_int,
    timeout: c_int,
    attach: c_uint,
    options: c_int,
) -> Result<c_int> {
    fn epoll_create() -> Result<c_int> {
        let fd = unsafe { libc::epoll_create(1) };
        if fd == -1 {
            return Err(Error::last_os_error());
        }

        return Ok(fd);
    }

    fn epoll_close(epfd: c_int) -> Result<()> {
        let err = unsafe { libc::close(epfd) };
        if err == -1 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }

    fn epoll_ctl(epfd: c_int, pidfd: c_int) -> Result<()> {
        let mut event = unsafe { MaybeUninit::<epoll_event>::zeroed().assume_init() };
        event.events = EPOLLIN as u32;

        let err = unsafe { libc::epoll_ctl(epfd, EPOLL_CTL_ADD, pidfd, &mut event) };
        if err == -1 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }

    fn epoll_wait(epfd: c_int, timeout: c_int) -> Result<()> {
        let mut events = unsafe { MaybeUninit::<epoll_event>::zeroed().assume_init() };

        let err = unsafe { libc::epoll_wait(epfd, &mut events, 1, timeout) };
        if err == -1 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }
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

    let epfd = epoll_create()?;

    let result = loop {
        epoll_ctl(epfd, pidfd)?;
        epoll_wait(epfd, timeout)?;

        let status = waitpid(pid)?;

        if WIFSTOPPED(status) {
            let signal = WSTOPSIG(status);

            const SIGTRAP_SYSCALL: c_int = SIGTRAP | 0x80;
            match signal {
                SIGTRAP => match signal >> 16 {
                    PTRACE_EVENT_VFORK if options & PTRACE_O_TRACEFORK != 0 => {
                        break Ok(status);
                    }

                    PTRACE_EVENT_FORK if options & PTRACE_O_TRACEFORK != 0 => {
                        break Ok(status);
                    }

                    PTRACE_EVENT_CLONE if options & PTRACE_O_TRACECLONE != 0 => {
                        break Ok(status);
                    }

                    PTRACE_EVENT_VFORK_DONE if options & PTRACE_O_TRACEVFORKDONE != 0 => {
                        break Ok(status);
                    }

                    PTRACE_EVENT_EXEC if options & PTRACE_O_TRACEEXEC != 0 => {
                        break Ok(status);
                    }

                    PTRACE_EVENT_EXIT if options & PTRACE_O_TRACEEXIT != 0 => {
                        break Ok(status);
                    }

                    PTRACE_EVENT_STOP if attach == PTRACE_SEIZE => {
                        break Ok(status);
                    }

                    PTRACE_EVENT_SECCOMP if options & PTRACE_O_TRACESECCOMP != 0 => {
                        break Ok(status);
                    }

                    0 => {}

                    _ => {
                        warn!("unknown event (signal = {signal:?})");
                        break Ok(status);
                    }
                },

                SIGTRAP_SYSCALL if options & PTRACE_O_TRACESYSGOOD != 0 => {
                    break Ok(status);
                }

                SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => {
                    match status >> 16 {
                        PTRACE_EVENT_STOP if attach == PTRACE_SEIZE => {
                            break Ok(status);
                        }

                        0 => {}

                        _ => {
                            warn!("unknown event (signal = {signal:?})");
                            break Ok(status);
                        }
                    }

                    if attach != PTRACE_SEIZE {
                        if let Err(err) = get_siginfo(pid) {
                            if err.kind() == Error::from_raw_os_error(EINVAL).kind() {
                                break Ok(status);
                            } else {
                                break Err(err);
                            }
                        }
                    }
                }

                _ => {}
            }

            cont(pid, signal)?;
        }

        if WIFEXITED(status) || WIFSIGNALED(status) {
            break Ok(status);
        }

        unreachable!();
    };

    epoll_close(epfd)?;
    return result;
}
