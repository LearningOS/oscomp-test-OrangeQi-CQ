use core::{mem, time::Duration};

use axerrno::{LinuxError, LinuxResult};
use axhal::{
    arch::TrapFrame,
    trap::{POST_TRAP, register_trap_handler},
};
use axprocess::{Pid, Process, ProcessGroup, Thread};
use axsignal::{
    ctypes::{k_sigaction, SignalAction, SignalActionFlags, SignalInfo, SignalSet}, handle_signal, SignalOSAction
};
use axtask::{TaskExtRef, current};
use linux_raw_sys::general::{SI_TKILL, SI_USER, siginfo, timespec};
use starry_core::task::{
    ProcessData, ThreadData, get_process, get_process_group, get_thread, processes,
};

use crate::ptr::{UserConstPtr, UserPtr, nullable};

use super::do_exit;

const SIGKILL: u32 = 9;
const SIGSTOP: u32 = 19;

fn dequeue_signal(mask: &SignalSet) -> Option<SignalInfo> {
    let curr = current();
    let task_ext = curr.task_ext();
    task_ext
        .thread_data()
        .pending
        .lock()
        .dequeue_signal(mask)
        .or_else(|| task_ext.process_data().pending.lock().dequeue_signal(mask))
}
fn check_signals(tf: &mut TrapFrame, restore_blocked: Option<SignalSet>) -> bool {
    let curr = current();
    let task_ext = curr.task_ext();

    let mut actions = task_ext.process_data().signal_actions.lock();

    let blocked = task_ext.thread_data().blocked.lock();
    let mask = !*blocked;
    let restore_blocked = restore_blocked.unwrap_or_else(|| *blocked);
    drop(blocked);

    let (signo, os_action, reset) = loop {
        let Some(sig) = dequeue_signal(&mask) else {
            return false;
        };
        let signo = sig.signo();
        let action = &actions[signo as usize];
        if let Some(os_action) = handle_signal(tf, restore_blocked, sig, action) {
            break (
                signo,
                os_action,
                action.flags.contains(SignalActionFlags::RESETHAND),
            );
        }
    };

    match os_action {
        SignalOSAction::Terminate => {
            do_exit(128 + signo as i32, true);
        }
        SignalOSAction::CoreDump => {
            // TODO: implement core dump
            do_exit(128 + signo as i32, true);
        }
        SignalOSAction::Stop => {
            // TODO: implement stop
            do_exit(1, true);
        }
        SignalOSAction::Continue => {
            // TODO: implement continue
        }
        SignalOSAction::Handler { add_blocked } => {
            if reset {
                actions[signo as usize] = SignalAction::default();
            }
            task_ext.thread_data().blocked.lock().add_from(&add_blocked);
        }
    }
    true
}

#[register_trap_handler(POST_TRAP)]
fn post_trap_callback(tf: &mut TrapFrame, from_user: bool) {
    if !from_user {
        return;
    }

    check_signals(tf, None);
}

fn check_sigset_size(size: usize) -> LinuxResult<()> {
    if size != size_of::<SignalSet>() {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

pub fn sys_rt_sigprocmask(
    how: i32,
    set: UserConstPtr<SignalSet>,
    oldset: UserPtr<SignalSet>,
    sigsetsize: usize,
) -> LinuxResult<isize> {
    check_sigset_size(sigsetsize)?;

    let curr = current();
    let mut blocked = curr.task_ext().thread_data().blocked.lock();

    if let Some(oldset) = nullable!(oldset.get_as_mut())? {
        *oldset = *blocked;
    }

    if let Some(set) = nullable!(set.get_as_ref())? {
        match how {
            // SIG_BLOCK
            0 => blocked.add_from(set),
            // SIG_UNBLOCK
            1 => blocked.remove_from(set),
            // SIG_SETMASK
            2 => *blocked = *set,
            _ => return Err(LinuxError::EINVAL),
        }
    }

    Ok(0)
}

pub fn sys_rt_sigaction(
    signum: i32,
    act: UserConstPtr<k_sigaction>,
    oldact: UserPtr<k_sigaction>,
    sigsetsize: usize,
) -> LinuxResult<isize> {
    check_sigset_size(sigsetsize)?;

    let signum = signum as u32;
    if !(1..32).contains(&signum) {
        return Err(LinuxError::EINVAL);
    }
    if signum == SIGKILL || signum == SIGSTOP {
        return Err(LinuxError::EINVAL);
    }

    let curr = current();
    let mut actions = curr.task_ext().process_data().signal_actions.lock();

    if let Some(oldact) = nullable!(oldact.get_as_mut())? {
        actions[signum as usize].to_ctype(oldact);
    }

    if let Some(act) = nullable!(act.get_as_ref())? {
        actions[signum as usize] = (*act).try_into()?;
    }

    Ok(0)
}

pub fn sys_rt_sigpending(set: UserPtr<SignalSet>, sigsetsize: usize) -> LinuxResult<isize> {
    check_sigset_size(sigsetsize)?;

    let curr = current();
    let thr_pending = curr.task_ext().thread_data().pending.lock();
    let proc_pending = curr.task_ext().process_data().pending.lock();

    *set.get_as_mut()? = thr_pending.pending | proc_pending.pending;

    Ok(0)
}

pub fn sys_rt_sigreturn(tf: &mut TrapFrame) -> LinuxResult<isize> {
    let curr = current();
    let mut blocked = curr.task_ext().thread_data().blocked.lock();
    axsignal::restore(tf, &mut blocked);
    Ok(tf.retval() as isize)
}

pub fn sys_rt_sigtimedwait(
    set: UserConstPtr<SignalSet>,
    info: UserPtr<siginfo>,
    timeout: UserConstPtr<timespec>,
    sigsetsize: usize,
) -> LinuxResult<isize> {
    check_sigset_size(sigsetsize)?;

    let curr = current();
    let proc_data = curr.task_ext().process_data();
    let thr_data = curr.task_ext().thread_data();
    let mut set = *set.get_as_ref()?;
    // Non-blocked signals cannot be waited
    set.remove_from(&!*thr_data.blocked.lock());

    let timeout = nullable!(timeout.get_as_ref())?
        .map(|spec| Duration::new(spec.tv_sec as u64, spec.tv_nsec as u32));

    if let Some(siginfo) = thr_data.pending.lock().dequeue_signal(&set) {
        if let Some(info) = nullable!(info.get_as_mut())? {
            siginfo.to_ctype(info);
        }
        return Ok(0);
    }

    let wq = &proc_data.signal_wq;
    let deadline = timeout.map(|dur| axhal::time::wall_time() + dur);

    // There might be false wakeups, so we need a loop
    loop {
        match &deadline {
            Some(deadline) => {
                match deadline.checked_sub(axhal::time::wall_time()) {
                    Some(dur) => {
                        if wq.wait_timeout(dur) {
                            // timed out
                            break;
                        }
                    }
                    None => {
                        // deadline passed
                        break;
                    }
                }
            }
            _ => wq.wait(),
        }

        if let Some(signal) = dequeue_signal(&set) {
            if let Some(info) = nullable!(info.get_as_mut())? {
                signal.to_ctype(info);
            }
            return Ok(0);
        }
    }

    // TODO: EINTR

    Err(LinuxError::EAGAIN)
}

pub fn sys_rt_sigsuspend(
    tf: &mut TrapFrame,
    set: UserPtr<SignalSet>,
    sigsetsize: usize,
) -> LinuxResult<isize> {
    check_sigset_size(sigsetsize)?;

    let curr = current();
    let thr_data = curr.task_ext().thread_data();
    let set = set.get_as_mut()?;

    set.remove(SIGKILL);
    set.remove(SIGSTOP);

    let old_blocked = mem::replace(&mut *thr_data.blocked.lock(), *set);

    tf.set_retval((-LinuxError::EINTR.code() as isize) as usize);

    loop {
        if check_signals(tf, Some(old_blocked)) {
            break;
        }
        curr.task_ext().process_data().signal_wq.wait();
    }

    Ok(0)
}

pub fn send_signal_thread(thr: &Thread, sig: SignalInfo) {
    info!("Send signal {} to thread {}", sig.signo(), thr.tid());
    let Some(thr_data) = thr.data::<ThreadData>() else {
        return;
    };
    let Some(proc_data) = thr.process().data::<ProcessData>() else {
        return;
    };
    thr_data.pending.lock().send_signal(sig);
    proc_data.signal_wq.notify_all(false);
}
pub fn send_signal_process(proc: &Process, sig: SignalInfo) {
    info!("Send signal {} to process {}", sig.signo(), proc.pid());
    let Some(proc_data) = proc.data::<ProcessData>() else {
        return;
    };
    proc_data.pending.lock().send_signal(sig);
    proc_data.signal_wq.notify_one(false);
}
pub fn send_signal_process_group(pg: &ProcessGroup, sig: SignalInfo) -> usize {
    info!("Send signal {} to process group {}", sig.signo(), pg.pgid());
    let processes = pg.processes();
    for proc in pg.processes() {
        send_signal_process(&proc, sig.clone());
    }
    processes.len()
}

fn make_siginfo(signo: u32, code: u32) -> LinuxResult<Option<SignalInfo>> {
    if !(1..32).contains(&signo) {
        return Err(LinuxError::EINVAL);
    }
    if signo == 0 {
        return Ok(None);
    }
    Ok(Some(SignalInfo::new(signo, code)))
}

pub fn sys_kill(pid: i32, sig: u32) -> LinuxResult<isize> {
    let Some(sig) = make_siginfo(sig, SI_USER)? else {
        // TODO: should also check permissions
        return Ok(0);
    };

    let curr = current();
    let mut result = 0usize;
    match pid {
        1.. => {
            let proc = get_process(pid as Pid)?;
            send_signal_process(&proc, sig);
            result += 1;
        }
        0 => {
            let pg = curr.task_ext().thread.process().group();
            result += send_signal_process_group(&pg, sig);
        }
        -1 => {
            for proc in processes() {
                if proc.is_init() {
                    // init process
                    continue;
                }
                send_signal_process(&proc, sig.clone());
                result += 1;
            }
        }
        ..-1 => {
            let pg = get_process_group((-pid) as Pid)?;
            result += send_signal_process_group(&pg, sig);
        }
    }

    Ok(result as isize)
}

pub fn sys_tgkill(tgid: Pid, tid: Pid, sig: u32) -> LinuxResult<isize> {
    let Some(sig) = make_siginfo(sig, SI_TKILL as u32)? else {
        // TODO: should also check permissions
        return Ok(0);
    };

    let thr = get_thread(tid)?;
    if thr.process().pid() != tgid {
        return Err(LinuxError::ESRCH);
    }
    send_signal_thread(&thr, sig);
    Ok(0)
}
