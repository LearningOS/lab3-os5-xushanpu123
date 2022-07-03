use crate::config::MAX_SYSCALL_NUM;
use crate::task::{
    add_task, current_task, exit_current_and_run_next, suspend_current_and_run_next, get_task_info,
    current_user_token, memory_alloc, memory_free, TaskStatus, TaskControlBlock, set_task_priority
};
use crate::mm::{VirtAddr, PhysAddr, PageTable, translated_refmut, translated_str};
use crate::timer::{get_time_us};
use crate::loader::get_app_data_by_name;
use alloc::sync::Arc;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub status: TaskStatus,
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    pub time: usize,
}

pub fn sys_exit(exit_code: i32) -> ! {
    debug!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    let task = current_task().unwrap();
    // find a child process

    // ---- access current TCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB lock exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after removing from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child TCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB lock automatically
}

// YOUR JOB: 引入虚地址后重写 sys_get_time
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    let _us = get_time_us();
    let t = _us / 1000;
    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    let va = VirtAddr::from(ts as usize);
    let vpn = va.floor();
    let ppn = page_table.translate(vpn).unwrap().ppn();
    let buf = ppn.get_bytes_array();
    let sec = t / 1000;
    let usec = t % 1000 * 1000;
    let offset = va.page_offset();

    buf[offset+0] = (sec & 0xff) as u8;
    buf[offset+1] = ((sec >> 8) & 0xff) as u8;
    buf[offset+2] = ((sec >> 16) & 0xff) as u8;
    buf[offset+3] = ((sec >> 24) & 0xff) as u8;

    buf[offset+8] = (usec & 0xff) as u8;
    buf[offset+9] = ((usec >> 8) & 0xff) as u8;
    buf[offset+10] = ((usec >> 16) & 0xff) as u8;
    buf[offset+11] = ((usec >> 24) & 0xff) as u8;
    0
}

// CLUE: 从 ch4 开始不再对调度算法进行测试~
pub fn sys_set_priority(pri: isize) -> isize {
    if pri < 2{
        return -1;
    }
    set_task_priority(pri as usize);
    pri as isize
}


// YOUR JOB: 扩展内核以实现 sys_mmap 和 sys_munmap
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    memory_alloc(start, len, port)
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    memory_free(start, len)
}

pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    let va = VirtAddr::from(ti as usize);
    let vpn = va.floor();
    let ppn = page_table.translate(vpn).unwrap().ppn();
    let offset = va.page_offset();
    let pa: PhysAddr = ppn.into();
    unsafe {
        let task_info = ((pa.0 + offset) as *mut TaskInfo).as_mut().unwrap();
        let tmp = get_task_info();
        *task_info = tmp;
    }
    0
}

// YOUR JOB: 实现 sys_spawn 系统调用
// ALERT: 注意在实现 SPAWN 时不需要复制父进程地址空间，SPAWN != FORK + EXEC
pub fn sys_spawn(_path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, _path);
    return if let Some(data) = get_app_data_by_name(path.as_str()) {
        let new_task: Arc<TaskControlBlock> = Arc::new(TaskControlBlock::new(data));
        let mut new_inner = new_task.inner_exclusive_access();
        let parent = current_task().unwrap();
        let mut parent_inner = parent.inner_exclusive_access();
        new_inner.parent = Some(Arc::downgrade(&parent));
        parent_inner.children.push(new_task.clone());
        drop(new_inner);
        drop(parent_inner);
        let new_pid = new_task.pid.0;
        add_task(new_task);
        new_pid as isize
    } else {
        -1
    }
}
