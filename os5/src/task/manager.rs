use super::TaskControlBlock;
use crate::sync::UPSafeCell;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;
use crate::config::BIG_STRIDE;

pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
}

/// A Stride scheduler.
impl TaskManager {
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
        }
    }
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        let task_inner = task.inner_exclusive_access();
        let stride = task_inner.task_stride;
        drop(task_inner);
        let len = self.ready_queue.len();
        for queue in 0..len{
            let task1 = self.ready_queue.get_mut(queue).unwrap();
            let stride1 = task1.inner_exclusive_access().task_stride;
            if (stride < stride1 && ((stride1 - stride) <= (BIG_STRIDE / 2))) || (stride > stride1 && ((stride - stride1) > (BIG_STRIDE / 2))) {
                self.ready_queue.insert(queue, task);
                return
            }
        }
        self.ready_queue.push_back(task)
    }
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.ready_queue.pop_front()
    }
}

lazy_static! {
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

pub fn add_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.exclusive_access().add(task);
}

pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    TASK_MANAGER.exclusive_access().fetch()
}
