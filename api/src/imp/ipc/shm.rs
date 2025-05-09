use core::iter::Map;

use alloc::vec;
use alloc::vec::Vec;
use alloc::collections::btree_map::BTreeMap;

use lazy_static::lazy_static;
use axerrno::{LinuxError, LinuxResult};
use axtask::{current, TaskExtRef};
use linux_raw_sys::{general::SCHED_FLAG_UTIL_CLAMP_MIN, net::IPV6_CHECKSUM};
use alloc::sync::Arc;
use axsync::Mutex;

use axerrno::{AxError, AxResult, ax_err};

use axprocess::{Pid, Process, ProcessGroup, Session, Thread};

use crate::imp::{ipc::shm, task::sys_getpid};

use memory_addr::{PhysAddr, VirtAddr, VirtAddrRange, PAGE_SIZE_4K};
use page_table_entry::MappingFlags;
use page_table_multiarch::{PageSize, PageTable64};
use axhal::paging::{PageTable, PagingHandlerImpl};

// use crate::util::{BiBTreeMap, IPCID_ALLOCATOR};
use crate::imp::ipc::{BiBTreeMap, IPCID_ALLOCATOR};


bitflags::bitflags! {
    /// flags for sys_shmat
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/shm.h>
    #[derive(Debug)]
    struct ShmAtFlags: u32 {
        /* attach read-only else read-write */
        const SHM_RDONLY = 0o10000;
        /* round attach address to SHMLBA */
        const SHM_RND = 0o20000;
        /* take-over region on attach */
        const SHM_REMAP = 0o40000;
        
    }
}

/// flags for sys_shmget, sys_msgget, sys_semget
///
/// See <https://github.com/bminor/glibc/blob/master/bits/ipc.h>
pub const IPC_RMID: u32 = 0;
pub const IPC_SET: u32 = 1;
pub const IPC_STAT: u32 = 2;

#[repr(C)]
/// Data structure describing a shared memory segment.
/// see <https://github.com/bminor/glibc/blob/master/bits/shm.h>
pub struct CTypeIpcPerm {
    pub key: u32,                
    pub uid: u32,                
    pub gid: u32,               
    pub cuid: u32,
    pub cgid: u32, 
    pub mode: u16, 
    pub seq: u16,
}

/// Data structure describing a shared memory segment.
/// see <https://github.com/bminor/glibc/blob/master/bits/shm.h>
#[repr(C)]
pub struct CTypeShmidDs {
    pub shm_perm: IpcPerm,        
    pub shm_segsz: usize,         
    pub shm_atime: SystemTime,    
    pub shm_dtime: SystemTime,    
    pub shm_ctime: SystemTime,    
    pub shm_cpid: RawFd,         
    pub shm_lpid: RawFd,         
    pub shm_nattch: u32,         
}

/**
 * struct ShmInner is used to maintain the shared memory in kernel, similar to shmid_ds in Linux.
 */
struct ShmInner {
    pub shmid: i32,
    pub page_num: usize,
    pub va_range: BTreeMap<Pid, VirtAddrRange>, // there can be at most one va_range for each process?
    pub phys_pages: Vec<PhysAddr>, // shm page offset -> physical page
    pub rmid: bool, // remove on last detach
    pub mapping_flags: MappingFlags,
}

impl ShmInner {
    fn new(page_num: usize, mapping_flags: MappingFlags) -> Self {
        ShmInner {
            shmid: {
                let mut shmid_allocator = IPCID_ALLOCATOR.lock();
                shmid_allocator.alloc()
            },
            page_num,
            va_range: BTreeMap::new(),
            phys_pages: Vec::new(),
            rmid: false,
            mapping_flags,
        }
    }

    pub fn has_mapped_to_phys(&self) -> bool {
        !self.phys_pages.is_empty()
    }

    pub fn map_to_phys(&mut self, phys_pages: Vec<PhysAddr>) {
        assert!(self.phys_pages.is_empty());
        self.phys_pages = phys_pages;
    }

    pub fn attach_count(&self) -> usize {
        self.va_range.len()
    }

    fn get_addr_range(&self, pid: Pid) -> Option<VirtAddrRange> {
        self.va_range.get(&pid).cloned()
    }

    // called by sys_shmat
    fn attach_process(&mut self, pid: Pid, va_range: VirtAddrRange) {
        assert!(self.get_addr_range(pid).is_none());
        self.va_range.insert(pid, va_range);
    }

    // called by sys_shmdt
    fn detach_process(&mut self, pid: Pid) {
        assert!(self.get_addr_range(pid).is_some());
        self.va_range.remove(&pid);
    }
}


/**
 * struct ShmManager is used to maintain the relationship between the shared memory segments and processes.
 * 
 * note: this struct do not modify the struct ShmInner, but only maintain the mapping.
 */
struct ShmManager {
    key_shmid: BiBTreeMap<i32, i32>, // key <-> shm_id
    shmid_inner: BTreeMap<i32, Arc<Mutex<ShmInner>>>, // shm_id -> shm_inner
    pid_shmid_vaddr: BTreeMap<Pid, BiBTreeMap<i32, VirtAddr>>, // in specific process, shm_id <-> shm_start_addr
}

impl ShmManager {
    const fn new() -> Self {
        ShmManager {
            key_shmid: BiBTreeMap::new(),
            shmid_inner: BTreeMap::new(),
            pid_shmid_vaddr: BTreeMap::new(),
        }
    }
    
    // used by sys_shmget
    fn get_shmid_by_key(&self, key: i32) -> Option<i32> {
        self.key_shmid.get_by_key(&key).cloned()
    }   

    // the only way to find shm_inner -- the data structure to maintain shm
    fn get_inner_by_shmid(&self, shmid: i32) -> Option<Arc<Mutex<ShmInner>>> {
        self.shmid_inner.get(&shmid).cloned()
    }

    // used by sys_shmdt
    fn get_shmid_by_vaddr(&self, pid: Pid, vaddr: VirtAddr) -> Option<i32> {
        self.pid_shmid_vaddr
            .get(&pid)
            .and_then(|map| map.get_by_value(&vaddr))
            .cloned()
    }

    fn get_shmids_by_pid(&self, pid: Pid) -> Option<Vec<i32>> {
        let map = self.pid_shmid_vaddr.get(&pid);
        if map.is_none() {
            return None;
        }
        let mut res = Vec::new();
        for key in map.unwrap().forward.keys() {
            res.push(*key); // 直接复制 key（假设 key 是 Copy 类型）
        }
        Some(res)
    }
    
    // used by garbage collection
    fn find_vaddr_by_shmid(&self, pid: Pid, shmid: i32) -> Option<VirtAddr> {
        self.pid_shmid_vaddr
            .get(&pid)
            .and_then(|map| map.get_by_key(&shmid))
            .cloned()
    }

    // used by sys_shmget
    pub fn insert_key_shmid(&mut self, key: i32, shmid: i32) {
        self.key_shmid.insert(key, shmid);
    }

    // used by sys_shmat
    pub fn insert_shmid_inner(&mut self, shmid: i32, shm_inner: Arc<Mutex<ShmInner>>) {
        self.shmid_inner.insert(shmid, shm_inner);
    }

    // used by sys_shmat, aiming at garbage collection when called sys_shmdt
    pub fn insert_shmid_vaddr(&mut self, pid: Pid, shmid: i32, vaddr: VirtAddr) {
        // maintain the map 'shmid_vaddr'
        self.pid_shmid_vaddr
            .entry(pid)
            .or_insert_with(BiBTreeMap::new)
            .insert(shmid, vaddr);
    }

    /**
     * Garbage collection for shared memory:
     * 1. when the process call sys_shmdt, delete everything related to shmaddr, 
     *    including the bidirectional map 'shmid_vaddr';
     * 2. when the last process detach the shared memory and this shared memory 
     *    was specified with IPC_RMID, delete everything related to this shared memory, 
     *    including all the 3 bidirectional maps;
     * 3. when a process exit, delete everything related to this process, including 2 
     *    bidirectional maps: 'shmid_vaddr' and 'shmid_inner';
     * 
     * 
     * Besides, the process_data maintains information about the shared memory it has, 
     *    in order to drop the shared memory when the process exits.
     * The attach between the process and the shared memory occurs in sys_shmat,
     *   and the detach occurs in sys_shmdt, or when the process exits.
     */

    /**
     * note: all the below delete functions only delete the mapping between the shm_id and the shm_inner,
     *    and the shm_inner is not deleted or modifyed.
     */
    
    // called by shmdt
    pub fn remove_shmaddr(&mut self, pid: Pid, shmaddr: VirtAddr) {
        let mut empty : bool = false;
        if let Some(map) = self.pid_shmid_vaddr.get_mut(&pid) {
            map.remove_by_value(&shmaddr);
            empty = map.forward.is_empty();
        }
        if empty {
            self.pid_shmid_vaddr.remove(&pid);
        }
    }
    
    // called when a process exit
    pub fn remove_pid(&mut self, pid: Pid) {   
        self.pid_shmid_vaddr.remove(&pid);
    }

    pub fn remove_shmid(&mut self, shmid: i32) {
        self.key_shmid.remove_by_value(&shmid);
        self.shmid_inner.remove(&shmid);
        for (key, map) in &self.pid_shmid_vaddr {
            assert!(map.get_by_key(&shmid).is_none());
        }
    }
}

lazy_static! {
    static ref SHM_MANAGER: Mutex<ShmManager> = Mutex::new(ShmManager::new());
}

// called when a process exit
pub fn clear_proc_shm(pid: Pid) {
    let mut shm_manager = SHM_MANAGER.lock();
    if let Some(shmids) = shm_manager.get_shmids_by_pid(pid) {
        for shmid in shmids {
            let mut shm_inner = shm_manager.get_inner_by_shmid(shmid).unwrap();
            let mut shm_inner = shm_inner.lock();
            shm_inner.detach_process(pid);
        }
    }
    shm_manager.remove_pid(pid);
}

pub fn sys_shmget(key: i32, size: usize, shmflg: usize) -> LinuxResult<isize> {
    let size = memory_addr::align_up_4k(size);
    let page_num = size / PAGE_SIZE_4K;
    if page_num == 0 {
        return Err(LinuxError::EINVAL);
    }

    let mut mapping_flags = MappingFlags::empty();
    mapping_flags.insert(MappingFlags::USER);
    if shmflg & 0o400 != 0 {
        mapping_flags.insert(MappingFlags::READ);
    }
    if shmflg & 0o200 != 0 {
        mapping_flags.insert(MappingFlags::WRITE);
    }
    if shmflg & 0o100 != 0 {
        mapping_flags.insert(MappingFlags::EXECUTE);
    }
    
    let mut shm_manager = SHM_MANAGER.lock();
    
    // This process has already created a shared memory segment with the same key
    if let Some(shmid) = shm_manager.get_shmid_by_key(key) {
        let mut shm_inner = shm_manager.get_inner_by_shmid(shmid).ok_or(LinuxError::EINVAL)?;
        let mut shm_inner = shm_inner.lock();
        if shm_inner.page_num != page_num || shm_inner.mapping_flags != mapping_flags {
            return Err(LinuxError::EINVAL);
        }
        return Ok(shmid as isize);
    }

    // Create a new shm_inner
    let shm_inner = Arc::new(Mutex::new(
        ShmInner::new(page_num, mapping_flags)
    ));
    let shmid = {
        let shm_inner = shm_inner.lock();
        shm_inner.shmid
    };
    shm_manager.insert_key_shmid(key, shmid);
    shm_manager.insert_shmid_inner(shmid, shm_inner);
    
    Ok(shmid as isize)
}

pub fn sys_shmat(shmid: i32, addr: usize, shmflg: u32) -> LinuxResult<isize> {
    error!("sys_shmat: shmid = {}", shmid);
    
    let shm_inner = {
        let shm_manager = SHM_MANAGER.lock();
        shm_manager.get_inner_by_shmid(shmid).unwrap()
    };
    let mut shm_inner = shm_inner.lock();

    warn!("mapping_flags: {:#x?}", shm_inner.mapping_flags);

    let mut mapping_flags = shm_inner.mapping_flags.clone();
    let shm_flg = ShmAtFlags::from_bits_truncate(shmflg);

    if shm_flg.contains(ShmAtFlags::SHM_RDONLY) {
        // mapping_flags.remove(MappingFlags::WRITE);
    }

    // TODO: solve shmflg: SHM_RND and SHM_REMAP

    let curr = current();
    let process_data = curr.task_ext().process_data();
    let cur_pid = current().task_ext().thread.process().pid();
    let mut aspace = process_data.aspace.lock();

    let start_aligned = memory_addr::align_down_4k(addr);
    let length = shm_inner.page_num * PAGE_SIZE_4K;

    // alloc the virtual address range
    assert!(shm_inner.get_addr_range(cur_pid).is_none());
    let start_addr  = aspace
            .find_free_area(
                VirtAddr::from(start_aligned),
                length,
                VirtAddrRange::new(aspace.base(), aspace.end()),
            )
            .or_else(|| aspace.find_free_area(
                aspace.base(),
                length,
                VirtAddrRange::new(aspace.base(), aspace.end()),
            ))
            .ok_or(LinuxError::ENOMEM)?;
    let end_addr = VirtAddr::from(start_addr.as_usize() + length);
    let va_range = VirtAddrRange::new(start_addr, end_addr);

    let mut shm_manager = SHM_MANAGER.lock();
    shm_manager.insert_shmid_vaddr(cur_pid, shm_inner.shmid, start_addr);
    shm_inner.attach_process(cur_pid, va_range);

    warn!("[SYS_SHMGET]: Process {} alloc shm addr: {:#x}, size: {}, mapping_flags: {:#x?}", 
                        cur_pid, start_addr.as_usize(), length, mapping_flags);

    let mapping_flags = MappingFlags::all();
                        
    // map the virtual address range to the physical address
    if !shm_inner.has_mapped_to_phys() {
        // This is the first process to attach the shared memory
        let result = aspace.map_alloc(
            start_addr,
            length,
            mapping_flags,
            // MappingFlags::all(),
            true,
        );

        match result {
            Ok(_) => {
                info!("proc {} map shm addr: {:#x}, size: {}", cur_pid, start_addr.as_usize(), length);
            }
            Err(e) => {
                error!("proc {} map shm addr: {:#x}, size: {}, error: {:?}", cur_pid, start_addr.as_usize(), length, e);
                return Err(LinuxError::ENOMEM);
            }
        }

        let mut tmp_page_table = vec![PhysAddr::from_usize(0); shm_inner.page_num];
        for i in 0..shm_inner.page_num {
            let proc_page_table = aspace.page_table();
            let curr_vaddr = start_addr + i * PAGE_SIZE_4K;
            let (mut paddr, _, _) = proc_page_table.query(curr_vaddr).map_err(|_| AxError::BadAddress)?;
            tmp_page_table[i] = paddr;
            info!("proc[{}]  vaddr[{:#x}] paddr[{:#x}] flags[{:#x}]", cur_pid, curr_vaddr.as_usize(), paddr.as_usize(), mapping_flags);
        }
        shm_inner.map_to_phys(tmp_page_table);
    } else {
        // Another proccess has attached the shared memory
        error!("branch 2");

        for i in 0..shm_inner.page_num {
            let proc_page_table = aspace.page_table_mut();
            let paddr = *shm_inner.phys_pages.get(i).ok_or(LinuxError::EINVAL)?;
            let vaddr = start_addr + i * PAGE_SIZE_4K;
            let result = proc_page_table.map(vaddr, paddr, PageSize::Size4K, mapping_flags);
            match result {
                Ok(_) => {
                    info!("proc[{}]  vaddr[{:#x}] paddr[{:#x}] flags[{:#x}]", 
                            cur_pid, vaddr.as_usize(), paddr.as_usize(), mapping_flags);
                }
                Err(e) => {
                    error!("proc[{}]  vaddr[{:#x}] paddr[{:#x}] flags[{:#x}], error: {:?}", 
                            cur_pid, vaddr.as_usize(), paddr.as_usize(), mapping_flags, e);
                    return Err(LinuxError::EINVAL);
                }
            }
        }
    }

    // axhal::arch::flush_tlb(None);
    Ok(start_addr.as_usize() as isize)
}

pub fn sys_shmctl(shmid: i32, cmd: u32, buf: usize) -> LinuxResult<isize> {
    let shm_inner = {
        let shm_manager = SHM_MANAGER.lock();
        shm_manager.get_inner_by_shmid(shmid).ok_or(LinuxError::EINVAL)?
    };
    let mut shm_inner = shm_inner.lock();

    if cmd == IPC_SET || cmd == IPC_STAT {
        return Err(LinuxError::EINVAL);
    }

    if cmd == IPC_STAT {
        shm_inner.rmid = true;
        return Ok(0)
    }

    Ok(0)
}

pub fn sys_shmdt(shmaddr: usize) -> LinuxResult<isize> {
    let shmaddr = VirtAddr::from(shmaddr);
    let pid = {
        let curr = current();
        curr.task_ext().thread.process().pid()
    };
    let shmid = {
        let shm_manager = SHM_MANAGER.lock();
        shm_manager.get_shmid_by_vaddr(pid, shmaddr)
            .ok_or(LinuxError::EINVAL)?
    };
    warn!("sys_shmdt: shmid = {}", shmid);
    
    let shm_inner = {
        let shm_manager = SHM_MANAGER.lock();
        shm_manager.get_inner_by_shmid(shmid).ok_or(LinuxError::EINVAL)?
    };
    let mut shm_inner = shm_inner.lock();
    let va_range = shm_inner.get_addr_range(pid).ok_or(LinuxError::EINVAL)?;

    let curr = current();
    let mut aspace =  curr.task_ext().process_data().aspace.lock();
    aspace.unmap(va_range.start, va_range.size())?;
    axhal::arch::flush_tlb(None);

    let mut shm_manager = SHM_MANAGER.lock();
    shm_manager.remove_shmaddr(pid, shmaddr);
    shm_inner.detach_process(pid);

    if shm_inner.rmid && shm_inner.attach_count() == 0 {
        shm_manager.remove_shmid(shmid);
    }
    
    Ok(0)
}