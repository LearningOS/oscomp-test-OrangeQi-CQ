## ipc 抽象

### ipc 抽象的数据结构

`struct ipc_namespace` IPC 命名空间（用于资源隔离）

`struct ipc_id` IPC 对象 ID 管理结构

`struct ipc_ops` 操作函数集合（具体 IPC 类型的创建和检查方法）

`struct ipc_params` 参数（key、权限、标志等）

```c
// include/linux/pic.h
struct kern_ipc_perm {
	spinlock_t	lock;
	bool		deleted;
	int		id;
	key_t		key;
	kuid_t		uid;
	kgid_t		gid;
	kuid_t		cuid;
	kgid_t		cgid;
	umode_t		mode;
	unsigned long	seq;
	void		*security;

	struct rhash_head khtnode;

	struct rcu_head rcu;
	refcount_t refcount;
} ____cacheline_aligned_in_smp __r


/*
 * Structure that holds the parameters needed by the ipc operations
 * (see after)
 */
struct ipc_params {
	key_t key;
	int flg;
	union {
		size_t size;	/* for shared memories */
		int nsems;	/* for semaphores */
	} u;			/* holds the getnew() specific param */
};


struct ipc_ids {
	int in_use;
	unsigned short seq;
	struct rw_semaphore rwsem;
	struct idr ipcs_idr;
	int max_idx;
	int last_idx;	/* For wrap around detection */
#ifdef CONFIG_CHECKPOINT_RESTORE
	int next_id;
#endif
	struct rhashtable key_ht;
};


/*
 * Structure that holds some ipc operations. This structure is used to unify
 * the calls to sys_msgget(), sys_semget(), sys_shmget()
 *      . routine to call to create a new ipc object. Can be one of newque,
 *        newary, newseg
 *      . routine to call to check permissions for a new ipc object.
 *        Can be one of security_msg_associate, security_sem_associate,
 *        security_shm_associate
 *      . routine to call for an extra check if needed
 */
struct ipc_ops {
	int (*getnew)(struct ipc_namespace *, struct ipc_params *);
	int (*associate)(struct kern_ipc_perm *, int);
	int (*more_checks)(struct kern_ipc_perm *, struct ipc_params *);
};
```

`struct kern_ipc_perm` 


### ipc 抽象的操作

主要参考 `ipc/util.h` 和 `ipc/util.c`

```c
/**
 * ipcget - Common sys_*get() code
 * @ns: namespace
 * @ids: ipc identifier set
 * @ops: operations to be called on ipc object creation, permission checks
 *       and further checks
 * @params: the parameters needed by the previous operations.
 *
 * Common routine called by sys_msgget(), sys_semget() and sys_shmget().
 */
int ipcget(struct ipc_namespace *ns, struct ipc_ids *ids,
			const struct ipc_ops *ops, struct ipc_params *params)
{
	if (params->key == IPC_PRIVATE)
		return ipcget_new(ns, ids, ops, params);
	else
		return ipcget_public(ns, ids, ops, params);
}


/**
 * ipcget_new -	create a new ipc object
 * @ns: ipc namespace
 * @ids: ipc identifier set
 * @ops: the actual creation routine to call
 * @params: its parameters
 *
 * This routine is called by sys_msgget, sys_semget() and sys_shmget()
 * when the key is IPC_PRIVATE.
 */
static int ipcget_new(struct ipc_namespace *ns, struct ipc_ids *ids,
		const struct ipc_ops *ops, struct ipc_params *params)
{
	int err;

	down_write(&ids->rwsem);        // 占用写锁
	err = ops->getnew(ns, params);  
	up_write(&ids->rwsem);          // 释放写锁
	return err;
}


/**
 * ipcget_public - get an ipc object or create a new one
 * @ns: ipc namespace
 * @ids: ipc identifier set
 * @ops: the actual creation routine to call
 * @params: its parameters
 *
 * This routine is called by sys_msgget, sys_semget() and sys_shmget()
 * when the key is not IPC_PRIVATE.
 * It adds a new entry if the key is not found and does some permission
 * / security checkings if the key is found.
 *
 * On success, the ipc id is returned.
 */
static int ipcget_public(struct ipc_namespace *ns, struct ipc_ids *ids,
		const struct ipc_ops *ops, struct ipc_params *params)
{
	struct kern_ipc_perm *ipcp;
	int flg = params->flg;
	int err;

    // 占用写锁
	down_write(&ids->rwsem);

    // 在 ids 中根据 key 查找 struct kern_ipc_perm 对象。
	ipcp = ipc_findkey(ids, params->key);

	if (ipcp == NULL) {
		// 未找到 Key 的情况
		if (!(flg & IPC_CREAT))
			err = -ENOENT;  // Key 不存在且未指定 IPC_CREAT，返回错误
		else
			err = ops->getnew(ns, params); // 创建新对象
	} else {
		// 找到 Key 的情况
        
		if (flg & IPC_CREAT && flg & IPC_EXCL)
			err = -EEXIST;  // 指定了 IPC_EXCL，但对象已存在，返回错误
		else {
			err = 0;
			if (ops->more_checks)
				err = ops->more_checks(ipcp, params);   // 类型特定的额外检查
			if (!err)
				/*
				 * ipc_check_perms returns the IPC id on
				 * success
				 */
				err = ipc_check_perms(ns, ipcp, ops, params); // 权限验证
		}
		ipc_unlock(ipcp);
	}

    // 释放写锁
	up_write(&ids->rwsem);

    // 成功返回 ID，失败返回错误码
	return err;
}

```


[ipcget_new 的实现](https://elixir.bootlin.com/linux/v6.14.5/source/ipc/util.c#L339)


## ipc_namespace

```c
// ipc/shm.c 

SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
{
	return ksys_shmget(key, size, shmflg);
}

long ksys_shmget(key_t key, size_t size, int shmflg)
{
	struct ipc_namespace *ns;
	static const struct ipc_ops shm_ops = {
		.getnew = newseg,
		.associate = security_shm_associate,
		.more_checks = shm_more_checks,
	};
	struct ipc_params shm_params;

	ns = current->nsproxy->ipc_ns;

	shm_params.key = key;
	shm_params.flg = shmflg;
	shm_params.u.size = size;

	return ipcget(ns, &shm_ids(ns), &shm_ops, &shm_params);
}

```

# 共享内存
## 相关数据结构

shmid_kernel


## shmget

一句话概括：创建一个共享内存文件。内核维护 shmid 与共享内存文件的对应关系。


```c
// 系统调用 shmget
SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
{
	return ksys_shmget(key, size, shmflg);
}


// 这里定义了共享内存的相关 ops
long ksys_shmget(key_t key, size_t size, int shmflg)
{
	struct ipc_namespace *ns;
	static const struct ipc_ops shm_ops = {
		.getnew = newseg,
		.associate = security_shm_associate,
		.more_checks = shm_more_checks,
	};
	struct ipc_params shm_params;

	ns = current->nsproxy->ipc_ns;

	shm_params.key = key;
	shm_params.flg = shmflg;
	shm_params.u.size = size;

	return ipcget(ns, &shm_ids(ns), &shm_ops, &shm_params);
}
```

创建 System V 共享内存段的核心代码：
```c
/**
 * newseg - Create a new shared memory segment
 * @ns: namespace
 * @params: ptr to the structure that contains key, size and shmflg
 *
 * Called with shm_ids.rwsem held as a writer.
 */
static int newseg(struct ipc_namespace *ns, struct ipc_params *params)
{
	// 初始化参数，检查参数合法性

	key_t key = params->key;
	int shmflg = params->flg;
	size_t size = params->u.size;
	int error;
	struct shmid_kernel *shp;
	size_t numpages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT; 将用户指定的 size 转换为内存页数
	struct file *file;
	char name[13];
	vm_flags_t acctflag = 0;

	if (size < SHMMIN || size > ns->shm_ctlmax)
		return -EINVAL;

	if (numpages << PAGE_SHIFT < size)
		return -ENOSPC;

	if (ns->shm_tot + numpages < ns->shm_tot ||
			ns->shm_tot + numpages > ns->shm_ctlall)
		return -ENOSPC;

	// 创建共享内存 id 结构体 struct shmid_kernel shp，并进行初始化

	shp = kmalloc(sizeof(*shp), GFP_KERNEL_ACCOUNT);
	if (unlikely(!shp))
		return -ENOMEM;

	shp->shm_perm.key = key;
	shp->shm_perm.mode = (shmflg & S_IRWXUGO);
	shp->mlock_ucounts = NULL;

	shp->shm_perm.security = NULL;
	error = security_shm_alloc(&shp->shm_perm);
	if (error) {
		kfree(shp);
		return error;
	}

	// 创建共享内存文件

	sprintf(name, "SYSV%08x", key);
	if (shmflg & SHM_HUGETLB) {
		// 处理大页（HugeTLB）
		struct hstate *hs;
		size_t hugesize;

		hs = hstate_sizelog((shmflg >> SHM_HUGE_SHIFT) & SHM_HUGE_MASK);
		if (!hs) {
			error = -EINVAL;
			goto no_file;
		}
		hugesize = ALIGN(size, huge_page_size(hs));

		/* hugetlb_file_setup applies strict accounting */
		if (shmflg & SHM_NORESERVE)
			acctflag = VM_NORESERVE;
		file = hugetlb_file_setup(name, hugesize, acctflag,
				HUGETLB_SHMFS_INODE, (shmflg >> SHM_HUGE_SHIFT) & SHM_HUGE_MASK);
	} else {
		// 普通共享内存（基于 tmpfs）
		/*
		 * Do not allow no accounting for OVERCOMMIT_NEVER, even
		 * if it's asked for.
		 */
		if  ((shmflg & SHM_NORESERVE) &&
				sysctl_overcommit_memory != OVERCOMMIT_NEVER)
			acctflag = VM_NORESERVE;
		file = shmem_kernel_file_setup(name, size, acctflag);
	}
	error = PTR_ERR(file);
	if (IS_ERR(file))
		goto no_file;

	// 初始化 shp 的共享内存元数据

	shp->shm_cprid = get_pid(task_tgid(current));
	shp->shm_lprid = NULL;
	shp->shm_atim = shp->shm_dtim = 0;
	shp->shm_ctim = ktime_get_real_seconds();
	shp->shm_segsz = size;
	shp->shm_nattch = 0;
	shp->shm_file = file;
	shp->shm_creator = current;

	//  注册到 IPC 命名空间

	/* ipc_addid() locks shp upon success. */
	error = ipc_addid(&shm_ids(ns), &shp->shm_perm, ns->shm_ctlmni);
	if (error < 0)
		goto no_id;

	shp->ns = ns;


	// 关联到进程的共享内存列表

	task_lock(current);
	list_add(&shp->shm_clist, &current->sysvshm.shm_clist);
	task_unlock(current);

	// 设置 inode 标识符，更新统计信息并返回

	/*
	 * shmid gets reported as "inode#" in /proc/pid/maps.
	 * proc-ps tools use this. Changing this will break them.
	 */
	file_inode(file)->i_ino = shp->shm_perm.id;

	ns->shm_tot += numpages;
	error = shp->shm_perm.id;

	ipc_unlock_object(&shp->shm_perm);
	rcu_read_unlock();
	return error;

no_id:
	ipc_update_pid(&shp->shm_cprid, NULL);
	ipc_update_pid(&shp->shm_lprid, NULL);
	fput(file);
	ipc_rcu_putref(&shp->shm_perm, shm_rcu_free);
	return error;
no_file:
	call_rcu(&shp->shm_perm.rcu, shm_rcu_free);
	return error;
}
```

核心在于 `shmem_kernel_file_setup` 函数。

```c
// mm/shmem.c

static inline struct inode *shmem_get_inode(struct mnt_idmap *idmap,
				struct super_block *sb, struct inode *dir,
				umode_t mode, dev_t dev, unsigned long flags)
{
	struct inode *inode = ramfs_get_inode(sb, dir, mode, dev);
	return inode ? inode : ERR_PTR(-ENOSPC);
}

static struct file *__shmem_file_setup(struct vfsmount *mnt, const char *name,
			loff_t size, unsigned long flags, unsigned int i_flags)
{
	struct inode *inode;
	struct file *res;

	if (IS_ERR(mnt))
		return ERR_CAST(mnt);

	if (size < 0 || size > MAX_LFS_FILESIZE)
		return ERR_PTR(-EINVAL);

	if (shmem_acct_size(flags, size))
		return ERR_PTR(-ENOMEM);

	if (is_idmapped_mnt(mnt))
		return ERR_PTR(-EINVAL);

	inode = shmem_get_inode(&nop_mnt_idmap, mnt->mnt_sb, NULL,
				S_IFREG | S_IRWXUGO, 0, flags);		// 核心函数
	if (IS_ERR(inode)) {
		shmem_unacct_size(flags, size);
		return ERR_CAST(inode);
	}
	inode->i_flags |= i_flags;
	inode->i_size = size;
	clear_nlink(inode);	/* It is unlinked */
	res = ERR_PTR(ramfs_nommu_expand_for_mapping(inode, size));
	if (!IS_ERR(res))
		res = alloc_file_pseudo(inode, mnt, name, O_RDWR,
				&shmem_file_operations);
	if (IS_ERR(res))
		iput(inode);
	return res;
}

/**
 * shmem_kernel_file_setup - get an unlinked file living in tmpfs which must be
 * 	kernel internal.  There will be NO LSM permission checks against the
 * 	underlying inode.  So users of this interface must do LSM checks at a
 *	higher layer.  The users are the big_key and shm implementations.  LSM
 *	checks are provided at the key or shm level rather than the inode.
 * @name: name for dentry (to be seen in /proc/<pid>/maps
 * @size: size to be set for the file
 * @flags: VM_NORESERVE suppresses pre-accounting of the entire object size
 */
struct file *shmem_kernel_file_setup(const char *name, loff_t size, unsigned long flags)
{
	return __shmem_file_setup(shm_mnt, name, size, flags, S_PRIVATE);
}

EXPORT_SYMBOL_GPL(shmem_kernel_file_setup);
```

## shmctl

https://elixir.bootlin.com/linux/v6.14.5/source/ipc/shm.c#L1291

## shmat

https://elixir.bootlin.com/linux/v6.14.5/source/ipc/shm.c#L1688

作用是将共享内存段附加到当前进程的地址空间。

核心部分：

```c
/*
 * Fix shmaddr, allocate descriptor, map shm, add attach descriptor to lists.
 *
 * NOTE! Despite the name, this is NOT a direct system call entrypoint. The
 * "raddr" thing points to kernel space, and there has to be a wrapper around
 * this.
 */
long do_shmat(int shmid, char __user *shmaddr, int shmflg,
	      ulong *raddr, unsigned long shmlba)
{
	struct shmid_kernel *shp;
	unsigned long addr = (unsigned long)shmaddr;
	unsigned long size;
	struct file *file, *base;
	int    err;
	unsigned long flags = MAP_SHARED;
	unsigned long prot;
	int acc_mode;
	struct ipc_namespace *ns;
	struct shm_file_data *sfd;
	int f_flags;
	unsigned long populate = 0;

	err = -EINVAL;
	if (shmid < 0)
		goto out;

	// 参数校验，地址对齐，设置权限与保护位
	if (addr) {
		if (addr & (shmlba - 1)) {
			if (shmflg & SHM_RND) {
				addr &= ~(shmlba - 1);  /* round down */

				/*
				 * Ensure that the round-down is non-nil
				 * when remapping. This can happen for
				 * cases when addr < shmlba.
				 */
				if (!addr && (shmflg & SHM_REMAP))
					goto out;
			} else
#ifndef __ARCH_FORCE_SHMLBA
				if (addr & ~PAGE_MASK)
#endif
					goto out;
		}

		flags |= MAP_FIXED;
	} else if ((shmflg & SHM_REMAP))
		goto out;

	if (shmflg & SHM_RDONLY) {
		prot = PROT_READ;
		acc_mode = S_IRUGO;
		f_flags = O_RDONLY;
	} else {
		prot = PROT_READ | PROT_WRITE;
		acc_mode = S_IRUGO | S_IWUGO;
		f_flags = O_RDWR;
	}
	if (shmflg & SHM_EXEC) {
		prot |= PROT_EXEC;
		acc_mode |= S_IXUGO;
	}

	// 获取共享内存对象

	/*
	 * We cannot rely on the fs check since SYSV IPC does have an
	 * additional creator id...
	 */
	ns = current->nsproxy->ipc_ns;
	rcu_read_lock();
	shp = shm_obtain_object_check(ns, shmid);
	if (IS_ERR(shp)) {
		err = PTR_ERR(shp);
		goto out_unlock;
	}

	err = -EACCES;
	if (ipcperms(ns, &shp->shm_perm, acc_mode))
		goto out_unlock;

	err = security_shm_shmat(&shp->shm_perm, shmaddr, shmflg);
	if (err)
		goto out_unlock;

	ipc_lock_object(&shp->shm_perm);

	/* check if shm_destroy() is tearing down shp */
	if (!ipc_valid_object(&shp->shm_perm)) {
		ipc_unlock_object(&shp->shm_perm);
		err = -EIDRM;
		goto out_unlock;
	}

	// 引用计数与文件克隆（没看懂）

	/*
	 * We need to take a reference to the real shm file to prevent the
	 * pointer from becoming stale in cases where the lifetime of the outer
	 * file extends beyond that of the shm segment.  It's not usually
	 * possible, but it can happen during remap_file_pages() emulation as
	 * that unmaps the memory, then does ->mmap() via file reference only.
	 * We'll deny the ->mmap() if the shm segment was since removed, but to
	 * detect shm ID reuse we need to compare the file pointers.
	 */
	base = get_file(shp->shm_file);
	shp->shm_nattch++;
	size = i_size_read(file_inode(base));
	ipc_unlock_object(&shp->shm_perm);
	rcu_read_unlock();

	err = -ENOMEM;
	sfd = kzalloc(sizeof(*sfd), GFP_KERNEL);
	if (!sfd) {
		fput(base);
		goto out_nattch;
	}

	file = alloc_file_clone(base, f_flags,
			  is_file_hugepages(base) ?
				&shm_file_operations_huge :
				&shm_file_operations);
	err = PTR_ERR(file);
	if (IS_ERR(file)) {
		kfree(sfd);
		fput(base);
		goto out_nattch;
	}

	sfd->id = shp->shm_perm.id;
	sfd->ns = get_ipc_ns(ns);
	sfd->file = base;
	sfd->vm_ops = NULL;
	file->private_data = sfd;

	// 内存映射的核心：利用 mmap 将共享内存文件映射到进程地址空间

	err = security_mmap_file(file, prot, flags);
	if (err)
		goto out_fput;

	if (mmap_write_lock_killable(current->mm)) {
		err = -EINTR;
		goto out_fput;
	}

	if (addr && !(shmflg & SHM_REMAP)) {
		err = -EINVAL;
		if (addr + size < addr)
			goto invalid;

		if (find_vma_intersection(current->mm, addr, addr + size))
			goto invalid;
	}

	addr = do_mmap(file, addr, size, prot, flags, 0, 0, &populate, NULL);
	*raddr = addr;

	// 首位工作：错误处理与清理，引用计数与销毁检查
	
	err = 0;
	if (IS_ERR_VALUE(addr))
		err = (long)addr;
invalid:
	mmap_write_unlock(current->mm);
	if (populate)
		mm_populate(addr, populate);

out_fput:
	fput(file);

out_nattch:
	down_write(&shm_ids(ns).rwsem);
	shp = shm_lock(ns, shmid);
	shp->shm_nattch--;

	if (shm_may_destroy(shp))
		shm_destroy(ns, shp);
	else
		shm_unlock(shp);
	up_write(&shm_ids(ns).rwsem);
	return err;

out_unlock:
	rcu_read_unlock();
out:
	return err;
}
```


## shmdt

https://elixir.bootlin.com/linux/v6.14.5/source/ipc/shm.c#L1829