#include <stdio.h>
#include <stddef.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <errno.h>

void test_create_and_stat() {
    
    key_t key = ftok("/tmp", 'A');
    int shmid = shmget(key, 1024, IPC_CREAT | 0666);
    
    if (shmid == -1) {
        perror("shmget failed");
        return;
    }

    struct shmid_ds buf;

    printf("sizeof shmid_ds: %d\n", sizeof(buf));
    printf("sizeof ipc_perm: %d\n", sizeof(buf.shm_perm));
    printf("sizelof ushort: %d\n", sizeof(buf.shm_perm.seq));

    printf("Offset of mode: %zu\n", offsetof(struct ipc_perm, mode));
    printf("Offset of seq: %zu\n", offsetof(struct ipc_perm, seq));
    printf("Offset of shm_segsz: %zu\n", offsetof(struct shmid_ds, shm_segsz));
    printf("Offset of shm_atime: %zu\n", offsetof(struct shmid_ds, shm_atime));
    printf("Offset of shm_dtime: %zu\n", offsetof(struct shmid_ds, shm_dtime));
    printf("Offset of shm_ctime: %zu\n", offsetof(struct shmid_ds, shm_ctime));
    printf("Offset of shm_cpid: %zu\n", offsetof(struct shmid_ds, shm_cpid));
    printf("Offset of shm_lpid: %zu\n", offsetof(struct shmid_ds, shm_lpid));
    printf("Offset of shm_nattch: %zu\n", offsetof(struct shmid_ds, shm_nattch));
    // printf("Offset of shm_unused: %zu\n", offsetof(struct shmid_ds, shm_unused));
    // printf("Offset of shm_unused2: %zu\n", offsetof(struct shmid_ds, shm_unused2));
    // printf("Offset of shm_unused3: %zu\n", offsetof(struct shmid_ds, shm_unused3));
    
    
    if (shmctl(shmid, IPC_STAT, &buf) == -1) {
        perror("shmctl IPC_STAT failed");
        return;
    }

    // printf("ipc perm: %d %d %d %d %d %d %s\n", 
    //     buf.shm_perm.key,
    //     buf.shm_perm.uid, 
    //     buf.shm_perm.gid,
    //     buf.shm_perm.cuid,
    //     buf.shm_perm.cgid,
    //     buf.shm_perm.mode,
    //     buf.shm_perm.seq
    // );

    // printf("shnidds: %d %d %d %d %d %d %d\n",
    //     buf.shm_segsz,
    //     buf.shm_atime,
    //     buf.shm_dtime,
    //     buf.shm_ctime,
    //     buf.shm_cpid,
    //     buf.shm_lpid,
    //     buf.shm_nattch
    // );


    printf("Shared memory segment created successfully\n");
    printf("Size: %zu bytes\n", buf.shm_segsz);
    printf("Last attach time: %ld\n", buf.shm_atime);
    printf("Processes attached: %d\n", buf.shm_nattch);

    // Cleanup
    shmctl(shmid, IPC_RMID, NULL);
}

void test_change_permissions() {
    key_t key = ftok("/tmp", 'B');
    int shmid = shmget(key, 1024, IPC_CREAT | 0666);
    
    struct shmid_ds buf;
    shmctl(shmid, IPC_STAT, &buf);
    
    printf("Old permissions: %o\n", buf.shm_perm.mode);
    
    buf.shm_perm.mode = 0600;  // Change to owner-only read/write
    if (shmctl(shmid, IPC_SET, &buf) == -1) {
        perror("shmctl IPC_SET failed");
        return;
    }
    
    shmctl(shmid, IPC_STAT, &buf);
    printf("New permissions: %o\n", buf.shm_perm.mode);
    
    shmctl(shmid, IPC_RMID, NULL);
}
void test_invalid_shmid() {
    struct shmid_ds buf;
    
    // Test with non-existent ID
    if (shmctl(99999, IPC_STAT, &buf) == -1) {
        perror("Expected error for invalid shmid");
        printf("Error code: %d\n", errno);
    }
}

void test_permission_denied() {
    key_t key = ftok("/tmp", 'C');
    int shmid = shmget(key, 1024, IPC_CREAT | 0600);  // Owner-only
    
    // Try to stat with different user (simulated by fork)
    pid_t pid = fork();
    if (pid == 0) {
        // Child process with different permissions
        struct shmid_ds buf;
        if (shmctl(shmid, IPC_STAT, &buf) == -1) {
            printf("Child got expected permission denied\n");
            _exit(0);
        }
        printf("Child unexpectedly succeeded\n");
        _exit(1);
    } else {
        wait(NULL);
        shmctl(shmid, IPC_RMID, NULL);
    }
}

void test_shm_lock() {
    key_t key = ftok("/tmp", 'D');
    int shmid = shmget(key, 1024, IPC_CREAT | 0666);
    
    // Lock shared memory in RAM
    if (shmctl(shmid, SHM_LOCK, NULL) == -1) {
        perror("SHM_LOCK failed");
        return;
    }
    
    printf("Shared memory locked in RAM\n");
    
    // Check lock status
    struct shmid_ds buf;
    shmctl(shmid, IPC_STAT, &buf);
    printf("Lock status: %s\n", (buf.shm_perm.mode & SHM_LOCKED) ? "Locked" : "Unlocked");
    
    // Unlock
    shmctl(shmid, SHM_UNLOCK, NULL);
    shmctl(shmid, IPC_RMID, NULL);
}

void test_shm_destroy() {
    key_t key = ftok("/tmp", 'E');
    int shmid = shmget(key, 1024, IPC_CREAT | 0666);
    
    // Attach to increment nattch
    void* addr = shmat(shmid, NULL, 0);
    
    // Try to destroy while attached
    if (shmctl(shmid, IPC_RMID, NULL) == -1) {
        printf("Expected failure when destroying attached segment\n");
    } else {
        printf("Unexpected success when destroying attached segment\n");
    }
    
    // Detach and destroy
    shmdt(addr);
    if (shmctl(shmid, IPC_RMID, NULL) == -1) {
        perror("IPC_RMID failed");
    } else {
        printf("Shared memory destroyed successfully\n");
    }
}

int main() {
    printf("=== Shared Memory Control Tests ===\n\n");
    
    printf("1. Create and stat test:\n");
    test_create_and_stat();
    
    printf("\n2. Permission change test:\n");
    test_change_permissions();
    
    printf("\n3. Invalid shmid test:\n");
    test_invalid_shmid();
    
    printf("\n4. Permission denied test:\n");
    test_permission_denied();
    
    printf("\n5. SHM lock test:\n");
    test_shm_lock();
    
    printf("\n6. Destroy test:\n");
    test_shm_destroy();
    
    return 0;
}