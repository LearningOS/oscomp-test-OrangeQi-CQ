#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

const int MOD = 998244353;
int shm_id;

int parent() {
    printf("Parent process\n");
    int *shm_ptr = (int *)shmat(shm_id, NULL, 0);
    
    if (shm_ptr == (void *)-1) {
        perror("shmat failed in parent");
        return 1;
    }
    
    printf("parent shmptr: %p\n", shm_ptr);

    for (int i = 0; i < 10; i++) {
        if (shm_ptr[i] == i + MOD) {
            return -1;
        }
    }

    printf("parent process wait for child proces to update:\n");
    sleep(2);

    for (int i = 0; i < 10; i++) {
        if (shm_ptr[i] != i + MOD) {
            printf("failed\n");
            return -1;
        }
    }

    printf("check passed!\n");
    wait(NULL);

    if (shmdt(shm_ptr)) {
        perror("shmdt failed in parent");
        return 1;
    }
    if (shmctl(shm_id, IPC_RMID, NULL) == -1) {
        perror("shmctl failed");
        return 1;
    }

    return 0;
}

int child() {
    printf("Child process started\n");
    
    int *shm_ptr = (int *)shmat(shm_id, NULL, 0);

    sleep(1);
    for (int i = 0; i < 10; i++) {
        shm_ptr[i] = i + MOD;
    }
    printf("Child process finished writing\n");
    if (shmdt(shm_ptr)) {
        perror("shmdt failed in child");
        return 1;
    }

    return 0;
}


int main() {
    shm_id = shmget(IPC_PRIVATE, 4096 * 10, IPC_CREAT | 0666);
    if (shm_id == -1) {
        perror("shmget failed");
        return 1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork failed");
        return 1;
    }

    if (pid == 0) { 
        child();
    } else { 
        parent();
    }

    return 0;
}



// #include <stdio.h>
// #include <stdlib.h>
// #include <sys/ipc.h>
// #include <sys/shm.h>
// #include <string.h>


// // 单个进程, 创建共享内存，连接，写入数据，分离共享内存，重新连接，读取数据，删除共享内存
// int test1() {
//     key_t key = ftok(".", 'A'); // 生成唯一键值
//     int shmid;
//     char *shm_ptr;

//     if ((shmid = shmget(key, 1024, IPC_CREAT | 0666)) == -1) {
//         perror("shmget failed");
//         return -1;
//     }

//     if ((shm_ptr = shmat(shmid, NULL, 0)) == (char *)-1) {
//         perror("shmat failed");
//         shmctl(shmid, IPC_RMID, NULL); // 清理
//         return -1;
//     }

//     strcpy(shm_ptr, "Hello, SHM!");

//     if (shmdt(shm_ptr) == -1) {
//         perror("shmdt failed");
//         shmctl(shmid, IPC_RMID, NULL);
//         return -1;
//     }

//     shm_ptr = shmat(shmid, NULL, 0);

//     if (strcpy(shm_ptr, "Hello, SHM!") == NULL) {
//         perror("strcpy failed");
//         shmctl(shmid, IPC_RMID, NULL);
//         return -1;
//     }

//     shmctl(shmid, IPC_RMID, NULL);
//     printf("Test 1: Basic operations passed\n");
//     return 0;
// }


// int main() {
//     // 测试共享内存的基本操作
//     if (test1() == -1) {
//         printf("Test 1 failed\n");
//         return -1;
//     }

//     printf("All tests passed\n");
//     return 0;
// }