#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define FILE_SIZE 1024

int main() {
    // 打开文件，如果文件不存在则创建，以读写模式打开
    int fd = open("testfile.txt", O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd == -1) {
        perror("open");
        return EXIT_FAILURE;
    }

    // 扩展文件大小到指定大小
    if (lseek(fd, FILE_SIZE - 1, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        return EXIT_FAILURE;
    }

    // 写入一个空字节，确保文件大小被扩展
    if (write(fd, "", 1) != 1) {
        perror("write");
        close(fd);
        return EXIT_FAILURE;
    }

    // 将文件映射到内存
    char *addr = mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return EXIT_FAILURE;
    }

    // 向映射的内存中写入数据
    for (int i = 0; i < FILE_SIZE; i++) {
        addr[i] = 'A' + (i % 26);
    }

    // 同步内存中的数据到文件
    if (msync(addr, FILE_SIZE, MS_SYNC) == -1) {
        perror("msync");
    }

    // 解除内存映射
    if (munmap(addr, FILE_SIZE) == -1) {
        perror("munmap");
    }

    // 关闭文件
    close(fd);

    // 重新打开文件以验证修改
    fd = open("testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return EXIT_FAILURE;
    }

    // 读取文件内容并打印
    char buffer[FILE_SIZE];
    ssize_t bytes_read = read(fd, buffer, FILE_SIZE);
    if (bytes_read == -1) {
        perror("read");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("File content:\n");
    for (int i = 0; i < bytes_read; i++) {
        putchar(buffer[i]);
    }
    putchar('\n');

    // 关闭文件
    close(fd);

    return EXIT_SUCCESS;
}    