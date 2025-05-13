#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define TEST(r, f, x, m) ( \
	errno=0, ((r) = (f)) == (x) || \
	(("%s failed (" m ")\n", #f, r, x, strerror(errno)), 0) )

#define TEST_S(s, x, m) ( \
	!strcmp((s),(x)) || \
	(("[%s] != [%s] (%s)\n", s, x, m), 0) )

static FILE *writetemp(const char *data)
{
	FILE *f = tmpfile();
	if (!f) return 0;
	if (!fwrite(data, strlen(data), 1, f)) {
		fclose(f);
		return 0;
	}
	rewind(f);
	return f;
}

int main(void)
{



	// int fd;
    // char write_buf[] = "Hello, this is a test!\n";
    // char read_buf[100] = {0};
    // ssize_t bytes_written, bytes_read;

    // // 1. 创建/打开文件（读写模式，不存在则创建，存在则清空）
    // fd = open("testfile.txt", O_RDWR | O_CREAT | O_TRUNC, 0644);
    // if (fd == -1) {
    //     perror("open failed");
    //     exit(EXIT_FAILURE);
    // }

    // // 2. 测试写入功能
    // bytes_written = write(fd, write_buf, strlen(write_buf));
    // if (bytes_written == -1) {
    //     perror("write failed");
    //     close(fd);
    //     exit(EXIT_FAILURE);
    // }
    // printf("Write test: Successfully wrote %zd bytes\n", bytes_written);

    // // 3. 将文件指针移回开头以准备读取
    // if (lseek(fd, 0, SEEK_SET) == -1) {
    //     perror("lseek failed");
    //     close(fd);
    //     exit(EXIT_FAILURE);
    // }

    // // 4. 测试读取功能
    // bytes_read = read(fd, read_buf, sizeof(read_buf) - 1);
    // if (bytes_read == -1) {
    //     perror("read failed");
    //     close(fd);
    //     exit(EXIT_FAILURE);
    // }
    // read_buf[bytes_read] = '\0'; // 确保字符串终止

    // printf("Read test: Successfully read %zd bytes\n", bytes_read);
    // printf("Content: %s", read_buf);

    // // 5. 验证读写内容是否一致
    // if (bytes_read != bytes_written || memcmp(write_buf, read_buf, bytes_written) != 0) {
    //     fprintf(stderr, "Verification failed: Written and read content differ!\n");
    //     close(fd);
    //     exit(EXIT_FAILURE);
    // }

    // printf("Verification: Written and read content match!\n");

    // // 6. 关闭文件
    // if (close(fd) == -1) {
    //     perror("close failed");
    //     exit(EXIT_FAILURE);
    // }
	
	
	
	
	
	int i, x, y;
	double u;
	char a[100], b[100];
	FILE *f;
	int p[2];

	TEST(i, pipe(p), 0, "failed to open pipe %d!=%d (%s)");
	TEST(i, !(f = fdopen(p[0], "rb")), 0, "failed to fdopen pipe %d!=%d (%s)");

	if (!f) {
		close(p[0]);
		close(p[1]);
		return 1;
	}

	// TEST(i, write(p[1], "hello, world\n", 13), 13, "write error %d!=%d (%s)");
	TEST(i, write(p[1], "hello, world\n", 13), 13, "write error %d!=%d (%s)");
	read(p[0], b, 13);
	
	// TEST(i, fscanf(f, "%s %[own]", a, b), 2, "got %d fields, expected %d");
	
	
	// TEST_S(a, "hello,", "wrong result for %s");
	// TEST_S(b, "wo", "wrong result for %[own]");
	// TEST(i, fgetc(f), 'r', "'%c' != '%c') (%s)");

	// TEST(i, write(p[1], " 0x12 0x34", 10), 10, "write error %d!=%d (%s)");
	// TEST(i, fscanf(f, "ld %5i%2i", &x, &y), 1, "got %d fields, expected %d");
	// TEST(i, x, 0x12, "%d != %d");
	// TEST(i, fgetc(f), '3', "'%c' != '%c'");

	// fclose(f);
	// close(p[1]);

	// TEST(i, !!(f=writetemp("      42")), 1, "failed to make temp file");
	// if (f) {
	// 	x=y=-1;
	// 	TEST(i, fscanf(f, " %n%*d%n", &x, &y), 0, "%d != %d");
	// 	TEST(i, x, 6, "%d != %d");
	// 	TEST(i, y, 8, "%d != %d");
	// 	TEST(i, ftell(f), 8, "%d != %d");
	// 	TEST(i, !!feof(f), 1, "%d != %d");
	// 	fclose(f);
	// }

	// TEST(i, !!(f=writetemp("[abc123]....x")), 1, "failed to make temp file");
	// if (f) {
	// 	x=y=-1;
	// 	TEST(i, fscanf(f, "%10[^]]%n%10[].]%n", a, &x, b, &y), 2, "%d != %d");
	// 	TEST_S(a, "[abc123", "wrong result for %[^]]");
	// 	TEST_S(b, "]....", "wrong result for %[].]");
	// 	TEST(i, x, 7, "%d != %d");
	// 	TEST(i, y, 12, "%d != %d");
	// 	TEST(i, ftell(f), 12, "%d != %d");
	// 	TEST(i, feof(f), 0, "%d != %d");
	// 	TEST(i, fgetc(f), 'x', "%d != %d");
	// 	fclose(f);
	// }

	// TEST(i, !!(f=writetemp("0x1p 12")), 1, "failed to make temp file");
	// if (f) {
	// 	x=y=-1;
	// 	u=-1;
	// 	TEST(i, fscanf(f, "%lf%n %d", &u, &x, &y), 0, "%d != %d");
	// 	TEST(u, u, -1.0, "%g != %g");
	// 	TEST(i, x, -1, "%d != %d");
	// 	TEST(i, y, -1, "%d != %d");
	// 	TEST(i, ftell(f), 4, "%d != %d");
	// 	TEST(i, feof(f), 0, "%d != %d");
	// 	TEST(i, fgetc(f), ' ', "%d != %d");
	// 	rewind(f);
	// 	TEST(i, fgetc(f), '0', "%d != %d");
	// 	TEST(i, fgetc(f), 'x', "%d != %d");
	// 	TEST(i, fscanf(f, "%lf%n%c %d", &u, &x, a, &y), 3, "%d != %d");
	// 	TEST(u, u, 1.0, "%g != %g");
	// 	TEST(i, x, 1, "%d != %d");
	// 	TEST(i, a[0], 'p', "%d != %d");
	// 	TEST(i, y, 12, "%d != %d");
	// 	TEST(i, ftell(f), 7, "%d != %d");
	// 	TEST(i, !!feof(f), 1, "%d != %d");
	// 	fclose(f);
	// }

	// TEST(i, !!(f=writetemp("0x.1p4    012")), 1, "failed to make temp file");
	// if (f) {
	// 	x=y=-1;
	// 	u=-1;
	// 	TEST(i, fscanf(f, "%lf%n %i", &u, &x, &y), 2, "%d != %d");
	// 	TEST(u, u, 1.0, "%g != %g");
	// 	TEST(i, x, 6, "%d != %d");
	// 	TEST(i, y, 10, "%d != %d");
	// 	TEST(i, ftell(f), 13, "%d != %d");
	// 	TEST(i, !!feof(f), 1, "%d != %d");
	// 	fclose(f);
	// }

	// TEST(i, !!(f=writetemp("0xx")), 1, "failed to make temp file");
	// if (f) {
	// 	x=y=-1;
	// 	TEST(i, fscanf(f, "%x%n", &x, &y), 0, "%d != %d");
	// 	TEST(i, x, -1, "%d != %d");
	// 	TEST(i, y, -1, "%d != %d");
	// 	TEST(i, ftell(f), 2, "%d != %d");
	// 	TEST(i, feof(f), 0, "%d != %d");
	// 	fclose(f);
	// }

	return 0;
}
