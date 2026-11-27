#include <uv.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main(void) {
    const char *source = "/sys/devices/system/cpu/online";
    struct stat info;
    if (stat(source, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0)
        return 77;

    int fd = open(source, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 77;
    char content[4096];
    ssize_t length = read(fd, content, sizeof(content));
    close(fd);
    if (length < 0 || info.st_size <= length) return 77;

    char scratch[] = "/tmp/circu-copyfile-eof-XXXXXX";
    CHECK(mkdtemp(scratch));
    char destination[sizeof(scratch) + 16];
    int written = snprintf(destination, sizeof(destination), "%s/copy", scratch);
    CHECK(written > 0 && (size_t)written < sizeof(destination));

    uv_fs_t request;
    int result = uv_fs_copyfile(NULL, &request, source, destination, 0, NULL);
    uv_fs_req_cleanup(&request);
    unlink(destination);
    CHECK(rmdir(scratch) == 0);

    CHECK(result == UV_EIO);
    return 0;
}
