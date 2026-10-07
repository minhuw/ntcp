#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int connection(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(16380)};
    assert(inet_pton(AF_INET, "10.73.0.1", &a.sin_addr) == 1);
    assert(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    return fd;
}
static atomic_int reading;
static int cancelled_cleanup;
static void reader_cleanup(void *p) { ++*(int *)p; }
static void *managed_reader(void *p) {
    int fd = *(int *)p;
    char byte;
    pthread_cleanup_push(reader_cleanup, &cancelled_cleanup);
    atomic_store(&reading, 1);
    ssize_t result = read(fd, &byte, 1);
    (void)result;
    // Explicit C cancellation point after Rust has released all lifetimes.
    pthread_testcancel();
    pthread_cleanup_pop(0);
    return NULL;
}
static void managed_cancel_safety(void) {
    int fd = connection();
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, managed_reader, &fd));
    while (!atomic_load(&reading)) sched_yield();
    usleep(20000);
    assert(!pthread_cancel(thread));
    // Managed cancellation is not prompt yet: release its Rust wait explicitly.
    assert(shutdown(fd, SHUT_RD) == 0);
    void *result;
    assert(!pthread_join(thread, &result));
    assert(result == PTHREAD_CANCELED && cancelled_cleanup == 1);
    assert(close(fd) == 0);
}
static void bounded_cookies(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    FILE *streams[512];
    for (size_t i = 0; i < 512; ++i) {
        streams[i] = fdopen(fd, "r+");
        assert(streams[i]);
    }
    assert(!fdopen(fd, "r+") && errno == EMFILE);
    assert(fcntl(fd, F_GETFD) >= 0);
    assert(fclose(streams[0]) == 0);
    for (size_t i = 1; i < 512; ++i)
        assert(fclose(streams[i]) == EOF && errno == EBADF);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    FILE *stream = fdopen(fd, "r+");
    assert(stream && fclose(stream) == 0);
}
int main(int argc, char **argv) {
    assert(argc == 2 || (argc == 3 && !strcmp(argv[2], "--managed")));
    signal(SIGPIPE, SIG_IGN);
    int fd = connection();
    errno = 0;
    assert(fdopen(fd, "invalid") == NULL && errno == EINVAL);
    assert(fcntl(fd, F_GETFD) >= 0); // Failed construction retains ownership.
    FILE *f = fdopen(fd, argv[1]);
    assert(f && fileno(f) == fd && fileno_unlocked(f) == fd);
    assert(fputs("PING\r\n", f) >= 0);
    assert(fflush(f) == 0);
    char reply[32];
    assert(fgets(reply, sizeof(reply), f) && !strcmp(reply, "+PONG\r\n"));
    assert(fseek(f, 0, SEEK_SET) == -1 && errno == ESPIPE);
    clearerr(f);
    // Larger than the adapter's per-call buffer; cookie writes must retry.
    size_t size = 256 * 1024;
    unsigned char *data = malloc(size), *copy = malloc(size);
    assert(data && copy);
    for (size_t i = 0; i < size; ++i) data[i] = (unsigned char)i;
    assert(fwrite(data, 1, size, f) == size);
    assert(fflush(f) == 0);
    assert(fread(copy, 1, size, f) == size && !memcmp(data, copy, size));
    free(data); free(copy);
    assert(fclose(f) == 0);
    assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    // Closing/reusing a FILE's fd must not redirect callbacks or fclose.
    fd = connection();
    f = fdopen(fd, "r+");
    assert(f && close(fd) == 0);
    int replacement = socket(AF_INET, SOCK_STREAM, 0);
    assert(replacement >= 0);
    if (replacement != fd) {
        assert(dup2(replacement, fd) == fd);
        assert(close(replacement) == 0);
    }
    if (argc == 3) {
    assert(fputs("do not redirect", f) >= 0);
    assert(fflush(f) == EOF && errno == EBADF);
    assert(fclose(f) == EOF && errno == EBADF);
    assert(fcntl(fd, F_GETFD) >= 0);
    assert(close(fd) == 0);
    } else {
        // Native libc has no descriptor identity guard.
        assert(fclose(f) == 0);
    }
    if (argc == 3) {
        bounded_cookies();
        managed_cancel_safety();
    }
    FILE *native = tmpfile();
    assert(native && fileno(native) >= 0);
    assert(fputs("native", native) >= 0 && fflush(native) == 0);
    rewind(native);
    assert(fgets(reply, sizeof(reply), native) && !strcmp(reply, "native"));
    assert(fclose(native) == 0);
    puts("PASS stdio buffering, binary payload, identity, ownership, reuse and native FILE");
    return 0;
}
