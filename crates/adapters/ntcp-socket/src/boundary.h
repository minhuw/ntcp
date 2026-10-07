#ifndef NTCP_BOUNDARY_H
#define NTCP_BOUNDARY_H
#include <errno.h>
#include <pthread.h>
// Every C -> Rust call is masked, including classifiers and nonblocking APIs.
// A signal handler may call native libc cancellation points while Rust is
// interrupted. Restore only in C, after the last Rust frame has returned.
// Nested calls preserve the disabled state; native forwarding remains outside.
#define NTCP_RUST_CALL(type, expression) ({ \
    int ntcp_state; \
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ntcp_state); \
    type ntcp_result = (expression); \
    int ntcp_errno = errno; \
    pthread_setcancelstate(ntcp_state, NULL); \
    errno = ntcp_errno; \
    ntcp_result; \
})
#endif
