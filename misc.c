#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "misc.h"
#include "log.h"

time_t monotonic_time(void) {
    struct timespec ts;
    nakd_assert(!clock_gettime(CLOCK_MONOTONIC, &ts));
    return ts.tv_sec;
}

void set_socket_timeout(int fd, int sec) {
    struct timeval connect_timeout = {
        .tv_sec = sec
    };
    nakd_assert(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                       (const void *)(&connect_timeout),
                               sizeof connect_timeout));
    nakd_assert(!setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                       (const void *)(&connect_timeout),
                               sizeof connect_timeout));
}
