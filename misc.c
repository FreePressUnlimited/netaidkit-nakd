#include <stdlib.h>
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

void log_execve(const char * const argv[]) {
    int format_len = 0;
    char *execve_log = malloc(NAKD_MAX_ARG_STRLEN);
    nakd_assert(execve_log != NULL);

    for (; *argv != NULL; argv++)
        format_len += snprintf(execve_log + format_len, NAKD_MAX_ARG_STRLEN
                                               - format_len, " %s", *argv);

    nakd_log(L_DEBUG, execve_log);
    free(execve_log);
}
