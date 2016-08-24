#ifndef NAKD_MISC_H
#define NAKD_MISC_H
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

#define N_ELEMENTS(arr) (sizeof(arr) / sizeof(arr[0]))
#define ARRAY_END(arr) (arr + N_ELEMENTS(arr))
#define ARRAY_ELEMENT_NUMBER(ptr, arr) ((int)(ptr - arr))

time_t monotonic_time(void);
void set_socket_timeout(int fd, int sec);

#define NAKD_MAX_ARG_STRLEN 8192
void log_execve(const char * const argv[]);

#endif
