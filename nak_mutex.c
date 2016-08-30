#include <time.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include "nak_mutex.h"
#include "log.h"

void _nakd_mutex_lock(pthread_mutex_t *lock, const char *lock_name,
                                      const char *file, int line) {
    int timeout_sec = NAKD_MUTEX_TIMEOUT;

    for (int try = 0;; ++try) {
        struct timespec timeout;
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += timeout_sec;
        int lock_status = pthread_mutex_timedlock(lock, &timeout);
        if (lock_status == ETIMEDOUT) {
            nakd_log(L_CRIT, "mutex timeout: %s [%s:%d]", lock_name, file,
                                                                    line);
            timeout_sec = 1;
            if (try > 3)
                nakd_terminate("Deadlock. Terminating...");
        } else if (lock_status) {
            nakd_log(L_CRIT, "error while locking mutex: %s",
                                      strerror(lock_status));
        } else {
            break;
        }
    }
}

void _nakd_mutex_unlock(pthread_mutex_t *lock, const char *lock_name,
                                        const char *file, int line) {
    pthread_mutex_unlock(lock);
}
