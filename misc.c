#include <time.h>
#include "misc.h"
#include "log.h"

time_t monotonic_time(void) {
    struct timespec ts;
    nakd_assert(!clock_gettime(CLOCK_MONOTONIC, &ts));
    return ts.tv_sec;
}
