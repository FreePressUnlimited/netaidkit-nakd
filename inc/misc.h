#ifndef NAKD_MISC_H
#define NAKD_MISC_H
#include <time.h>

#define N_ELEMENTS(arr) (sizeof(arr) / sizeof(arr[0]))
#define ARRAY_END(arr) (arr + N_ELEMENTS(arr))
#define ARRAY_ELEMENT_NUMBER(ptr, arr) ((int)(ptr - arr))

time_t monotonic_time(void);

#endif
