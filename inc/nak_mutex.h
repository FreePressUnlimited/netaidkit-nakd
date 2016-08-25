#ifndef NAKD_MUTEX_H
#define NAKD_MUTEX_H
#include <pthread.h>

#define NAKD_MUTEX_TIMEOUT 30

#define nakd_mutex_lock(lock) \
    _nakd_mutex_lock(lock, #lock, __FILE__, __LINE__)

#define nakd_mutex_unlock(lock) \
    _nakd_mutex_unlock(lock, #lock, __FILE__, __LINE__)

void _nakd_mutex_lock(pthread_mutex_t *lock, const char *lock_name,
                                       const char *file, int line);
void _nakd_mutex_unlock(pthread_mutex_t *lock, const char *lock_name,
                                         const char *file, int line);

#endif
