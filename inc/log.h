#ifndef NAKD_LOG_H
#define NAKD_LOG_H
#include <stdio.h>
#include <stdlib.h>
#define DEFAULT_LOG_LEVEL L_INFO

enum {
    L_CRIT,
    L_WARNING,
    L_NOTICE,
    L_INFO,
    L_DEBUG,

    L_END
};

#define nakd_log(priority, format, args...) \
    _nakd_log((priority), (format), __func__, __FILE__, __LINE__, ##args)

extern const char *loglevel_string[];

void _nakd_log(int priority, const char *format, const char *func,
                                 const char *file, int line, ...);

#define nakd_log_va(priority, format, vl) \
    _nakd_log_va((priority), (format), __func__, __FILE__, __LINE__, vl)

void _nakd_log_va(int priority, const char *format, const char *func,
                             const char *file, int line, va_list vl);

#define nakd_terminate(format, args...) \
    { nakd_log(L_CRIT, (format), ##args); fflush(stdout); fflush(stderr); \
                                                                 exit(1); }

#define nakd_assert(stmt) _nakd_assert((stmt), #stmt, __PRETTY_FUNCTION__, __LINE__)

void _nakd_assert(int stmt, const char *stmt_str, const char *func, int line);

#define nakd_log_execution_point() \
    nakd_log(L_DEBUG, "")

void nakd_set_loglevel(int level);
void nakd_use_syslog(int use);
void nakd_log_init();
void nakd_log_close();

#endif
