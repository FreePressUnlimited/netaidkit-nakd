#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "log.h"

#define CRIT    "CRITICAL"
#define WARNING "WARNING"
#define NOTICE  "NOTICE"
#define INFO    "INFO"
#define DEBUG   "DEBUG"

static int use_syslog = 1;
static int loglevel = DEFAULT_LOG_LEVEL;

static int syslog_loglevel[] = {
    [L_CRIT] = LOG_CRIT,
    [L_WARNING] = LOG_WARNING,
    [L_NOTICE] = LOG_NOTICE,
    [L_INFO] = LOG_INFO,
    [L_DEBUG] = LOG_DEBUG,
};

const char *loglevel_string[] = {
    [L_CRIT] = CRIT,
    [L_WARNING] = WARNING,
    [L_NOTICE] = NOTICE,
    [L_INFO] = INFO,
    [L_DEBUG] = DEBUG,

    [L_END] = NULL
};

void nakd_set_loglevel(int level) {
    loglevel = level;
}

void nakd_use_syslog(int use) {
    use_syslog = use;
}

void nakd_log_init() {
    openlog("nakd", 0, LOG_DAEMON);
}

void nakd_log_close() {
    closelog();
}

static const char *_ansi_color[] = {
    [L_CRIT] = "31",
    [L_WARNING] = "33",
    [L_NOTICE] = "35",
    [L_INFO] = "32",
    [L_DEBUG] = "36"
};

void _nakd_log(int priority, const char *format, const char *func,
                                const char *file, int line, ...) {
    va_list vl;
    char _fmt[256];

    if (priority > loglevel)
        return;

    long tid = syscall(SYS_gettid);
    va_start(vl, format);
    if (use_syslog) {
        snprintf(_fmt, sizeof(_fmt), "(%ld) [%s:%d, %s] %s", tid,
                                      file, line, func, format);

        vsyslog(syslog_loglevel[priority], _fmt, vl);
    } else {
        snprintf(_fmt, sizeof(_fmt), "\x1b[%sm[%s] (%ld) [%s:%d, %s] %s\x1b[37m\n",
                _ansi_color[priority], loglevel_string[priority], tid,
                                            file, line, func, format);
        vfprintf(stderr, _fmt, vl);
    }

    fflush(stdout);
    fflush(stderr);

    va_end(vl);
}

void _nakd_assert(int stmt, const char *stmt_str, const char *func,
                                                        int line) {
    if (stmt)
        return;

    nakd_terminate("nakd: assertion (%s) failed in %s:%d\n", stmt_str, func,
                                                                      line);
}
