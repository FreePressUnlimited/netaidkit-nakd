#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <linux/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <getopt.h>
#include "log.h"
#include "nak_signal.h"
#include "module.h"
#include "shell.h"

#define PID_PATH "/run/nakd/nakd.pid"

/* Create file containing pid as a string and obtain a write lock for it. */
static int _write_pid(char *pid_path) {
    int fd;
    struct flock pid_lock;
    char pid_str[64];

    if ((fd = open(pid_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)) == -1)
        nakd_terminate("open()");

    pid_lock.l_type = F_WRLCK;
    pid_lock.l_whence = SEEK_SET;
    pid_lock.l_start = 0;
    pid_lock.l_len = 0;

    if (fcntl(fd, F_SETLK, &pid_lock) == -1)
        return -1;

    if (ftruncate(fd, 0) == -1)
        nakd_terminate("ftruncate()");

    snprintf(pid_str, sizeof pid_str, "%ld\n", (long) getpid());
    if (write(fd, pid_str, strlen(pid_str)) != strlen(pid_str))
        nakd_terminate("write()");

    return fd;
}

static void _config_stderr(void) {
    nakd_use_syslog(0);
}

static void _config_loglevel(void) {
    for (const char **ll = loglevel_string; *ll != NULL; ll++) {
        if (!strcasecmp(*ll, optarg)) {
            nakd_set_loglevel(ll - loglevel_string);
            return;
        }
    }
    nakd_terminate("No such loglevel: %s. See: syslog manpage", optarg);
}

static void _get_args(int argc, char *argv[]) {
    void (*config_impl[])(void) = {
        _config_stderr,
        _config_loglevel
    };

    static struct option long_options[] = {
        {"stderr", no_argument, NULL, 0},
        {"loglevel", required_argument, NULL, 1},
        {}
    };

    int index;
    int val;
    while ((val = getopt_long(argc, argv, "", long_options, &index)) != -1)
        config_impl[val]();
}

int main(int argc, char *argv[]) {
    int pid_fd;
    nakd_assert(!chdir(NAKD_SCRIPT_PATH));

    _get_args(argc, argv);    

    nakd_log_init();

    /* Check if nakd is already running. */
    if ((pid_fd = _write_pid(PID_PATH)) == -1)
        nakd_terminate("writePid()");

    /* TODO: CHECK IF CURRENT USER IS ROOT AND IF NAKD USER EXISTS */

    nakd_init_modules();
    nakd_sigwait_loop();
    nakd_cleanup_modules();

    nakd_log_close();
    return 0;
}
