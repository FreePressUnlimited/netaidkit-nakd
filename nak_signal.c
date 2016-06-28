#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <execinfo.h>
#include <unistd.h>
#include "nak_signal.h"
#include "log.h"
#include "thread.h"
#include "module.h"

#define CRASH_REPORT_PATH "/run/nakd/nakd_crashXXXXXX"

struct nakd_signal_handler {
    nakd_signal_handler impl;
    struct nakd_signal_handler *next;
} static *_handlers = NULL;

/* block by default in other threads */
static const int _sigmask[] = {
    SIGINT,
    SIGQUIT,
    SIGHUP,
    SIGTERM,
    SIGALRM,
    SIGCONT,
    SIGPIPE,
    0
};

/* handle these here */
static const int _sigwait[] = {
    SIGINT,
    SIGQUIT,
    SIGHUP,
    SIGTERM,
    SIGALRM,
    0
};

static int _shutdown;

static sigset_t _sigset(const int *signals) {
    sigset_t set;

    sigemptyset(&set);
    for (const int *sig = signals; *sig; sig++)
        sigaddset(&set, *sig);

    return set;
}

static void _set_default_sigmask(void) {
    sigset_t set = _sigset(_sigmask);

    int s = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (s)
        nakd_terminate("Couldn't set default sigmask");
}

static struct nakd_signal_handler *_alloc_handler() {
    struct nakd_signal_handler *ret =
        malloc(sizeof(struct nakd_signal_handler)); 
    nakd_assert(ret != NULL);

    ret->impl = NULL;
    ret->next = NULL;
    return ret;
}

void nakd_signal_add_handler(nakd_signal_handler impl) {
    struct nakd_signal_handler *last_handler;

    if (_handlers == NULL) {
        last_handler = _handlers = _alloc_handler();
    } else {
        for (last_handler = _handlers; last_handler->next != NULL;
                               last_handler = last_handler->next);

        last_handler = last_handler->next = _alloc_handler();
    }

    last_handler->impl = impl;
} 

static void _free_handlers() {
    struct nakd_signal_handler *handler = _handlers;
    while (handler != NULL) {
        struct nakd_signal_handler *next = handler->next;
        free(handler);
        handler = next;
    }
}

static void _sighandler(siginfo_t *siginfo) {
    int handled = 0;
    struct nakd_signal_handler *handler = _handlers;
    while (handler != NULL) {
        if (!handler->impl(siginfo))
            handled = 1;
        handler = handler->next;
    }
    
    if (!handled) {
        nakd_log(L_NOTICE, "%s caught, terminating.",
                     strsignal(siginfo->si_signo));
        _shutdown = 1;
    }
}

void nakd_sigwait_loop(void) {
    sigset_t set = _sigset(_sigwait);

    while (!_shutdown) {
        siginfo_t siginfo;
        if (sigwaitinfo(&set, &siginfo) != -1) {
            _sighandler(&siginfo);
        } else {
            if (errno != EINTR)
                nakd_terminate("sigwaitinfo(): %s", strerror(errno));
        }
    }
}

void nakd_sigsegv_handler(int signo) {
    void *bt[128];
    int size = backtrace(bt, sizeof bt);

    fputs("Segmentation fault\n", stderr);
    backtrace_symbols_fd(bt, size, fileno(stderr));

    int fd;
    if ((fd = mkstemp(CRASH_REPORT_PATH)) != -1) {
        backtrace_symbols_fd(bt, size, fd);
        close(fd);
    }

    exit(1);
}

static int _signal_init(void) {
    _set_default_sigmask();

    if (signal(SIGSEGV, nakd_sigsegv_handler) == SIG_ERR)
        nakd_terminate("Couldn't register SIGSEGV handler: %s", strerror(errno));

    return 0;
}

static int _signal_cleanup(void) {
    _free_handlers();
    return 0;
}

static struct nakd_module module_signal = {
    .name = "signal",
    .deps = NULL,
    .init = _signal_init,
    .cleanup = _signal_cleanup
};

NAKD_DECLARE_MODULE(module_signal);
