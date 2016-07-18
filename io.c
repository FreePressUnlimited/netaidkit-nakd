#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "io.h"
#include "module.h"
#include "thread.h"
#include "log.h"
#include "workqueue.h"

#define NAKD_MAXEVENTS 64
static struct epoll_event _events[NAKD_MAXEVENTS];

static int _efd;
static struct nakd_thread *_poll_thread;
static int _shutdown;

struct handler_data {
    nakd_poll_handler cb;
    void *priv;
};

static void _poll_handle(void *priv) {
    struct epoll_event *ev = priv;
    struct handler_data *hnd = ev->data.ptr;
    hnd->cb(ev, hnd->priv);
    free(priv);
}

static struct work_desc _poll_handle_desc = {
    .impl = _poll_handle,
    .name = "epoll handler"
};

static void _poll_loop(struct nakd_thread *thread) {
    while (!_shutdown) {
        int n = epoll_wait(_efd, _events, NAKD_MAXEVENTS, 1000);  
        if (n <= 0)
            continue;

        for (int i = 0; i < n; i++) {
            struct work *io_work = nakd_alloc_work(&_poll_handle_desc);

            struct epoll_event *evcopy = malloc(sizeof(struct epoll_event));
            *evcopy = _events[i];
            io_work->desc.priv = evcopy;

            nakd_workqueue_add(nakd_wq, io_work);
        }
    }
}

static void _poll_shutdown(struct nakd_thread *thread) {
    _shutdown = 1;
}

static int _io_init(void) {
    nakd_assert(!nakd_thread_create_joinable(_poll_loop,
         _poll_shutdown, NULL, (void *)(_poll_thread)));
    nakd_assert((_efd = epoll_create1(0)) != -1);
    return 0;
}

static int _io_cleanup(void) {
    close(_efd);
    return 0;
}

int nakd_poll_add(int fd, int events, nakd_poll_handler handler, void *priv) {
    struct epoll_event ev;

    ev.data.fd = fd;
    ev.events = events;

    struct handler_data *data = malloc(sizeof(struct handler_data));
    data->cb = handler;
    data->priv = priv;
    ev.data.ptr = data;

    return epoll_ctl(_efd, EPOLL_CTL_ADD, fd, &ev);
}

int nakd_poll_remove(int fd) {
    /* TODO free handler_data */
    return epoll_ctl(_efd, EPOLL_CTL_DEL, fd, NULL);
}

static struct nakd_module module_io = {
    .name = "io",
    .deps = (const char *[]){"thread", "workqueue", NULL},
    .init = _io_init,
    .cleanup = _io_cleanup
};
NAKD_DECLARE_MODULE(module_io);
