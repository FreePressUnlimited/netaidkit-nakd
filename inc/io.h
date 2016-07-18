#ifndef NAKD_IO_H
#define NAKD_IO_H
#include <sys/epoll.h>

typedef void (*nakd_poll_handler)(struct epoll_event *ev, void *priv);

int nakd_poll_add(int fd, int events, nakd_poll_handler handler, void *priv);
int nakd_poll_remove(int fd);

#endif
