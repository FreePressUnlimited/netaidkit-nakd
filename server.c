#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <linux/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <json-c/json.h>
#include "server.h"
#include "request.h"
#include "log.h"
#include "misc.h"
#include "jsonrpc.h"
#include "module.h"
#include "workqueue.h"
#include "io.h"

#define MAX_CONNECTIONS     64
#define CONNECTION_TIMEOUT 2 /* seconds */
#define SOCK_DIR       "/run/nakd"
#define SOCK_PATH      SOCK_DIR "/nakd.sock"

struct connection {
    int sockfd;
    struct sockaddr_un sockaddr;

    int nb_read;
    json_tokener *jtok;

    int refcount;
    pthread_mutex_t refcount_mutex;

    pthread_mutex_t write_mutex;
};

static struct sockaddr_un _nakd_sockaddr;
static int                _nakd_sockfd;

static pthread_mutex_t _shutdown_mutex;

static sem_t _connections_sem;
static int _server_shutdown;

static void _connection_get(struct connection *c) {
    pthread_mutex_lock(&c->refcount_mutex);
    c->refcount++;
    pthread_mutex_unlock(&c->refcount_mutex);
}

static void _connection_put(struct connection *c) {
    pthread_mutex_lock(&c->refcount_mutex);
    int s = --c->refcount;
    pthread_mutex_unlock(&c->refcount_mutex);
    if (s)
        return;

    pthread_mutex_destroy(&c->refcount_mutex);
    pthread_mutex_destroy(&c->write_mutex);

    nakd_poll_remove(c->sockfd);
    close(c->sockfd);
    json_tokener_free(c->jtok);
    free(c);

    sem_post(&_connections_sem);
}

static void _create_unix_socket(void) {
    struct stat sock_path_st;

    /* Create the nakd server socket. */
    nakd_assert((_nakd_sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) != -1);

    /* Check if SOCK_PATH is strncpy safe. */
    nakd_assert(sizeof SOCK_PATH < UNIX_PATH_MAX);

    /* Set domain socket path to SOCK_PATH. */
    strncpy(_nakd_sockaddr.sun_path, SOCK_PATH, sizeof SOCK_PATH);
    _nakd_sockaddr.sun_family = AF_UNIX;

    /* Remove domain socket file if it exists. */
    if (stat(SOCK_PATH, &sock_path_st) == 0)
        if (unlink(SOCK_PATH) == -1)
            nakd_terminate("Couldn't remove socket at %s",
                                 _nakd_sockaddr.sun_path);

    nakd_log(L_INFO, "Using socket at %s", _nakd_sockaddr.sun_path);

    /* Bind nakd server socket to the domain socket. */
    nakd_assert(bind(_nakd_sockfd, (struct sockaddr *) &_nakd_sockaddr,
                                     sizeof(struct sockaddr_un)) >= 0);

    /* Set domain socket world writable, permissions via credentials passing */
    nakd_assert(chmod(SOCK_PATH, 0777) != -1);
}

int _check_epollerr(struct epoll_event *ev) {
    if (ev->events & EPOLLERR) {
        int       error = 0;
        socklen_t errlen = sizeof(error);
        if (!getsockopt(ev->data.fd, SOL_SOCKET, SO_ERROR, (void *)&error,
                                                               &errlen)) {
            nakd_log(L_CRIT, "EPOLLERR: %s", strerror(error));
        } else {
            nakd_log(L_CRIT, "getsockopt() returned \"%s\"", strerror(errno));
        }
        return 1;
    }
    return 0;
}

static void _send_response(struct connection *c, json_object *jresponse) {
    const char *jrstr = json_object_to_json_string_ext(jresponse,
                                        JSON_C_TO_STRING_PRETTY);

    int nb_resp;
    const char *jrstrp = jrstr;
    pthread_mutex_lock(&c->write_mutex);
    while (nb_resp = strlen(jrstrp)) {
        int nb_sent = sendto(c->sockfd, jrstrp, nb_resp, 0,
                         (struct sockaddr *)(&c->sockaddr),
                                       sizeof c->sockaddr);
        if (nb_sent == -1) {
            if (errno == EINTR)
                continue;

            nakd_log(L_NOTICE, "Couldn't send response: %s ", strerror(errno));
            goto unlock;
        }
        jrstrp += nb_sent;
    }
    nakd_log(L_DEBUG, "Response sent: %s", jrstr);

unlock:
    pthread_mutex_unlock(&c->write_mutex);
    json_object_put(jresponse);
}

struct message_handler_data {
    struct connection *c;
    json_object *jmsg;
};

static void _handle_message(void *priv) {
    struct message_handler_data *d = priv;

    /* jresponse will be NULL while handling notifications. */
    json_object *jresponse = nakd_handle_message(d->jmsg);
    if (jresponse != NULL)
        _send_response(d->c, jresponse);

    _connection_put(d->c);
    free(priv);
}

static struct work_desc _handle_message_desc = {
    .impl = _handle_message,
    .name = "jsonrpc handler"
};

static void _connection_handler(struct epoll_event *ev, void *priv) {
    /* level-triggered epoll, one calling thread */

    struct connection *c = priv;
    char message_buf[4096];

    pthread_mutex_lock(&c->refcount_mutex);

    if (_check_epollerr(ev) || ev->events & EPOLLHUP) {
        _connection_put(c);
        return;
    }
    nakd_assert(ev->events & EPOLLIN);

    if (c->nb_read > NAKD_JSONRPC_RCVMSGLEN_LIMIT) {
        nakd_log(L_NOTICE, "JSONRPC message longer than %d bytes, "
                   "disconnecting.", NAKD_JSONRPC_RCVMSGLEN_LIMIT);
        _connection_put(c);
        return;
    }

    socklen_t c_len = sizeof c->sockaddr;
    int nb_read = recvfrom(c->sockfd, message_buf, sizeof message_buf, 0,
                             (struct sockaddr *)(&c->sockaddr), &c_len);
    if (nb_read == -1) {
        if (errno == EINTR || errno == EAGAIN)
            return;

        nakd_log(L_NOTICE, "Closing connection (%s)",
                                    strerror(errno));
        _connection_put(c);
        return;
    } else if (!nb_read) {
        nakd_log(L_DEBUG, "Closing connection - client hung up.");
        _connection_put(c);
        return;
    }

    c->nb_read += nb_read;

     /* partial JSON strings are stored in tokener context */
    json_object *jmsg = json_tokener_parse_ex(c->jtok, message_buf, nb_read);
    enum json_tokener_error jerr = json_tokener_get_error(c->jtok);

    if (jerr == json_tokener_continue)
        return;

    json_object *jresponse;
    if (jerr == json_tokener_success) {
        /* doesn't allocate memory */
        const char *jmsg_string = json_object_to_json_string_ext(jmsg,
                                             JSON_C_TO_STRING_PRETTY);
        nakd_log(L_DEBUG, "Got a message: %s", jmsg_string);

        struct work *jsonrpc_work = nakd_alloc_work(&_handle_message_desc);

        struct message_handler_data *d = malloc(sizeof(struct message_handler_data));
        d->c = c;
        d->jmsg = jmsg, json_object_get(jmsg);
        jsonrpc_work->desc.priv = d;

        _connection_get(c);
        nakd_workqueue_add(nakd_wq, jsonrpc_work);
    } else {
        nakd_log(L_DEBUG, "Couldn't parse JSONRPC message: %s",
                                json_tokener_error_desc(jerr));
        json_tokener_reset(c->jtok);

        jresponse = nakd_jsonrpc_response_error(NULL, PARSE_ERROR, NULL);
        _send_response(c, jresponse);        
    }
}

void _init_connection(int sfd, struct sockaddr_un sa) {
    struct connection *c;
    nakd_assert((c = calloc(1, sizeof(struct connection))) != NULL);

    c->sockfd = sfd;
    c->sockaddr = sa;

    /* reader reference */
    c->refcount = 1;

    pthread_mutex_init(&c->refcount_mutex, NULL);
    pthread_mutex_init(&c->write_mutex, NULL);

    nakd_assert((c->jtok = json_tokener_new()) != NULL);
    nakd_assert(!nakd_poll_add(sfd, EPOLLIN, _connection_handler, c));
}

static void _accept_handler(struct epoll_event *ev, void *priv) {
    if (_check_epollerr(ev))
        return;

    struct timespec ts;
    nakd_assert(!clock_gettime(CLOCK_MONOTONIC, &ts));
    ts.tv_sec += CONNECTION_TIMEOUT;
    if (sem_timedwait(&_connections_sem, &ts)) {
        if (errno == ETIMEDOUT) {
            nakd_log(L_INFO, "Out of connection slots.");
            return;
        }
        nakd_log(L_CRIT, "sem_timedwait(): %s", strerror(errno));
        return;
    }

    struct sockaddr_un c_sockaddr;
    socklen_t len = sizeof c_sockaddr;
    int c_sock = accept4(_nakd_sockfd, (struct sockaddr *)(&c_sockaddr), &len,
                                                                SOCK_CLOEXEC);

    if (c_sock == -1) {
        sem_post(&_connections_sem);
        if (errno == EINTR)
            return;
        if (errno == EBADF) {
            nakd_log(L_DEBUG, "accept4() returned \"%s\", shutting down...",
                                                           strerror(errno));
            nakd_poll_remove(_nakd_sockfd);
            return;
        }

        nakd_log(L_CRIT, "Couldn't accept a connection: %s", strerror(errno));
        return;
    }

    int flags;
    nakd_assert((flags = fcntl(c_sock, F_GETFL, 0)) != -1);
    nakd_assert(fcntl(c_sock, F_SETFL, flags | O_NONBLOCK) != -1);

    nakd_log(L_DEBUG, "Connection accepted, %d connection(s) currently "
                                  "active.", nakd_active_connections());
    _init_connection(c_sock, c_sockaddr);
}

static void _listen(void) {
    /* Listen on local domain socket. */
    nakd_assert(listen(_nakd_sockfd, MAX_CONNECTIONS) != -1);
    nakd_assert(!nakd_poll_add(_nakd_sockfd, EPOLLIN, _accept_handler, NULL));
}

int nakd_active_connections(void) {
    int value;
    sem_getvalue(&_connections_sem, &value);
    return MAX_CONNECTIONS - value;
}

static void _create_sock_dir(void) {
    if (access(SOCK_DIR, X_OK))
        nakd_assert(!mkdir(SOCK_DIR, 770));
}

static int _server_init(void) {
    sem_init(&_connections_sem, 0, MAX_CONNECTIONS);

    _create_sock_dir();
    _create_unix_socket();
    _listen();
    return 0;
}

static int _server_cleanup(void) {
    close(_nakd_sockfd);
    nakd_assert(!unlink(SOCK_PATH));

    sem_destroy(&_connections_sem);
    return 0;
}

static struct nakd_module module_server = {
    .name = "server",
    .deps = (const char *[]){ "workqueue", "io", NULL },
    .init = _server_init,
    .cleanup = _server_cleanup
};
NAKD_DECLARE_MODULE(module_server);
