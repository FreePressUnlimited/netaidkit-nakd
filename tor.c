#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <errno.h>
#include <json-c/json.h>
#include "log.h"
#include "command.h"
#include "jsonrpc.h"
#include "tor.h"
#include "module.h"
#include "timer.h"
#include "workqueue.h"
#include "io.h"

#define SOCK_PATH "/run/tor/tor.sock"

static struct sockaddr_un _tor_sockaddr;
static size_t _tor_sockaddr_len;

struct tor_cs {
    int fd;
    FILE *fp;
};

static struct tor_cs _tor_notification_s;

#define TOR_NOTIFICATION_RECONNECT_INTERVAL 5000 /* ms */
static struct nakd_timer *_notification_reconnect_timer;

static pthread_mutex_t _tor_cmd_mutex = PTHREAD_MUTEX_INITIALIZER;

static void _close_mgmt_socket(struct tor_cs *s);
static int _tor_init_notification_socket(void);

static int _access_mgmt_socket() {
    return access(SOCK_PATH, W_OK);
}

enum tor_response_code {
    CONNECTION_LOST = 0,

    TOR_OK = 250,
    TOR_UNNECESSARY = 251,

    TOR_RESOURCE_EXHAUSTED = 451,

    TOR_SYNTAX_ERROR = 500,

    TOR_UNRECOGNIZED_COMMAND = 510,
    TOR_UNIMPLEMENTED_COMMAND = 511,
    TOR_SYNTAX_ERROR_ARG = 512,
    TOR_UNRECOGNIZED_ARGUMENT = 513,
    TOR_AUTHENTICATION_REQUIRED = 514,
    TOR_BAD_AUTHENTICATION = 515,

    TOR_UNSPECIFIED_ERROR = 550,
    TOR_INTERNAL_ERROR = 551,
    TOR_UNRECOGNIZED_ENTITY = 552,
    TOR_INVALID_CONFIG_VALUE = 553,
    TOR_INVALID_DESCRIPTOR = 554,
    TOR_UNMANAGED_ENTITY = 555,

    TOR_ASYNCHRONOUS_NOTIFICATION = 650
};

struct tor_response {
    enum tor_response_code code;

    /* it's the last response line */
    int complete;
};

int _tor_parse_response(char *s, struct tor_response *result) {
    if (strlen(s) < 4)
        return 1;

    /* See:
     * https://gitweb.torproject.org/torspec.git/tree/control-spec.txt 
     *
     * 2.3.
     */
    result->complete = s[3] == ' ';
    s[3] = 0;
    result->code = (enum tor_response_code)(atoi(s));
    return 0;
}

static int _tor_positive_completion(enum tor_response_code rc) {
    return rc == TOR_OK || rc == TOR_UNNECESSARY; 
}

static void _tor_notification_process_single(const char * line) {
    nakd_log(L_DEBUG, "Got Tor notification: %s", line);
}

static int _tor_notification_process(FILE *fp) {
    char buf[1024];

    struct tor_response response;
    while (fgets(buf, sizeof buf, fp) != NULL) {
        if (_tor_parse_response(buf, &response))
            continue;

        if (response.code != TOR_ASYNCHRONOUS_NOTIFICATION)
            nakd_log(L_CRIT, "Expected code 650, got %d.", response.code);
        else
            _tor_notification_process_single(buf);

        if (response.complete)
            break;
    }

    if (!response.complete) {
        nakd_log(L_WARNING, "Incomplete notification.");  
        return 1;
    }
    return 0;
}

static int _tor_command(struct tor_cs *s, json_object **jresult,
                                         const char *fmt, ...) {
    va_list vl; 
    char buf[1024];
    char command[1024];

    va_start(vl, fmt);
    vsnprintf(command, sizeof command - 1, fmt, vl);
    strcat(command, "\n");
    va_end(vl);

    if (fputs(command, s->fp) == EOF) {
        nakd_log(L_WARNING, "Couldn't write to Tor control socket.");
        return 1;
    }

    if (jresult != NULL)
        *jresult = json_object_new_array();

    struct tor_response response;
    while (fgets(buf, sizeof buf, s->fp) != NULL) {
        if (jresult != NULL) {
            json_object *jline = json_object_new_string(buf);
            json_object_array_add(*jresult, jline);
        }

        if (_tor_parse_response(buf, &response))
            continue;
        if (response.complete)
            break;
    }

    if (!response.complete)
        nakd_log(L_WARNING, "Incomplete command response.");

    if (!_tor_positive_completion(response.code)) {
        nakd_log(L_WARNING, "Tor command failed, code: %d",
                                     (int)(response.code));
    }

    return !(_tor_positive_completion(response.code) && response.complete);

fail:
    if (jresult != NULL)
        json_object_put(*jresult);
    return 1;
}

static int _is_open(struct tor_cs *s) {
    return s->fd && fcntl(s->fd, F_GETFD) != -1;
}

static int _open_mgmt_socket(struct tor_cs *s) {
    if (_access_mgmt_socket()) {
        nakd_log(L_WARNING, "Can't access Tor management socket at "
                                                         SOCK_PATH);
        return -1;
    }

    nakd_assert((s->fd = socket(AF_UNIX, SOCK_CLOEXEC | SOCK_STREAM, 0)) != -1);

    if (connect(s->fd, (struct sockaddr *)(&_tor_sockaddr),
                                _tor_sockaddr_len) == -1) {
        nakd_log(L_WARNING, "Couldn't connect to Tor management socket "
                                   SOCK_PATH ". (%s)", strerror(errno));
        return -1;
    }
    nakd_assert((s->fp = fdopen(s->fd, "r+")) != NULL);
    setbuf(s->fp, NULL);

    nakd_log(L_DEBUG, "Connected to Tor management socket " SOCK_PATH);

    if (_tor_command(s, NULL, "AUTHENTICATE")) {
        nakd_log(L_WARNING, "Couldn't authenticate Tor control connection."); 
        return 1;
    }
    return 0;
}

static void _close_mgmt_socket(struct tor_cs *s) {
    nakd_log(L_DEBUG, "Closing Tor management socket " SOCK_PATH);

    if (s->fp) {
        fclose(s->fp);
        s->fp = 0;
    }
    /* closed in fclose */
    s->fd = 0;
}

static const char *_tor_acl[] = {
    "GETINFO version",
    "GETINFO circuit-status",
    "GETINFO stream-status",
    "GETINFO orconn-status",
    "GETINFO traffic/read",
    "GETINFO traffic/written",
    "GETINFO network-liveness",
    "GETINFO status/circuit-established",
    "GETINFO status/bootstrap-phase",
    NULL,
};

static int _test_acl(const char *command) {
    for (const char **acl = _tor_acl; *acl != NULL; acl++) {
        if (!strcmp(*acl, command))
            return 0;
    }
    return 1;
}

json_object *cmd_tor(json_object *jcmd, void *arg) {
    json_object *jresponse;
    json_object *jparams;

    if ((jparams = nakd_jsonrpc_params(jcmd)) == NULL ||
        json_object_get_type(jparams) != json_type_string) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_PARAMS,
                   "Invalid parameters - params should be a string");
        goto response;
    }

    const char *command = json_object_get_string(jparams);

    if (_test_acl(command)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
                             "Invalid request - blacklisted command");
        goto response;
    }

    pthread_mutex_lock(&_tor_cmd_mutex);

    struct tor_cs cmd_s;
    if (_open_mgmt_socket(&cmd_s)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
               "Internal error - couldn't open Tor control socket.");
        goto unlock;
    }

    json_object *jresult;
    if (_tor_command(&cmd_s, &jresult, command)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
            "Internal error - while processing Tor command");
        goto unlock;
    }

    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);

unlock:
    _close_mgmt_socket(&cmd_s);
    pthread_mutex_unlock(&_tor_cmd_mutex);
response:
    return jresponse;
}

static void _tor_init_sockaddr(void) {
    /* check if SOCK_PATH is strncpy safe. */
    nakd_assert(sizeof SOCK_PATH < UNIX_PATH_MAX);

    _tor_sockaddr.sun_family = AF_UNIX;
    strncpy(_tor_sockaddr.sun_path, SOCK_PATH, sizeof SOCK_PATH);       
    _tor_sockaddr_len = sizeof(_tor_sockaddr.sun_family) + sizeof SOCK_PATH
                                                                       - 1;
}

static int _tor_notification_subscribe(const char *ev_code) {
    return _tor_command(&_tor_notification_s, NULL, "SETEVENTS %s", ev_code);
}

static void _tor_notification_handler(struct epoll_event *ev) {
    if (_tor_notification_process(_tor_notification_s.fp)) {
        /* read failed */
        nakd_poll_remove(_tor_notification_s.fd);
        _close_mgmt_socket(&_tor_notification_s);
    }
}

static int _tor_init_notification_socket(void) {
    if (_open_mgmt_socket(&_tor_notification_s)) {
        nakd_log(L_WARNING, "Couldn't open Tor notification socket at "
                                                         SOCK_PATH);
        return 1;
    }
    if (_tor_notification_subscribe("STATUS_CLIENT")) {
        nakd_log(L_WARNING, "Couldn't subscribe to STATUS_CLIENT "
                                                 "notifications");
        return 1;
    }
    nakd_assert(!nakd_poll_add(_tor_notification_s.fd, EPOLLIN,
                                   _tor_notification_handler));
    return 0;
}

static void _tor_notification_reconnect_work(void *priv) {
    if (!_tor_init_notification_socket()) {
        nakd_log(L_INFO, "Initialized Tor notification socket at "
                                                       SOCK_PATH);
    } else {
        nakd_log(L_WARNING, "Couldn't initialize Tor notification socket.");
    }
}

static struct work_desc _tor_notification_reconnect_desc = {
    .impl = _tor_notification_reconnect_work,
    .name = "tor notification socket reconnect"
};

static void _tor_notification_reconnect_handler(siginfo_t *timer_info,
                                           struct nakd_timer *timer) {
    if (!_is_open(&_tor_notification_s)) {
        struct work *reconnect_entry =
            nakd_alloc_work(&_tor_notification_reconnect_desc);
        nakd_workqueue_add(nakd_wq, reconnect_entry);
    }
}

static int _tor_init(void) {
    _tor_init_sockaddr();
    _notification_reconnect_timer = nakd_timer_add(
               TOR_NOTIFICATION_RECONNECT_INTERVAL,
               _tor_notification_reconnect_handler,
                                             NULL);
    return 0;
}

static int _tor_cleanup(void) {
    nakd_timer_remove(_notification_reconnect_timer);
    _close_mgmt_socket(&_tor_notification_s);
    return 0;
}

static struct nakd_command tor = {
    .name = "tor",
    .desc = "Manage Tor daemon",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"tor\", \"params\":"
               "\"Command, as specified in TC v1, subject to ACLs\", "
                                                        "\"id\": 42}",
    .handler = cmd_tor,
    .access = ACCESS_USER
};
NAKD_DECLARE_COMMAND(tor);

static struct nakd_module module_tor = {
    .name = "tor",
    .deps = (const char *[]){"timer", "workqueue", NULL},
    .init = _tor_init,
    .cleanup = _tor_cleanup
};
NAKD_DECLARE_MODULE(module_tor);
