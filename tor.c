#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <json-c/json.h>
#include "log.h"
#include "command.h"
#include "jsonrpc.h"
#include "tor.h"

#define SOCK_PATH "/run/tor/tor.sock"

static struct sockaddr_un _tor_sockaddr;
static int                _tor_sockfd;
static FILE               *_tor_fp;

static pthread_mutex_t _tor_cmd_mutex = PTHREAD_MUTEX_INITIALIZER;

static int _access_mgmt_socket(void) {
    return access(SOCK_PATH, W_OK);
}

static int _tor_authenticate(void) {
    char buf[256];

    if (fputs("AUTHENTICATE\n", _tor_fp) == EOF)
        nakd_log(L_WARNING, "Couldn't write to Tor socket.");

    fgets(buf, sizeof buf, _tor_fp);

    const char auth_successful[] = "250 OK";
    return strncmp(auth_successful, buf, sizeof auth_successful - 1);
}

static int _open_mgmt_socket(void) {
    /* check if there's already a valid descriptor open. */
    if (_tor_sockfd && fcntl(_tor_sockfd, F_GETFD) != -1) {
        return 0;
    }

    if (_access_mgmt_socket()) {
        nakd_log(L_WARNING, "Can't access Tor management socket at "
                                                         SOCK_PATH);
        return -1;
    }

    nakd_assert((_tor_sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) != -1);

    /* check if SOCK_PATH is strncpy safe. */
    nakd_assert(sizeof SOCK_PATH < UNIX_PATH_MAX);

    _tor_sockaddr.sun_family = AF_UNIX;
    strncpy(_tor_sockaddr.sun_path, SOCK_PATH, sizeof SOCK_PATH);       
    int len = sizeof(_tor_sockaddr.sun_family) + sizeof SOCK_PATH - 1;
    if (connect(_tor_sockfd, (struct sockaddr *)(&_tor_sockaddr), len) == -1) {
        nakd_log(L_WARNING, "Couldn't connect to Tor management socket "
                                   SOCK_PATH ". (%s)", strerror(errno));
        return -1;
    }
    nakd_assert((_tor_fp = fdopen(_tor_sockfd, "r+")) != NULL);
    setbuf(_tor_fp, NULL);

    nakd_log(L_DEBUG, "Connected to Tor management socket " SOCK_PATH);

    if (_tor_authenticate()) {
        nakd_log(L_WARNING, "Couldn't authenticate Tor control connection."); 
        return 1;
    }
    return 0;
}

static void _close_mgmt_socket(void) {
    nakd_log(L_DEBUG, "Closing Tor management socket " SOCK_PATH);

    if (_tor_fp) {
        fclose(_tor_fp);
        _tor_fp = 0;
    }

    if (_tor_sockfd) {
        close(_tor_sockfd);
        _tor_sockfd = 0;
    }
}

static json_object *_read_result(void) {
    char buf[1024];

    json_object *jresult = json_object_new_array();
    while (fgets(buf, sizeof buf, _tor_fp) != NULL) {
        nakd_assert(strlen(buf) >= 4);

        json_object *jline = json_object_new_string(buf);
        json_object_array_add(jresult, jline);

        /* See:
         * https://svn.torproject.org/svn/tor/tags/imported-from-cvs/trunk/doc/control-spec.txt
         *
         * 2.3
         */
        if (buf[3] == ' ')
            break;
    }
    return jresult;
}

static const char *_tor_acl[] = {
    "GETINFO version",
    "GETINFO circuit-status",
    "GETINFO stream-status",
    "GETINFO orconn-status",
    "GETINFO accounting/bytes",
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

    if (_open_mgmt_socket()) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
               "Internal error - couldn't open Tor control socket.");
        goto unlock;
    }

    if (fputs(command, _tor_fp) == EOF) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
            "Internal error - couldn't write to Tor control socket");
        goto unlock;
    }

    json_object *jresult = _read_result();
    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);

unlock:
    _close_mgmt_socket();
    pthread_mutex_unlock(&_tor_cmd_mutex);
response:
    return jresponse;
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
