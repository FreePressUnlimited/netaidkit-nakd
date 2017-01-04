#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <linux/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <json-c/json.h>
#include "openvpn.h"
#include "log.h"
#include "jsonrpc.h"
#include "misc.h"
#include "command.h"
#include "stage.h"
#include "nak_mutex.h"
#include "module.h"
#include "timer.h"
#include "workqueue.h"

#define SOCK_PATH "/run/nakd/openvpn.sock"
#define CONFIG_PATH "/nak/ovpn/current.ovpn"
#define AUTH_PATH "/nak/ovpn/auth.txt"
#define UP_SCRIPT_PATH "/usr/share/nakd/scripts/util/openvpn_up.sh"
#define OPENVPN_CWD "/usr/share/nakd/scripts"
#define SCRIPT_SECURITY "2"

#define STATE_UPDATE_INTERVAL 1000 /* ms */

static char * const _argv[] = {
    "/usr/sbin/openvpn",
    "--log-append", "/var/log/openvpn.log",
    "--daemon",
    "--management", SOCK_PATH, "unix",
    "--config", CONFIG_PATH,
    "--script-security", SCRIPT_SECURITY,
    "--up", UP_SCRIPT_PATH,
    "--persist-tun",
    "--persist-key",
    "--persist-remote-ip",
    NULL
};

static char * const _argv_auth[] = {
    "/usr/sbin/openvpn",
    "--log-append", "/var/log/openvpn.log",
    "--daemon",
    "--management", SOCK_PATH, "unix",
    "--config", CONFIG_PATH,
    "--auth-user-pass", AUTH_PATH,
    "--script-security", SCRIPT_SECURITY,
    "--up", UP_SCRIPT_PATH,
    "--persist-tun",
    "--persist-key",
    "--persist-remote-ip",
    NULL
};

static struct sockaddr_un _openvpn_sockaddr;
static int                _openvpn_sockfd = -1;
static int                _openvpn_pid;

static pthread_mutex_t _ovpn_command_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t _ovpn_daemon_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t _ovpn_rpc_mutex = PTHREAD_MUTEX_INITIALIZER;

static json_object *_ovpn_state = NULL;
static pthread_mutex_t _ovpn_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct nakd_timer *_ovpn_watchdog_timer;

static int _kill_openvpn(int signal) {
    nakd_log(L_INFO, "Sending %s to OpenVPN, PID %d", strsignal(signal),
                                                          _openvpn_pid);

    /* Kill whole process group */
    int result = kill(-_openvpn_pid, signal);
    if (result == -1) {
        nakd_log(L_WARNING, "Couldn't send %s to OpenVPN process group, "
                          "pgid %d: %s", strsignal(signal), _openvpn_pid,
                                                        strerror(errno));
        return -1;
    }
    return 0;
}

static int _access_config_file(void) {
    return access(CONFIG_PATH, R_OK);
}

static int _access_mgmt_socket(void) {
    return access(SOCK_PATH, R_OK);
}

static int _access_auth_file(void) {
    return access(AUTH_PATH, R_OK);
}

static char *_getline(void) {
    const size_t line_max = 1024;
    char *buf = calloc(line_max, 1);
    nakd_assert(buf != NULL);

    errno = 0;
    for (char *bptr = buf; bptr < buf + line_max - 1;) {
        if (read(_openvpn_sockfd, bptr, 1) == -1) {
            if (errno == EAGAIN) {
                continue;
            } else {
                nakd_log(L_WARNING, "Error while reading from OpenVPN management "
                                                   "socket: %s", strerror(errno));
                goto err;
            }
        }

        if (*bptr == '\n') {
            *(bptr + 1) = 0;
            goto response;
        }
        bptr++;
    }

err:
    free(buf), buf = NULL;
response:
    if (buf != NULL)
        nakd_log(L_DEBUG, "<<%s", buf);
    return buf;
}

static int _open_mgmt_socket(void) {
    /* Check if there's already a valid descriptor open. */
    if (_openvpn_sockfd != -1 && fcntl(_openvpn_sockfd, F_GETFD) != -1)
        return 0;

    if (_access_mgmt_socket()) {
        nakd_log(L_WARNING, "Can't access OpenVPN management socket at "
                                                             SOCK_PATH);
        return -1;
    }

    nakd_assert((_openvpn_sockfd = socket(AF_UNIX, SOCK_CLOEXEC | SOCK_STREAM,
                                                                   0)) != -1);

    /* Check if SOCK_PATH is strncpy safe. */
    nakd_assert(sizeof SOCK_PATH < UNIX_PATH_MAX);

    _openvpn_sockaddr.sun_family = AF_UNIX;
    strncpy(_openvpn_sockaddr.sun_path, SOCK_PATH, sizeof SOCK_PATH);
    int len = sizeof(_openvpn_sockaddr.sun_family) + sizeof SOCK_PATH - 1;
    set_socket_timeout(_openvpn_sockfd, 1);
    if (connect(_openvpn_sockfd, (struct sockaddr *)(&_openvpn_sockaddr), len)
                                                                      == -1) {
        nakd_log(L_WARNING, "Couldn't connect to OpenVPN management socket "
                                       SOCK_PATH ". (%s)", strerror(errno));
        return -1;
    }

    nakd_log(L_DEBUG, "Connected to OpenVPN management socket %s", SOCK_PATH);

    char *info = _getline();
    if (info == NULL) {
        nakd_log(L_WARNING, "Couldn't get OpenVPN challenge line");
        return -1;
    } else {
        nakd_log(L_DEBUG, "OpenVPN challenge line: %s", info);
        free(info);
    }

    return 0;
}

static void _flush(void) {
    char buf[128];

    errno = 0;
    do {
        recv(_openvpn_sockfd, buf, sizeof buf, MSG_DONTWAIT);
    } while(errno != EWOULDBLOCK);
}

static void _close_mgmt_socket(void) {
    nakd_log(L_DEBUG, "Closing OpenVPN management socket %s", SOCK_PATH);
    close(_openvpn_sockfd);
    _openvpn_sockfd = -1;
}

static int _writeline(const char *line) { 
    nakd_log(L_DEBUG, ">>%s", line);

    const int len = strlen(line);                                                 
    for (int written = 0, d = 0;                                                  
         written != len;                                                          
         d = write(_openvpn_sockfd, line + d, len - written)) {                   
        if (d == -1) {                                                            
            nakd_log(L_WARNING, "Couldn't write to OpenVPN management socket: %s",
                                                                 strerror(errno));
            return 1;                                                             
        }                                                                         
        written += d;                                                             
    }                                                                             
    write(_openvpn_sockfd, "\n", 1);
    return 0;                                                                     
}                                                                                 

static char *_call_command(const char *command) {
    char *resp = NULL;
    nakd_log(L_DEBUG, "Calling OpenVPN management command: %s", command);

    nakd_mutex_lock(&_ovpn_command_mutex);

    if (!_openvpn_pid || _open_mgmt_socket())
        goto response;
    _flush();
    if (_writeline(command))
        goto csocket;

    resp = _getline();

csocket:
    _close_mgmt_socket();
response:
    nakd_mutex_unlock(&_ovpn_command_mutex);
    return resp;
}

static int _mgmt_signal(const char *signal) {
    char buf[256];
    snprintf(buf, sizeof buf, "signal %s", signal);

    char *result = _call_command(buf);
    if (result != NULL) {
        free(result);
        return 0;
    }
    return 1;
}

static void _free_multiline(char ***lines) {
    /* a NULL-terminated array */
    for (char **line = *lines; *line != NULL; line++)
        free(*line);
    free(*lines);
    *lines = NULL;
}

static char **_call_command_multiline(const char *command) {
    char **lines = NULL;
    nakd_log(L_DEBUG, "Calling OpenVPN management command: %s", command);

    nakd_mutex_lock(&_ovpn_command_mutex);

    if (!_openvpn_pid || _open_mgmt_socket())
        goto response;
    _flush();
    if (_writeline(command))
        goto csocket;

    /* read response */
    const size_t lines_max = 128;
    lines = malloc(sizeof(*lines) * lines_max);
    nakd_assert(lines != NULL);
    for (char **line = lines; line < lines + lines_max; line++)
        *line = NULL;

    for (char **line = lines; line < lines + lines_max - 1; line++) {
        char *_line = _getline();
        if (_line == NULL)
            goto err;

        if (!strncmp(_line, "END", sizeof("END") - 1)) {
            free(_line);
            goto csocket;
        }

        *line = _line;        
    }

err:
     _free_multiline(&lines);
csocket:
    _close_mgmt_socket();
response:
    nakd_mutex_unlock(&_ovpn_command_mutex);
    return lines;
}

static int __start_openvpn(void) {
    if (access(OPENVPN_CWD, R_OK)) {
        nakd_log(L_CRIT, "Can't access OpenVPN working directory: " OPENVPN_CWD);
        return -1;
    }

    if (_access_config_file()) {
        nakd_log(L_CRIT, "Can't access OpenVPN config file at " CONFIG_PATH);
        return -1;
    }

    char * const *argv;
    if (_access_auth_file()) {
        nakd_log(L_INFO, "No OpenVPN auth file found.");
        argv = _argv;
    } else {
        nakd_log(L_INFO, "Using OpenVPN auth file at " AUTH_PATH);
        argv = _argv_auth;
    }

    int pid = fork();
    nakd_assert(pid >= 0);

    log_execve(L_DEBUG, "Starting OpenVPN: %s", (const char * const *)(argv));
    if (pid == 0) /* child */ {
        setsid();
        chdir(OPENVPN_CWD);
        execve(argv[0], argv, NULL);
        nakd_log(L_CRIT, "Couldn't start OpenVPN: %s", strerror(errno));
        return -1;
    } else if (pid == -1) {
        nakd_log(L_CRIT, "fork() failed: %s", strerror(errno));
        return -1;
    } 

    /* parent */
    _openvpn_pid = pid;
    nakd_log(L_INFO, "Started OpenVPN, PID %d", pid);
    return 0;
}

int nakd_start_openvpn(void) {
    nakd_mutex_lock(&_ovpn_daemon_mutex);
    int ret = __start_openvpn();
    nakd_mutex_unlock(&_ovpn_daemon_mutex);
    return ret;
}

static int __stop_openvpn(void) {
    if (!_openvpn_pid) {
        nakd_log(L_INFO, "Attempted to stop OpenVPN, but it isn't running.");
        return 0;
    }

    /* Sending a SIGTERM to _openvpn_pid wouldn't deliver it to its child
     * processes, hence delivery via the management console.
     */
    /* If OpenVPN is still running: */
    if (_mgmt_signal("SIGTERM")) {
        /* In case the signal couldn't have been sent this way: */
        _kill_openvpn(SIGTERM);
    }

    nakd_log(L_INFO, "Waiting for OpenVPN to terminate, PID %d: ",
                                                    _openvpn_pid);
    waitpid(_openvpn_pid, NULL, WUNTRACED);
    _openvpn_pid = 0;

    return 0;
}

int nakd_stop_openvpn(void) {
    nakd_mutex_lock(&_ovpn_daemon_mutex);
    int ret = __stop_openvpn();
    nakd_mutex_unlock(&_ovpn_daemon_mutex);
    return ret;
} 

static int __restart_openvpn(void) {
    /*
     *  OpenVPN drops privileges after init - restarting via _mgmt_signal()
     *  won't cut it.
     */

    return __stop_openvpn() || __start_openvpn();

    /* Cause OpenVPN to close all TUN/TAP and network connections, restart, 
     * re-read the configuration file (if any), and reopen TUN/TAP and network
     * connections. -- OpeVPN manpage
     *
     *  return _mgmt_signal("SIGHUP");
     */
}

int nakd_restart_openvpn(void) {
    nakd_mutex_lock(&_ovpn_daemon_mutex);
    int ret = __restart_openvpn();
    nakd_mutex_unlock(&_ovpn_daemon_mutex);
    return ret;
}

static json_object *_parse_state_line(const char *resp) {
    char *respcp = strdup(resp);
    char *pos = respcp;
    const char *delim = ",";

    char *time = strsep(&pos, delim);
    char *state = strsep(&pos, delim);

    if (time == NULL || state == NULL) {
        nakd_log(L_WARNING, "Couldn't parse OpenVPN state: %s", resp);
        return NULL;
    }

    nakd_log(L_DEBUG, "Parsed OpenVPN state line: time=%s, state=%s", time,
                                                                    state);

    json_object *jresult = json_object_new_object();
    nakd_assert(jresult != NULL);
    
    json_object *jtime = json_object_new_string(time);
    nakd_assert(jtime != NULL);

    json_object *jstate = json_object_new_string(state);
    nakd_assert(jstate != NULL);

    json_object_object_add(jresult, "timestamp", jtime);
    json_object_object_add(jresult, "state", jstate);

    free(respcp);
    return jresult;
}

json_object *_call_state(json_object *jcmd) {
    json_object *jresponse;

    nakd_mutex_lock(&_ovpn_state_mutex);
    if (_ovpn_state == NULL) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                     "Internal error - OpenVPN state not available");
        goto unlock;
    }

    json_object_get(_ovpn_state);
    jresponse = nakd_jsonrpc_response_success(jcmd, _ovpn_state); 

unlock:
    nakd_mutex_unlock(&_ovpn_state_mutex);
response:
    return jresponse;
}

json_object *_call_start(json_object *jcmd) {
    json_object *jresponse;

    if (_access_config_file()) {
         jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                "Internal error - can't access OpenVPN configuration "
                                                   "at " CONFIG_PATH);
         goto response;
    }

    if (nakd_start_openvpn()) {
         jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                           "Internal error - couldn't start OpenVPN");
         goto response;
    }

    json_object *jresult = json_object_new_string("OK");
    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);

response:
    return jresponse;
}

json_object *_call_stop(json_object *jcmd) {
    json_object *jresponse;

    if (nakd_stop_openvpn()) {
         jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                              "Internal error - OpenVPN not running");
         goto response;
    }

    json_object *jresult = json_object_new_string("OK");
    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);

response:
    return jresponse;
}

json_object *_call_restart(json_object *jcmd) {
    json_object *jresponse;

    if (nakd_restart_openvpn()) {
         jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                              "Internal error - OpenVPN not running");
         goto response;
    }

    json_object *jresult = json_object_new_string("OK");
    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);

response:
    return jresponse;
}

json_object *cmd_openvpn(json_object *jcmd, void *priv) {
    json_object *jresponse;
    json_object *jparams;

    /*
     *  TODO daemon plumbing
     *  TODO 1. rename stage -> mode throughout the codebase
     *  TODO 2. export modes from modules
     *  TODO 3. import modules from .so plugins
     *  TODO 4. acquire stage_status lock in RPC interface for every cmd_*()
     *  TODO 5. replace workqueue.c impl with a priority queue
     */
    const struct stage *current_stage = nakd_stage_current();
    /*
     *  Don't serve RPC calls if we're turning VPN mode off.
     */
    const struct stage *requested_stage = nakd_stage_requested();
    if (current_stage != NULL && strcmp(current_stage->name, "vpn") ||
                                            requested_stage != NULL) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
                 "Invalid request - only available in \"vpn\" stage");
        goto response;
    }

    if ((jresponse = nakd_command_timedlock(jcmd, &_ovpn_rpc_mutex)) != NULL)
        goto response;

    json_object *(*impl)(json_object *) = priv;
    jresponse = impl(jcmd);

unlock:
    pthread_mutex_unlock(&_ovpn_rpc_mutex);
response:
    return jresponse;
}

static void _ovpn_watchdog_async(void *priv) {
    nakd_mutex_lock(&_ovpn_daemon_mutex);
    if (!_openvpn_pid)
        goto unlock;

    /* 
     * If OpenVPN is not running, but it should be, restart it.
     */
    if (_openvpn_pid) {
        nakd_assert(!kill(_openvpn_pid, 0));
        if (waitpid(_openvpn_pid, NULL, WUNTRACED | WNOHANG) == _openvpn_pid) {
            nakd_log(L_INFO, "Restarting OpenVPN...");
            __restart_openvpn();
            goto unlock;
        }
    }

    char **lines = _call_command_multiline("state");
    if (lines == NULL) {
        nakd_log(L_WARNING, "Couldn't get current state from OpenVPN daemon.");
        goto unlock;
    }

    json_object *jstate = json_object_new_array();
    nakd_assert(jstate != NULL);  

    /* a NULL-terminated array */
    for (char **line = lines; *line != NULL; line++) {
        json_object *jline = _parse_state_line(*line);
        if (jline == NULL) {
            /*
             *  jline shouldn't be NULL, _parse_state_line() logged error
             */
            json_object_put(jstate), jstate = NULL;
            break;
        }
        json_object_array_add(jstate, jline);
    }

    nakd_mutex_lock(&_ovpn_state_mutex);
    if (_ovpn_state != NULL)
        json_object_put(_ovpn_state);
    _ovpn_state = jstate;
    nakd_mutex_unlock(&_ovpn_state_mutex);

    _free_multiline(&lines);

unlock:
    nakd_mutex_unlock(&_ovpn_daemon_mutex);
}

static struct work_desc _ovpn_watchdog_desc = {
    .impl = _ovpn_watchdog_async,
    .name = "openvpn watchdog",
    .timeout = 10
};

/* Commands in OpenVPN management console have different semantics, hence
 * the need for specialized handlers.
 */
static void _ovpn_watchdog_cb(siginfo_t *timer_info,
                             struct nakd_timer *timer) {
    if (!nakd_work_pending(nakd_wq, _ovpn_watchdog_desc.name)) {
        struct work *work = nakd_alloc_work(&_ovpn_watchdog_desc);
        nakd_workqueue_add(nakd_wq, work);
    } else {
        nakd_log(L_DEBUG, "There's already an openvpn update job in the"
                                               " workqueue. Skipping.");
    }
}

static int _openvpn_init(void) {
    _ovpn_watchdog_timer = nakd_timer_add(STATE_UPDATE_INTERVAL,
                  _ovpn_watchdog_cb, NULL, "openvpn_watchdogr");
    return 0;
}

static int _openvpn_cleanup(void) {
    if (_openvpn_pid)
        waitpid(_openvpn_pid, NULL, WUNTRACED);
    return 0;
}

static struct nakd_module module_openvpn = {
    .name = "openvpn",
    .deps = (const char *[]){ "command", "workqueue", "timer", NULL },
    .init = _openvpn_init,
    .cleanup = _openvpn_cleanup
};
NAKD_DECLARE_MODULE(module_openvpn);

static struct nakd_command openvpn_state = {
    .name = "openvpn_state",
    .desc = "Yields OpenVPN daemon status.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"openvpn_state\","
                                                     " \"id\": 42}",
    .handler = cmd_openvpn,
    .priv = _call_state,
    .access = ACCESS_ALL,
    .module = &module_openvpn
};
NAKD_DECLARE_COMMAND(openvpn_state);

static struct nakd_command openvpn_start = {
    .name = "openvpn_start",
    .desc = "Yields OpenVPN daemon status.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"openvpn_start\","
                                                     " \"id\": 42}",
    .handler = cmd_openvpn,
    .priv = _call_start,
    .access = ACCESS_ADMIN,
    .module = &module_openvpn
};
NAKD_DECLARE_COMMAND(openvpn_start);

static struct nakd_command openvpn_stop = {
    .name = "openvpn_stop",
    .desc = "Yields OpenVPN daemon status.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"openvpn_stop\","
                                                    " \"id\": 42}",
    .handler = cmd_openvpn,
    .priv = _call_stop,
    .access = ACCESS_ADMIN,
    .module = &module_openvpn
};
NAKD_DECLARE_COMMAND(openvpn_stop);

static struct nakd_command openvpn_restart = {
    .name = "openvpn_restart",
    .desc = "Yields OpenVPN daemon status.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"openvpn_restart\","
                                                       " \"id\": 42}",
    .handler = cmd_openvpn,
    .priv = _call_restart,
    .access = ACCESS_ADMIN,
    .module = &module_openvpn
};
NAKD_DECLARE_COMMAND(openvpn_restart);
