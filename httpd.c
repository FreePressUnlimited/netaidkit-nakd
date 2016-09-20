#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <json-c/json.h>
#include <uuid/uuid.h>
#include "httpd.h"
#include "module.h"
#include "config.h"
#include "log.h"
#include "workqueue.h"
#include "jsonrpc.h"
#include "request.h"
#include "thread.h"
#include "json.h"
#include "auth.h"

#define PORT 8000

#define SESSION_DIR "/tmp/nakd_sessions"
#define NAK_SESSION_COOKIE "nak_sessid" 

struct http_request {
    struct MHD_Connection *connection;

    json_tokener *jtok;
    enum json_tokener_error jerr;
    json_object *jrequest;
    size_t request_len;

    json_object *jresponse;
    /* freed in json_object_put together with jresponse */
    const char *response_string;
    size_t response_len;
};

static struct MHD_Daemon *_daemon;

static struct http_request *_init_http_request(struct MHD_Connection *c) {
    struct http_request *req;
    nakd_assert((req = malloc(sizeof(struct http_request))) != NULL);

    req->connection = c;
    nakd_assert((req->jtok = json_tokener_new()) != NULL);
    req->jrequest = NULL;
    req->request_len = 0;
    req->jresponse = NULL;
    req->response_string = NULL;
    req->response_len = 0;

    return req;
}

static struct http_request *_free_http_request(struct http_request *c) {
    if (c->jrequest != NULL)
        json_object_put(c->jrequest);
    if (c->jtok != NULL)
        json_tokener_free(c->jtok);
    if (c->jresponse != NULL)
        json_object_put(c->jresponse);
    free(c);
}

static void _request_free_cb(void *priv) {
    struct http_request *req = priv;
    _free_http_request(req);
}

static ssize_t _http_response_reader(void *priv, uint64_t pos, char *buf,
                                                         size_t max) {
    struct http_request *req = priv;
    if (!max)
        return 0;
    if (pos >= req->response_len || req->jresponse == NULL)
        return MHD_CONTENT_READER_END_OF_STREAM;

    ssize_t nb = req->response_len - pos >= max ? max :
                               req->response_len - pos;
    strncpy(buf, req->response_string + pos, nb);
    return nb;
}

static void _http_rpc_completion(json_object *jresponse, void *priv) {
    struct http_request *c = priv;

    c->jresponse = jresponse;
    c->response_string = json_object_to_json_string_ext(jresponse,
                                         JSON_C_TO_STRING_PRETTY);
    c->response_len = strlen(c->response_string);
    MHD_resume_connection(c->connection);
}

static void _http_rpc_timeout(void *priv) {
    struct http_request *req = priv;
    const char *jstr = json_object_to_json_string_ext(req->jrequest,
                                           JSON_C_TO_STRING_PRETTY);
    nakd_log(L_CRIT, "RPC timeout while handling: %s", jstr);
}

static json_object *_http_get_session_data(const char *sessid) {
    char sess_path[PATH_MAX];
    snprintf(sess_path, sizeof sess_path, "%s/%s", SESSION_DIR, sessid);
    return nakd_json_parse_file(sess_path);
}

static enum nakd_access_level _http_session_acl(
            struct MHD_Connection *connection) {
    enum nakd_access_level acl = ACCESS_ALL;
    const char *sessid = MHD_lookup_connection_value(connection,
                           MHD_COOKIE_KIND, NAK_SESSION_COOKIE);
    if (sessid == NULL)
        goto ret;

    json_object *jsessdata = _http_get_session_data(sessid);
    if (jsessdata == NULL)
        goto ret;

    json_object *jacl = NULL;
    json_object_object_get_ex(jsessdata, "acl", &jacl);
    if (jacl == NULL)
        goto cleanup;

    nakd_assert(json_object_get_type(jacl) == json_type_string);
    acl = nakd_acl_from_string(json_object_get_string(jacl));

cleanup:
    json_object_put(jsessdata);
    /* null-safe */
    json_object_put(jacl);
ret:
    return acl;
}

static int _http_store_session_data(const char *sessid,
                              json_object *jsessdata) {
    char sess_path[PATH_MAX];
    snprintf(sess_path, sizeof sess_path, "%s/%s", SESSION_DIR, sessid);

    nakd_assert(jsessdata != NULL);
    const char *jdatastr = json_object_to_json_string_ext(jsessdata,
                                           JSON_C_TO_STRING_PRETTY);

    FILE *fp = fopen(sess_path, "w");
    if (fp == NULL)
        return 0;
    fputs(jdatastr, fp);
    fclose(fp);
    return 1;
}

/* Reserve at least 37 bytes for sessid */
static void _http_gen_sessid(char *sessid) {
    uuid_t uuid;
    /* uses /dev/urandom */
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, sessid);
}

static int _http_create_session(const char *sessid,
                      enum nakd_access_level acl) {
    json_object *jsessdata = json_object_new_object();
    json_object *jacl = json_object_new_string(
         nakd_access_level_string[(int)(acl)]);
    json_object_object_add(jsessdata, "acl", jacl);
    return _http_store_session_data(sessid, jsessdata);
}

static int _http_set_session_cookie(struct MHD_Connection *connection,
                                                 const char* sessid) {
    char cookie[512];
    snprintf(cookie , sizeof cookie, "%s=%s", NAK_SESSION_COOKIE, sessid);
    return MHD_YES == MHD_set_connection_value(connection, MHD_HEADER_KIND,
                                       MHD_HTTP_HEADER_SET_COOKIE, cookie);
}

static int _http_queue_response(const char *text, int code,
                       struct MHD_Connection *connection) {
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(
                  strlen(text), (void *)(text), MHD_RESPMEM_PERSISTENT);
    int ret = MHD_queue_response(connection, code, mhd_response);
    MHD_destroy_response(mhd_response);
    return ret;
}

static int _http_rpc_handler(void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *post_data, size_t *post_data_size, void **ptr) {
    if (strcmp(method, MHD_HTTP_METHOD_POST))
        return MHD_NO;

    if (*ptr == NULL) {
        struct http_request *req = _init_http_request(connection);
        *ptr = req;
        return MHD_YES;
    }

    /* second+ pass */
    int ret;
    struct http_request *req = *ptr;
    if (*post_data_size) {
        if (req->request_len += *post_data_size >
                  NAKD_JSONRPC_RCVMSGLEN_LIMIT) {
            nakd_log(L_NOTICE, "JSONRPC message longer than %d bytes, "
                       "disconnecting.", NAKD_JSONRPC_RCVMSGLEN_LIMIT);
            _free_http_request(req), *ptr = NULL;
            ret = MHD_NO;
        } else {
            req->jrequest = json_tokener_parse_ex(req->jtok, post_data,
                                                      *post_data_size);
            req->jerr = json_tokener_get_error(req->jtok);
            *post_data_size = 0;
            ret = MHD_YES;
        }
    /* last pass */
    } else {
        if (req->jerr == json_tokener_success) {
            /* doesn't allocate memory */
            const char *jreq_string = json_object_to_json_string_ext(req->jrequest,
                                                          JSON_C_TO_STRING_PRETTY);
            nakd_log(L_DEBUG, "Got a message: %s (URL: %s)", jreq_string, url);

            /* Get credentials from session cookie */
            const char *session_cookie = MHD_lookup_connection_value(
                     req->connection, MHD_COOKIE_KIND, NAK_SESSION_COOKIE);

            /* 
             * Suspend connection to avoid busywaiting on
             * _http_response_reader.
             */
            MHD_suspend_connection(req->connection);

            enum nakd_access_level acl = _http_session_acl(req->connection);
            nakd_handle_message(acl, req->jrequest, _http_rpc_completion,
                                                 _http_rpc_timeout, req);
            struct MHD_Response *mhd_response =
                 MHD_create_response_from_callback(MHD_SIZE_UNKNOWN, 4096, 
                          &_http_response_reader, req, &_request_free_cb);
            ret = MHD_queue_response(connection, MHD_HTTP_OK,
                                               mhd_response);
            MHD_destroy_response(mhd_response);

            /*
             * reset ptr: we're ready for another request after this call
             * completes. Request will be freed in _request_free_cb.
             */
            *ptr = NULL;
        } else {
            json_object *jresponse = nakd_jsonrpc_response_error(NULL,
                                                   PARSE_ERROR, NULL);
            const char *jrstr = json_object_to_json_string_ext(jresponse,
                                                JSON_C_TO_STRING_PRETTY);
            struct MHD_Response *mhd_response = MHD_create_response_from_buffer(
                         strlen(jrstr), (void *)(jrstr), MHD_RESPMEM_MUST_COPY);
            json_object_put(jresponse);

            ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST,
                                                        mhd_response);
            MHD_destroy_response(mhd_response);
            /* 
             * reset ptr: we're ready for another request after this call
             * completes
             */
            _free_http_request(req), *ptr = NULL;
       }
    }
    return ret;
}

static int _http_auth_handler(void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *post_data, size_t *post_data_size, void **ptr) {
    const char* user = MHD_lookup_connection_value(connection,
                               MHD_GET_ARGUMENT_KIND, "user");
    const char* pass = MHD_lookup_connection_value(connection,
                               MHD_GET_ARGUMENT_KIND, "pass");
    if (user == NULL || pass == NULL)
        return _http_queue_response("Bad request.", 400, connection);

    if (!nakd_authenticate(user, pass)) {
        char sessid[64];
        _http_gen_sessid(sessid);

        enum nakd_access_level acl = nakd_get_user_acl(user);
        _http_create_session(sessid, acl);
        _http_set_session_cookie(connection, sessid);
        return _http_queue_response(sessid, MHD_HTTP_OK, connection);
    }
    return _http_queue_response("Login incorrect.", MHD_HTTP_OK, connection);
}

struct http_handler {
    const char *url;
    MHD_AccessHandlerCallback cb;
} static _http_handlers[] = {
    { "/nak-rpc", _http_rpc_handler },
    { "/nak-auth", _http_auth_handler },
    { NULL, NULL }
};

static int _http_handler(void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *post_data, size_t *post_data_size, void **ptr) {
    for (struct http_handler *hndp = _http_handlers; hndp->url != NULL;
                                                              hndp++) {
        if (!strcmp(hndp->url, url)) {
            return hndp->cb(cls, connection, url, method, version, post_data,
                                                        post_data_size, ptr);
        }
    }
    return _http_queue_response("No such object.", 404, connection);
}

static void _httpd_logger(void *arg, const char *fmt, va_list ap) {
    nakd_log_va(L_DEBUG, fmt, ap);
}

static int _httpd_init(void) {
    if (access(SESSION_DIR, X_OK))
        nakd_assert(!mkdir(SESSION_DIR, 770));

    _daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY |
                   MHD_USE_SUSPEND_RESUME | MHD_USE_DEBUG,
                   PORT, NULL, NULL, &_http_handler, NULL, 
                          MHD_OPTION_CONNECTION_LIMIT, 64,
                        MHD_OPTION_CONNECTION_TIMEOUT, 10,
     MHD_OPTION_THREAD_STACK_SIZE, NAKD_THREAD_STACK_SIZE,
                           MHD_OPTION_THREAD_POOL_SIZE, 2,
          MHD_OPTION_EXTERNAL_LOGGER, _httpd_logger, NULL,
                                          MHD_OPTION_END);
    nakd_assert(_daemon != NULL);
    return 0;
}

static int _httpd_cleanup(void) {
    MHD_stop_daemon(_daemon);
    return 0;
}

static struct nakd_module module_httpd = {
    .name = "httpd",
    .deps = (const char *[]){ "config", "command", "workqueue", "auth", NULL },
    .init = _httpd_init,
    .cleanup = _httpd_cleanup
};
NAKD_DECLARE_MODULE(module_httpd);
