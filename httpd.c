#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
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
#include "session.h"
#include "kv.h"

#define PORT 8000

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
    nakd_log(L_DEBUG, "Sending HTTP response: %s", c->response_string);
    MHD_resume_connection(c->connection);
}

static void _http_rpc_timeout(void *priv) {
    struct http_request *req = priv;
    const char *jstr = json_object_to_json_string_ext(req->jrequest,
                                           JSON_C_TO_STRING_PRETTY);
    nakd_log(L_CRIT, "RPC timeout while handling: %s", jstr);
}

static const char *_http_connection_sessid(struct MHD_Connection *connection) {
    return MHD_lookup_connection_value(connection,
             MHD_COOKIE_KIND, NAK_SESSION_COOKIE);
}

static int _http_set_cookie(struct MHD_Response *response, const char *key,
                                                       const char *value) {
    char cookie[4096];
    snprintf(cookie, sizeof cookie, "%s=%s", key, value);
    return MHD_NO == MHD_add_response_header(response,
                  MHD_HTTP_HEADER_SET_COOKIE, cookie);
}

static int _http_set_session_cookie(struct MHD_Response *response,
                                             const char *sessid) {
    return _http_set_cookie(response, NAK_SESSION_COOKIE, sessid);
}

static int _http_set_cookies(struct MHD_Response *response, json_object *jkv) {
    json_object_object_foreach(jkv, key, jval) {
        nakd_assert(json_object_get_type(jval) == json_type_string);
        const char *value = json_object_get_string(jval);
        if (_http_set_cookie(response, key, value))
            return 1;
    }
    return 0;
}

static int _http_queue_response(const char *text, const char *sessid,
                                     json_object *jcookies, int code, 
                                 struct MHD_Connection *connection) {
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(
                   strlen(text), (void *)(text), MHD_RESPMEM_MUST_COPY);

    if (sessid != NULL)
        _http_set_session_cookie(mhd_response, sessid);
    if (jcookies != NULL)
        _http_set_cookies(mhd_response, jcookies);

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

            /* 
             * Suspend connection to avoid busywaiting on
             * _http_response_reader.
             */
            MHD_suspend_connection(req->connection);

            enum nakd_access_level acl = nakd_session_acl(
                _http_connection_sessid(req->connection));
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
    const char *logout = MHD_lookup_connection_value(connection,
                               MHD_GET_ARGUMENT_KIND, "logout");
    if (logout != NULL) {
        const char *sessid = _http_connection_sessid(connection);
        nakd_session_destroy(sessid);
        return _http_queue_response("OK", NULL, NULL, MHD_HTTP_OK, connection);
    }

    const char* user = MHD_lookup_connection_value(connection,
                               MHD_GET_ARGUMENT_KIND, "user");
    const char* pass = MHD_lookup_connection_value(connection,
                               MHD_GET_ARGUMENT_KIND, "pass");
    if (user == NULL || pass == NULL)
        return _http_queue_response("Bad request.", NULL, NULL, 400, connection);

    if (!nakd_authenticate(user, pass)) {
        char sessid[64];
        nakd_gen_sessid(sessid);

        enum nakd_access_level acl = nakd_get_user_acl(user);
        nakd_session_create(sessid, user, acl);
        return _http_queue_response(sessid, sessid, NULL, MHD_HTTP_OK, connection);
    }

    /* reply with HTTP 401 Unauthorised */
    return _http_queue_response("Login incorrect.", NULL, NULL, 401, connection);
}

static int _store_cookie_kv_it(void *cls, enum MHD_ValueKind kind,
                             const char *key, const char *value) {
    json_object *jkv = cls;
    json_object *jv = json_object_new_string(value);
    if (strcmp(key, NAK_SESSION_COOKIE))
        json_object_object_add(jkv, key, jv);
    return MHD_YES;
}

static int _store_cookie_kv(const char *user,
         struct MHD_Connection *connection) {
    json_object *jcookies = json_object_new_object();
    MHD_get_connection_values(connection, MHD_COOKIE_KIND, _store_cookie_kv_it,
                                                                     jcookies);
    return nakd_kv_set_bulk(user, jcookies);
}

static int _http_session_handler(void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *post_data, size_t *post_data_size, void **ptr) {
    const char *sessid = _http_connection_sessid(connection);
    if (sessid == NULL) {
        return _http_queue_response("Bad request - no sessid.", NULL,
                                              NULL, 400, connection);
    }
    if (!nakd_session_exists(sessid)) {
        return _http_queue_response("Bad request - bad sessid.", NULL,
                                               NULL, 400, connection);
    }

    json_object *jusername = nakd_session_get_user(sessid); 
    const char *username = json_object_get_string(jusername);
    nakd_assert(nakd_user_exists(username));

    _store_cookie_kv(username, connection);
    json_object *jukv = nakd_kv(username);
    json_object_put(jusername);

    return _http_queue_response("OK", sessid, jukv, MHD_HTTP_OK, connection);
}

struct http_handler {
    const char *url;
    MHD_AccessHandlerCallback cb;
} static _http_handlers[] = {
    { "/nak-rpc", _http_rpc_handler },
    { "/nak-auth", _http_auth_handler },
    { "/nak-session", _http_session_handler },
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
    return _http_queue_response("No such object.", NULL, NULL, 404, connection);
}

static void _httpd_logger(void *arg, const char *fmt, va_list ap) {
    nakd_log_va(L_DEBUG, fmt, ap);
}

static int _httpd_init(void) {
    _daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY |
                   MHD_USE_SUSPEND_RESUME | MHD_USE_DEBUG,
                   PORT, NULL, NULL, &_http_handler, NULL, 
                          MHD_OPTION_CONNECTION_LIMIT, 64,
                        MHD_OPTION_CONNECTION_TIMEOUT, 10,
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
    .deps = (const char *[]){ "config", "command", "workqueue", "auth",
                                               "session", "kv", NULL },
    .init = _httpd_init,
    .cleanup = _httpd_cleanup
};
NAKD_DECLARE_MODULE(module_httpd);
