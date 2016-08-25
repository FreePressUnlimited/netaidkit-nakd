#include <string.h>
#include <json-c/json.h>
#include "request.h"
#include "command.h"
#include "log.h"
#include "misc.h"
#include "jsonrpc.h"
#include "workqueue.h"
#include "nak_mutex.h"

void nakd_handle_message(json_object *jmsg, nakd_response_cb cb,
                       nakd_timeout_cb timeout_cb, void *priv) {
    if (nakd_jsonrpc_is_batch(jmsg)) {
        nakd_handle_batch(jmsg, cb, timeout_cb, priv);
        return;
    }
    
    if (nakd_jsonrpc_is_request(jmsg) || nakd_jsonrpc_is_notification(jmsg)) {
        nakd_handle_single(jmsg, cb, timeout_cb, priv);
        return;
    }

    json_object *jresp = nakd_jsonrpc_response_error(jmsg, INVALID_REQUEST,
                                                                     NULL);
    if (cb != NULL)
        cb(jresp, priv);
}

void nakd_handle_single(json_object *jreq, nakd_response_cb cb,
                      nakd_timeout_cb timeout_cb, void *priv) {
    const char *method_name = nakd_jsonrpc_method(jreq);
    if (method_name == NULL) {
        nakd_log(L_WARNING, "Couldn't get method name from request");
        json_object *jresponse = nakd_jsonrpc_response_error(jreq,
                                          METHOD_NOT_FOUND, NULL);
        if (cb != NULL)
            cb(jresponse, priv);
    }
    
    nakd_log(L_DEBUG, "Handling request, method=\"%s\".", method_name);
    nakd_call_command(method_name, jreq, cb, timeout_cb, priv);
}

struct batch {
    void *priv;

    int requests;
    int handled;
    pthread_mutex_t mutex;
    json_object *jresponse;
    nakd_response_cb completion_cb;
};

static struct batch *_init_batch(int requests, nakd_response_cb completion_cb,
                                                                 void *priv) {
    struct batch *b;
    nakd_assert((b = malloc(sizeof(struct batch))) != NULL);
    nakd_assert(!pthread_mutex_init(&b->mutex, NULL));
    nakd_assert((b->jresponse = json_object_new_array()) != NULL);
    b->requests = requests;
    b->handled = 0;
    b->completion_cb = completion_cb;
    b->priv = priv;
    return b;
}

static void _cleanup_batch(struct batch *b) {
    pthread_mutex_destroy(&b->mutex);
}

static void _batch_completion(json_object *jresult, void *priv) {
    struct batch *b = priv;

    nakd_mutex_lock(&b->mutex);
    if (jresult != NULL)
        json_object_array_add(b->jresponse, jresult);
    int complete = b->requests == ++b->handled;
    pthread_mutex_unlock(&b->mutex);

    if (complete) {
        if (b->completion_cb != NULL) {
            b->completion_cb(b->jresponse, b->priv);
        }
        _cleanup_batch(b);
    }
}

void nakd_handle_batch(json_object *jmsg, nakd_response_cb cb,
                     nakd_timeout_cb timeout_cb, void *priv) {
    int requests = json_object_array_length(jmsg);
    struct batch *b = _init_batch(requests, cb, priv);
    for (int i = 0; i < json_object_array_length(jmsg); i++) {
        json_object *jsingle = json_object_array_get_idx(jmsg, i);
        nakd_handle_single(jsingle, _batch_completion, timeout_cb, b);
    }
}
