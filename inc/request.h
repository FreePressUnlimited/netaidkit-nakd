#ifndef NAKD_REQUEST_H
#define NAKD_REQUEST_H
#include <json-c/json.h>
#include "command.h"

void nakd_handle_message(json_object *jmsg, nakd_response_cb cb,
                        nakd_timeout_cb timeout_cb, void *priv);
void nakd_handle_single(json_object *jmsg, nakd_response_cb cb,
                       nakd_timeout_cb timeout_cb, void *priv);
void nakd_handle_batch(json_object *jmsg, nakd_response_cb cb,
                      nakd_timeout_cb timeout_cb, void *priv);

#endif
