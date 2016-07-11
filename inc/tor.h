#ifndef NAKD_TOR_H
#define NAKD_TOR_H

void nakd_tor_enable_notifications(void);
void nakd_tor_disable_notifications(void);
json_object *cmd_tor(json_object *jcmd, void *arg);

#endif
