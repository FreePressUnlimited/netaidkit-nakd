#ifndef NAKD_STAGE_H
#define NAKD_STAGE_H
#include <json-c/json.h>
#include "nak_uci.h"
#include "hooks.h"
#include "connectivity.h"
#include "led.h"

struct stage;
typedef int (*stage_work)(const struct stage *stage);

struct stage_step {
    const char *name;
    const char *desc;
    stage_work work;
};

struct stage {
    const char *name;
    const char *desc;
    const struct stage_step *work_start;
    const struct stage_step *work_stop;
    enum nakd_connectivity connectivity_level;
    struct led_condition led;
    int update_default_stage;

    struct nakd_uci_hook *hooks;
};

const struct stage *nakd_stage_current(void);
const struct stage *nakd_stage_requested(void);

json_object *cmd_stage_set(json_object *jcmd, void *param);

void nakd_stage_spec(struct stage *stage, int save);
void nakd_stage_spec_synch(struct stage *stage, int save);
int nakd_stage(const char *stage_name);

#endif
