#ifndef NAKD_TIMER_H
#define NAKD_TIMER_H
#include <signal.h>

struct nakd_timer;
typedef void (*nakd_timer_handler)(siginfo_t *timer_info,
                               struct nakd_timer *timer);
struct nakd_timer {
    timer_t id;
    nakd_timer_handler handler;
    const char *name;
    void *priv;

    int active;
};

#define nakd_log_timer(timer) nakd_log(L_DEBUG, "Handling \"%s\" timer.", \
                                                              timer->name);

struct nakd_timer *nakd_timer_add(int interval_ms, nakd_timer_handler handler,
                                                void *priv, const char *name);
void __nakd_timer_remove(struct nakd_timer *timer);
void nakd_timer_remove(struct nakd_timer *timer);

#endif
