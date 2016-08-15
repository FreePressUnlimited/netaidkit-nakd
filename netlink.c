#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include "module.h"
#include "log.h"
#include "thread.h"
#include "netlink.h"

/* Use libnl-3.2.21 private API for now. */
/* TODO remove after OpenWRT/LEDE switches to libnl-3.2.24. */
enum {
        NL_ACT_UNSPEC,
        NL_ACT_NEW,
        NL_ACT_DEL,
        NL_ACT_GET,
        NL_ACT_SET,
        NL_ACT_CHANGE,
        __NL_ACT_MAX,
};

static struct nakd_thread *_netlink_thread;

static struct nl_cache_mngr *_manager;
static struct nl_cache *_cache;

static int _shutdown;

static void _update_cb(struct nl_cache *cache, struct nl_object *obj,
                                            int action, void *priv) {
    struct rtnl_link *link = (struct rtnl_link *)(obj);
    switch (action) {
        case NL_ACT_NEW:
        break;
        case NL_ACT_DEL:
        break;
        case NL_ACT_CHANGE:
            nakd_log(L_DEBUG, "%s: carrier %s", rtnl_link_get_name(link),
                          rtnl_link_get_carrier(link) ? "up" : "down");
        break;
    }
}

static void _netlink_loop(struct nakd_thread *thread) {
    while (!_shutdown) {
        int err = nl_cache_mngr_poll(_manager, 1000);
        if (err < 0 && err != -NLE_INTR)
            nakd_log(L_CRIT, "netlink: polling failed: %s", nl_geterror(err));
    }    
}

static void _netlink_shutdown(struct nakd_thread *thread) {
    _shutdown = 1;
}

static int _netlink_init(void) {
    nakd_assert(!nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE,
                                                              &_manager));
    nakd_assert(!nl_cache_mngr_add(_manager, "route/link", &_update_cb,
                                                       NULL, &_cache));
    nakd_assert(!nakd_thread_create_joinable(_netlink_loop,
               _netlink_shutdown, NULL, &_netlink_thread));
    return 0;
}

static int _netlink_cleanup(void) {
    nl_cache_mngr_free(_manager);
    return 0;
}

static struct nakd_module module_netlink = {
    .name = "netlink",
    .deps = (const char *[]){ "event", "workqueue", NULL },
    .init = _netlink_init,
    .cleanup = _netlink_cleanup
};
NAKD_DECLARE_MODULE(module_netlink);
