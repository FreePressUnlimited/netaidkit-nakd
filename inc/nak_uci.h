#ifndef NAKD_UCI_H
#define NAKD_UCI_H
#include <json-c/json.h>

/* -std=c99 */
#define typeof __typeof
#include <uci.h>
#undef typeof

typedef int (*nakd_uci_option_foreach_cb)(struct uci_option *option,
                                                     void *cb_priv);

struct uci_package *nakd_load_uci_package(const char *name);
struct uci_option *nakd_uci_option_single(const char *option_name);
int nakd_uci_option_foreach(const char *option_name,
                      nakd_uci_option_foreach_cb cb,
                                     void *cb_priv);
int nakd_uci_option_foreach_pkg(const char *package, const char *option_name,
                               nakd_uci_option_foreach_cb cb, void *cb_priv);
int nakd_uci_save(struct uci_package *pkg);
int nakd_uci_commit(struct uci_package **pkg, bool overwrite);
int nakd_unload_uci_package(struct uci_package *pkg);
int nakd_uci_set(struct uci_ptr *ptr);
void nakd_uci_lock(void);
void nakd_uci_unlock(void);
json_object *nakd_get_option(const char *package, const char *section,
                                                  const char *option);

#endif
