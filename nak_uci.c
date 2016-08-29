#include <unistd.h>
#include <pthread.h>
#include "nak_uci.h"
#include "log.h"
#include "module.h"
#include "nak_mutex.h"

static pthread_mutex_t _uci_mutex;
static struct uci_context *_uci_ctx = NULL;

static int _uci_init(void) {
    pthread_mutex_init(&_uci_mutex, NULL);
    return 0;
}

static int _uci_cleanup(void) {
    pthread_mutex_destroy(&_uci_mutex);
    return 0;
}

struct uci_package *nakd_load_uci_package(const char *name) {
   struct uci_package *pkg = NULL;

    /*
     * nakd_log(L_INFO, "Loading UCI package \"%s\"", name);
     */
    nakd_assert(name != NULL);
   
    for (int try = 0; try < 5; try++) {
        if (uci_load(_uci_ctx, name, &pkg)) {
            char *uci_err;
            uci_get_errorstr(_uci_ctx, &uci_err, "");
            nakd_log(L_CRIT, "Couldn't load UCI package \"%s\": %s. "
                      "Could be a race condition, retrying...", name,
                                                            uci_err);
            sleep(1);
        } else {
            break;
        }
    }
    return pkg;
}

static int _uci_option_single_cb(struct uci_option *option, void *priv) {
    struct uci_option **result = (struct uci_option **)(priv);
    *result = option;
    return 0;
}

struct uci_option *nakd_uci_option_single(const char *option_name) {
    struct uci_option *result = NULL;
    nakd_uci_option_foreach(option_name, _uci_option_single_cb, &result);
    return result;
}

int nakd_uci_save(struct uci_package *pkg) {
    /*
     *    nakd_log(L_INFO, "Saving UCI package \"%s\"", pkg->e.name);
     */
    return uci_save(_uci_ctx, pkg);
}

int nakd_uci_commit(struct uci_package **pkg, bool overwrite) {
    /* 
     * nakd_log(L_DEBUG, "Commiting changes to UCI package \"%s\"",
     *                                             (*pkg)->e.name);
     */
    return uci_commit(_uci_ctx, pkg, overwrite);
}

int nakd_unload_uci_package(struct uci_package *pkg) {
    /*
     * nakd_log(L_DEBUG, "Unloading UCI package \"%s\"", pkg->e.name);
     */
    if (uci_unload(_uci_ctx, pkg)) {
        char *uci_err;
        uci_get_errorstr(_uci_ctx, &uci_err, "");
        nakd_log(L_CRIT, "Couldn't unload UCI package: %s", uci_err);
        return 1;
    }
    return 0;
}

/* Execute a callback for every option 'option_name', in selected UCI package */
int nakd_uci_option_foreach_pkg(const char *package, const char *option_name,
                              nakd_uci_option_foreach_cb cb, void *cb_priv) {
    struct uci_element *sel;
    struct uci_section *section;
    struct uci_option *option;
    struct uci_package *uci_pkg;
    int cb_calls = 0;
    
    uci_pkg = nakd_load_uci_package(package);
    if (uci_pkg == NULL)
        return 1;

    /*
     * Iterate through sections, ie.
     *  config redirect
     */
    uci_foreach_element(&uci_pkg->sections, sel) {
        section = uci_to_section(sel);

        option = uci_lookup_option(uci_pkg->ctx, section, option_name);
        if (option == NULL)
            continue;

        if (cb(option, cb_priv)) {
            cb_calls = -1;
            goto unload;
        } else {
            cb_calls++;
        }
    }

unload:
    nakd_assert(nakd_uci_save(uci_pkg) == UCI_OK);
    /* nakd probably wouldn't recover from these */
    nakd_assert(nakd_uci_commit(&uci_pkg, true) == UCI_OK);
    if (uci_pkg != NULL)
        nakd_assert(nakd_unload_uci_package(uci_pkg) == UCI_OK);
    return cb_calls;
}

/* Execute a callback for every option 'option_name' */
int nakd_uci_option_foreach(const char *option_name,
                      nakd_uci_option_foreach_cb cb,
                                    void *cb_priv) {
    int cb_calls = 0;

    char **uci_packages;
    if ((uci_list_configs(_uci_ctx, &uci_packages) != UCI_OK)) {
        nakd_log(L_CRIT, "Couldn't enumerate UCI packages");
        cb_calls = -1;
        goto unlock;
    }

    for (char **package = uci_packages; *package != NULL; package++) {
        int pkg_calls = nakd_uci_option_foreach_pkg(*package, option_name,
                                                             cb, cb_priv);
        if (pkg_calls < 0) {
            cb_calls = -1;
            goto unlock;
        }
        cb_calls += pkg_calls;
    }

unlock:
    free(uci_packages);
    return cb_calls;
}

int nakd_uci_set(struct uci_ptr *ptr) {
    if (uci_set(_uci_ctx, ptr)) {
        char *uci_err;
        uci_get_errorstr(_uci_ctx, &uci_err, "");
        nakd_log(L_CRIT, "UCI: %s", uci_err);
        return 1;
    }
    return 0;
}

/* UCI isn't thread-safe - keep this lock during UCI operations */
void nakd_uci_lock(void) {
    nakd_mutex_lock(&_uci_mutex);
    _uci_ctx = uci_alloc_context();
    if (_uci_ctx == NULL)
        nakd_terminate("Couldn't initialize UCI context.");
}

void nakd_uci_unlock(void) {
    uci_free_context(_uci_ctx), _uci_ctx = NULL;
    pthread_mutex_unlock(&_uci_mutex);
}

json_object *nakd_get_option(const char *package, const char *section,
                                                 const char *option) {
    struct uci_ptr option_ptr = {
        .package = package,
        .section = section,
        .option = option
    };

    if (uci_lookup_ptr(_uci_ctx, &option_ptr, NULL, 1) == UCI_OK) {
        if (option_ptr.o != NULL && option_ptr.o->v.string != NULL)
            return json_object_new_string(option_ptr.o->v.string);
    }
    nakd_log(L_DEBUG, "Couldn't get \"%s\" option (%s/%s/%s)", option,
                                            package, section, option);
    return NULL;
}

static struct nakd_module module_uci = {
    .name = "uci",
    .deps = NULL,
    .init = _uci_init,
    .cleanup = _uci_cleanup
};

NAKD_DECLARE_MODULE(module_uci);
