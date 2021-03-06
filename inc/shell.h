#ifndef NAKD_SHELL_H
#define NAKD_SHELL_H
#include <json-c/json.h>
#include "command.h"
#include "module.h"

#define MAX_SHELL_RESULT_LEN 4096

#define NAKD_SCRIPT_PATH "/usr/share/nakd/scripts/"
#define NAKD_SCRIPT(filename) NAKD_SCRIPT_PATH filename

int nakd_shell_exec(const char *cwd, char **output, int timeout_term,
                             int timeout_kill, const char *fmt, ...);
int nakd_shell_exec_argv(const char **argv, const char *cwd,
         int timeout_term, int timeout_kill, char **output);

typedef int (*nakd_traverse_cb)(const char *path, void *priv);
int nakd_traverse_directory(const char *path, nakd_traverse_cb cb, void *priv);

int nakd_shell_run_scripts(const char *dirpath, int timeout_term,
                                               int timeout_kill);

struct cmd_shell_spec {
    const char **argv;
    const char *cwd;
};

json_object *cmd_shell(json_object *jcmd, struct cmd_shell_spec *spec);
extern struct nakd_module module_shell;

/*
 * Usage:
 * struct nakd_command update = CMD_SHELL_NAKD(ACCESS_ADMIN, "update", "do_update.sh");
 * NAKD_DECLARE_COMMAND(update);
 */
#define CMD_SHELL_ARGV(acl, cname, cwd, path, argv...) \
    { .name = cname, \
      .access = acl, \
      .handler = (nakd_cmd_handler)(cmd_shell), \
      .module = &module_shell, \
      .priv = &(struct cmd_shell_spec) \
        { (const char*[]){ path, argv, NULL }, cwd } \
    }
#define CMD_SHELL(acl, cname, cwd, path) \
    { .name = cname, \
      .access = acl, \
      .handler = (nakd_cmd_handler)(cmd_shell), \
      .module = &module_shell, \
      .priv = &(struct cmd_shell_spec) \
        { (const char*[]){ path, NULL }, cwd } \
    }
#define CMD_SHELL_NAKD_ARGV(acl, cname, path, argv...) \
    { .name = cname, \
      .access = acl, \
      .handler = (nakd_cmd_handler)(cmd_shell), \
      .module = &module_shell, \
      .priv = &(struct cmd_shell_spec) \
        { (const char*[]){ NAKD_SCRIPT(path), argv, NULL }, \
                                         NAKD_SCRIPT_PATH } \
    }
#define CMD_SHELL_NAKD(acl, cname, path) \
    { .name = cname, \
      .access = acl, \
      .handler = (nakd_cmd_handler)(cmd_shell), \
      .module = &module_shell, \
      .priv = &(struct cmd_shell_spec) \
        { (const char*[]){ NAKD_SCRIPT(path), NULL }, NAKD_SCRIPT_PATH } \
    }

#endif
