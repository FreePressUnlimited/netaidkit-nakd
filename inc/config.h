#ifndef NAKD_CONFIG_H
#define NAKD_CONFIG_H

int nakd_config_key(const char *key, char **ret);
int nakd_config_set(const char *key, const char *val);
int nakd_config_key_int(const char *key, int *ret);
int nakd_config_set_int(const char *key, int val);

#endif
