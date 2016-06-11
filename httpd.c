#include <string.h>
#include "httpd.h"
#include "module.h"
#include "config.h"
#include "log.h"

static int _httpd_init(void) {

}

static int _httpd_cleanup(void) {

}

static int ahc_echo (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data, size_t *upload_data_size, void **ptr) {
    if (strcmp(method, "POST"))
        return MHD_NO;

    /* second pass */
    if (ptr == NULL) {
        ptr = (void**)(1);
        return MHD_YES;
    }
}

static struct nakd_module module_httpd = {
    .name = "httpd",
    .deps = (const char *[]){ "config" },
    .init = _httpd_init,
    .cleanup = _httpd_cleanup
};
NAKD_DECLARE_MODULE(module_httpd);
