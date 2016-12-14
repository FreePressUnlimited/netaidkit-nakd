#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <json-c/json.h>
#include "module.h"
#include "command.h"
#include "log.h"
#include "nak_mutex.h"
#include "workqueue.h"
#include "jsonrpc.h"
#include "json.h"
#include "shell.h"
#include "stage.h"
#include "config.h"
#include "updater.h"

#define UPDATER_PATH "/sbin/sysupgrade"

struct update_params {
    FILE *fupdate;
    json_object *jparams;
};

static pthread_mutex_t _updater_mutex;

static EVP_PKEY *_read_update_pkey(void) {
    EVP_PKEY *pkey = NULL;

    char *pkey_path;
    if (nakd_config_key("update_pkey_path", &pkey_path)) {
        nakd_log(L_CRIT, "Path to firmware update public key is undefined.");
        goto ret;
    }

    FILE *fpkey = fopen(pkey_path, "r");
    if (fpkey == NULL) {
        nakd_log(L_CRIT, "Couldn't open public keyfile at %s", pkey_path);
        goto ret;
    }

    pkey = PEM_read_PUBKEY(fpkey, NULL, NULL, NULL);
    fclose(fpkey);

    nakd_log(L_DEBUG, "Read public key (%s).", pkey_path);
ret:
    return pkey;
}

/* 
 *  Tests new firmware image's signature and applies a shared lock on the
 *  update file if fp_ex isn't NULL.
 */ 
int nakd_check_update_signature(const char *update_path, FILE** fp_ex) {
    int status = 1;

    EVP_PKEY *pkey = _read_update_pkey();
    if (pkey == NULL)
        goto ret;
    size_t pkey_size = RSA_size(EVP_PKEY_get1_RSA(pkey));

    FILE *fupdate = fopen(update_path, "r");
    if (fupdate == NULL) {
        nakd_log(L_WARNING, "Couldn't open firmware update file (%s).", update_path);
        goto ret;
    }
    if (fp_ex != NULL) {
        if (flock(fileno(fupdate), LOCK_SH)) {
            nakd_log(L_WARNING, "Can't lock firmware update file (%s): %s",
                                             update_path, strerror(errno));
            goto ret;
        }
    }

    fseek(fupdate, 0, SEEK_END);
    size_t update_size = ftell(fupdate);
    rewind(fupdate);

    void *pupdate = mmap(NULL, update_size, PROT_READ,
                     MAP_PRIVATE, fileno(fupdate), 0);
    if (pupdate == MAP_FAILED)
        nakd_terminate("mmap() failed - %s", strerror(errno)); 

    if (update_size - pkey_size <= 0) {
        nakd_log(L_WARNING, "Bad update file.");
        goto cleanup_mmap;
    }

    void *psignature = pupdate + update_size - pkey_size;
    const size_t fw_image_size = update_size - pkey_size;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    nakd_assert(mdctx != NULL);

    char *update_digest;
    if (nakd_config_key("update_digest", &update_digest)) {
        nakd_log(L_CRIT, "Update digest is undefined");
        goto cleanup_mdctx;
    }
    const EVP_MD *md = EVP_get_digestbyname(update_digest);
    if (md == NULL) {
        nakd_log(L_CRIT, "Unknown message digest \"%s\".", update_digest);
        goto cleanup_mdctx;
    }

    nakd_assert(EVP_DigestInit_ex(mdctx, md, NULL));
    nakd_assert(EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey));

    int rc;
    rc = EVP_DigestVerifyUpdate(mdctx, pupdate, fw_image_size);
    if (!rc) {
        nakd_log(L_WARNING, "Can't verify the signature: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        goto cleanup_mdctx;
    }
    rc = EVP_DigestVerifyFinal(mdctx, psignature, pkey_size);
    if (!rc) {
        nakd_log(L_WARNING, "Wrong signature (%s).", update_path);
    } else {
        nakd_log(L_DEBUG, "Good signature (%s).", update_path);
        status = 0;
    }
    
cleanup_mdctx:
    EVP_MD_CTX_destroy(mdctx);
cleanup_mmap:
    munmap(pupdate, update_size);
cleanup_fd:
    if (fp_ex != NULL && !status)
        *fp_ex = fupdate;
    else
        fclose(fupdate);
ret:
    return status;
}

static void _async_sysupgrade_work(void *priv) {
    struct update_params *uparams = priv;
    const char *path = json_object_get_string(uparams->jparams);

    /* Make sure OpenVPN and Tor daemons aren't running to free RAM. */
    if (nakd_stage("stage_offline"))
        nakd_log(L_CRIT, "nakd_stage() failed");

    if (access(path, R_OK)) {
        nakd_log(L_CRIT, "Can't access the update image at \"%s\"", path);
        goto refcount;
    } 

    if (nakd_shell_exec("/tmp", NULL, 120, 130, UPDATER_PATH " %s", path)) {
        nakd_log(L_CRIT, "sysupgrade failed");

        /*
         *  In case sysupgrade returns before the upgrade is completed,
         *  close (and release LOCK_SH) only if sysupgrade failed.
         *  Normally OpenWRT sysupgrade kills all other processes before
         *  upgrading the system.
         */
        fclose(uparams->fupdate);
    }

refcount:
    json_object_put(uparams->jparams);
    free(uparams);
}

static struct work_desc _async_sysupgrade_desc = {
    .impl = _async_sysupgrade_work,
    .name = "sysupgrade"
};

json_object *cmd_sysupgrade(json_object *jcmd, void *arg) {
    json_object *jresponse = NULL;
    json_object *jparams;

    if ((jparams = nakd_jsonrpc_params(jcmd)) == NULL ||
        json_object_get_type(jparams) != json_type_string) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_PARAMS,
           "Invalid parameters - params should be a filesystem path "
                                                           "string");
        goto response;
    }

    if ((jresponse = nakd_command_timedlock(jcmd, &_updater_mutex)) != NULL)
        goto response;

    if (nakd_work_pending(nakd_wq, _async_sysupgrade_desc.name)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
                                "Invalid request - already updating");
        goto unlock;
    }

    const char *path = json_object_get_string(jparams);
    if (access(path, R_OK)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
                     "Can't access the update image at \"%s\"", path);
        goto unlock;
    } 

    /*
     *  Check the signature and leave a shared lock on the update file if
     *  everything goes right.
     */
    FILE *fupdate;
    if (nakd_check_update_signature(path, &fupdate)) {
        nakd_log(L_WARNING, "Bad signature (%s), aborting system upgrade.", path);
        jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
                 "Bad signature (%s), aborting system upgrade", path);
        goto unlock;
    }

    struct update_params *uparams = malloc(sizeof(struct update_params));
    uparams->fupdate = fupdate;
    uparams->jparams = jparams;

    struct work *sysupgrade_wq_entry = nakd_alloc_work(&_async_sysupgrade_desc);
    json_object_get(jparams), sysupgrade_wq_entry->desc.priv = uparams;
    nakd_workqueue_add(nakd_wq, sysupgrade_wq_entry);

    json_object *jresult = json_object_new_string("Good signature, "
                                          "queued system upgrade.");
    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);

unlock:
    nakd_mutex_unlock(&_updater_mutex);
response:
    return jresponse;
}

static struct nakd_module module_updater = {
    .name = "updater",
    .deps = (const char *[]){ "command", "shell", NULL },
};
NAKD_DECLARE_MODULE(module_updater);

static struct nakd_command sysupgrade = {
    .name = "sysupgrade",
    .desc = "",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"sysupgrade\","
            "\"params\": \"/tmp/sysupgrade-image\", \"id\": 42}",
    .handler = cmd_sysupgrade,
    .access = ACCESS_ADMIN,
    .module = &module_updater
};
NAKD_DECLARE_COMMAND(sysupgrade);
