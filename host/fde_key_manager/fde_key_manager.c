/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2023, Canonical Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>

#include <tee_client_api.h>
#include <tee_api_defines.h>

#include <json-c/json.h>

#include "fde_key_handler_ta_type.h"
#include "fde_key_manager_ca.h"

#define MAX_JSON_BUF_SIZE   (1024 * 10)

#define FDE_SETUP "fde-setup"
#define FDE_REVEAL_KEY "fde-reveal-key"

#define SNAPCTL "snapctl"

#define FDE_JSON_OP                "op"
#define FDE_JSON_OP_REVEAL         "reveal"
#define FDE_JSON_OP_LOCK           "lock"
#define FDE_JSON_OP_INITIAL_SETUP  "initial-setup"
#define FDE_JSON_OP_FEATURES       "features"
#define FDE_JSON_KEY               "key"
#define FDE_JSON_KEY_NAME          "key-name"
#define FDE_JSON_SEALED_KEY        "sealed-key"
#define FDE_JSON_HANDLE            "handle"
#define FDE_JSON_RESULT_FEATURES   "{\"features\":[]}"

#if !defined(TRUE)
  #define TRUE ((json_bool)1)
#endif
#if !defined(FALSE)
  #define FALSE ((json_bool)0)
#endif

// by default we print sesult to stdout
static int snapctl_output = 0;

static void print_help(void)
{
    printf("This binary should be invoked only under specific context\n\n");
    printf("For testing purpose following out of context options are supported\n");
    printf("\t--ta-lock-status: get TA lock status\n");
    printf("\t--lock-ta: lock TA for any crypto operation till next reboot\n");
    printf("\t--generate-random [len in bytes]: generate random buffer and print it coded in base64\n");
    printf("\t\tby default 128bytes buffer is generated unless size is passed\n");
    printf("\t--encrypt-decrypt-selftest: encrypt and decrypt selftest\n");
}

char *get_snap_hook_fde_setup_request(void) {
    FILE *f;
    char *request = NULL;
    char *pos = NULL;

    // run snapctl
    f = popen(SNAPCTL" fde-setup-request", "r");
    if (f == NULL) {
        ree_log(REE_ERROR, "Failed to run snapctl command" );
        return NULL;
    }
    request = (char *)malloc(MAX_JSON_BUF_SIZE);
    if (!request) {
       ree_log(REE_ERROR, "Failed to allocate request buffer" );
       pclose(f);
       return NULL;
    }

    // read output
    pos = request;
    while (fgets(pos, MAX_JSON_BUF_SIZE, f) != NULL) {
        pos = request + strlen(request);
    }

    pclose(f);
    return request;
}

int set_snap_hook_fde_setup_request_result(const unsigned char *result, int len) {
    FILE *out_stream;
    int ret = EXIT_SUCCESS;
    // run snapctl
    out_stream = popen(SNAPCTL" fde-setup-result", "w");
    if (!out_stream) {
      ree_log(REE_ERROR, "Failed to pass fde-setup-result");
      return EXIT_FAILURE;
    }

    fwrite(result, len, 1, out_stream);
    fflush(out_stream);

    if (ferror (out_stream)) {
        ree_log(REE_ERROR, "Failed to write to fde-setup-result stdin");
        ret = EXIT_FAILURE;
    }
    pclose(out_stream);
    return ret;
}

int set_result(const unsigned char * result, int len) {
    int ret;
    if (snapctl_output) {
        return set_snap_hook_fde_setup_request_result(result, len);
    } else {
        ret = fprintf( stdout, "%s\n", result);
        // ret has number of written bytes, only check report fail / success
        if (ret > 0) {
            ret = EXIT_SUCCESS;
        }
        return ret;
    }
}

char *get_initrd_fde_request() {
    size_t b_read = 0;
    size_t size_remaining;
    char *request = NULL;
    char *pos = NULL;

    ree_log(REE_DEBUG, "get_initrd_fde_request");
    request = (char *)malloc(MAX_JSON_BUF_SIZE);
    if (!request) {
       ree_log(REE_ERROR, "Failed to allocate request buffer" );
       return NULL;
    }

    // start reading
    size_remaining = MAX_JSON_BUF_SIZE;
    pos = request;
    while((b_read = read(STDIN_FILENO, pos, size_remaining)) == size_remaining) {
        size_remaining -= b_read;
        pos += b_read;
    }
    return request;
}

int handle_operation_reveal(struct json_object *request_json) {
    int ret = EXIT_SUCCESS;
    struct json_object *j_key = NULL;
    struct json_object *j_handle = NULL;
    struct json_object *j_response = NULL;
    struct json_object *j_unsealed_key = NULL;
    json_bool j_ret;
    unsigned char *sealed_key_buf = NULL;
    unsigned char *handle_buf = NULL;
    unsigned char *unsealed_key_buf = NULL;
    size_t sealed_key_buf_len = 0;
    size_t handle_buf_len = 0;
    size_t unsealed_key_buf_len = 0;
    char *unsealed_key = NULL;
    const char *result;

    // get other request data:
    //   FDE_JSON_SEALED_KEY | FDE_JSON_HANDLE
    j_ret = json_object_object_get_ex(request_json,
                                      FDE_JSON_SEALED_KEY,
                                      &j_key);
    if ((j_ret != TRUE) ||
        (json_type_string != json_object_get_type(j_key))
       ) {
        ree_log(REE_ERROR, "sealed key json malformed[%d]", j_ret);
        ret = EXIT_FAILURE;
        goto cleanup;
    }
    sealed_key_buf = base64_decode(json_object_get_string(j_key),
                                    strlen(json_object_get_string(j_key)),
                                    &sealed_key_buf_len);

    if (!sealed_key_buf){
        ree_log(REE_ERROR, "failed to decode sealed key from base64");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    j_ret = json_object_object_get_ex(request_json,
                                      FDE_JSON_HANDLE,
                                      &j_handle);
    if ((j_ret != TRUE) ||
        (json_type_string != json_object_get_type(j_handle))
       ) {
       ree_log(REE_ERROR, "handle json malformed[%d]", j_ret);
       ret = EXIT_FAILURE;
       goto cleanup;
    }
    handle_buf = base64_decode(json_object_get_string(j_handle),
                               strlen(json_object_get_string(j_handle)),
                               &handle_buf_len);
    if (!handle_buf) {
           ree_log(REE_ERROR, "failed to decode key handle base64");
           ret = EXIT_FAILURE;
           goto cleanup;
    }

    // call crypto operation
    unsealed_key_buf_len = MAX_BUF_SIZE;
    unsealed_key_buf = (unsigned char *)malloc(unsealed_key_buf_len);
    if (!unsealed_key_buf){
        ree_log(REE_ERROR, "unsealed_key buf alloc failed");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    ret = decrypt_key(sealed_key_buf,
                      sealed_key_buf_len,
                      handle_buf,
                      handle_buf_len,
                      unsealed_key_buf,
                      &unsealed_key_buf_len);
    if (ret) {
        ree_log(REE_ERROR, "Key decrypt crypto operation failed: 0x%X", ret);
        goto cleanup;
    }

    unsealed_key = base64_encode(unsealed_key_buf, unsealed_key_buf_len);
    if (!unsealed_key) {
        ree_log(REE_ERROR, "Failed to base64 encode unsealed key");
        goto cleanup;
    }

    // build json with unsealed key: {“key”: “base64 encoded key”}
    j_response = json_object_new_object();
    if (!j_response) {
        ree_log(REE_ERROR, "Failed to create response json obj");
        goto cleanup;
    }
    j_unsealed_key = json_object_new_string(unsealed_key);
    if (!j_unsealed_key) {
        ree_log(REE_ERROR, "Failed to create json obj with unsealed key");
        goto cleanup;
    }
    json_object_object_add(j_response, FDE_JSON_KEY, j_unsealed_key);
    // ownership of j_unsealed_key has been taken by j_response
    j_unsealed_key =  NULL;
    result = json_object_to_json_string(j_response);
    set_result(result, strlen(result));

    cleanup:
        if (sealed_key_buf)
            free(sealed_key_buf);
        if (handle_buf)
            free(handle_buf);
        if (unsealed_key_buf)
            free(unsealed_key_buf);
        if (unsealed_key)
            free(unsealed_key);
        if (j_response)
            json_object_put(j_response);
        if (j_unsealed_key)
            json_object_put(j_unsealed_key);

        return ret;
}

int handle_operation_lock(void) {
    return lock_ta();
}

int handle_operation_setup(struct json_object *request_json) {
    int ret = EXIT_SUCCESS;
    struct json_object *j_key = NULL;
    struct json_object *j_key_name = NULL;
    struct json_object *j_response = NULL;
    struct json_object *j_handle = NULL;
    struct json_object *j_sealed_key = NULL;
    json_bool j_ret;
    unsigned char *unsealed_key_buf = NULL;
    unsigned char *sealed_key_buf = NULL;
    unsigned char *handle_buf = NULL;
    size_t unsealed_key_buf_len = 0;
    size_t sealed_key_buf_len = 0;
    size_t handle_buf_len = 0;
    char *sealed_key = NULL;
    char *handle = NULL;
    const char *result = NULL;

    // get other request data:
    // FDE_JSON_KEY | FDE_JSON_KEY_NAME
    j_ret = json_object_object_get_ex(request_json,
                                      FDE_JSON_KEY,
                                      &j_key);
    if ((j_ret != TRUE) ||
        ((json_type_string != json_object_get_type(j_key)))
       ) {
        ree_log(REE_ERROR, "request json is missing key[%d]", j_ret);
        ret = EXIT_FAILURE;
        goto cleanup;
    }
    unsealed_key_buf = base64_decode(json_object_get_string(j_key),
                                      strlen(json_object_get_string(j_key)),
                                      &unsealed_key_buf_len);
    if (!unsealed_key_buf) {
        ree_log(REE_ERROR, "failed to decode unsealed key");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    j_ret = json_object_object_get_ex(request_json,
                                      FDE_JSON_KEY_NAME,
                                      &j_key_name);

    if ((j_ret != TRUE) ||
        (json_type_string != json_object_get_type(j_key_name))
       ) {
        ree_log(REE_ERROR, "key name json malformed[%d]", j_ret);
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    // encrypt key
    handle_buf_len = HANDLE_SIZE;
    handle_buf = (char *)malloc(HANDLE_SIZE);
    sealed_key_buf_len = MAX_BUF_SIZE;
    sealed_key_buf = (char *)malloc(MAX_BUF_SIZE);
    if (!sealed_key_buf) {
        ree_log(REE_ERROR, "sealed_key buf alloc failed");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    ret = encrypt_key(unsealed_key_buf,
                      unsealed_key_buf_len,
                      handle_buf,
                      &handle_buf_len,
                      sealed_key_buf,
                      &sealed_key_buf_len);

    if (ret) {
        ree_log(REE_ERROR, "Key encrypt crypto operation failed: 0x%X", ret);
        goto cleanup;
    }

    // encode sealed key with base64
    sealed_key = base64_encode(sealed_key_buf, sealed_key_buf_len);
    if (!sealed_key) {
        ree_log(REE_ERROR, "Failed to base64 encode sealed key");
        goto cleanup;
    }

    // create response
    j_response = json_object_new_object();
    if (!j_response) {
        ree_log(REE_ERROR, "Failed to create response json obj");
        goto cleanup;
    }
    j_sealed_key = json_object_new_string(sealed_key);
    if (!j_sealed_key) {
        ree_log(REE_ERROR, "Failed to create json obj with sealed key");
        goto cleanup;
    }
    json_object_object_add(j_response, FDE_JSON_SEALED_KEY, j_sealed_key);
    // ownership of j_sealed_key has been taken by j_response
    j_sealed_key =  NULL;

    handle = base64_encode(handle_buf, handle_buf_len);
    if (!handle) {
        ree_log(REE_ERROR, "Failed to base64 encode key handle");
        goto cleanup;
    }
    j_handle = json_object_new_string(handle);
    if (!j_handle) {
        ree_log(REE_ERROR, "Failed to create json obj with key handle");
        goto cleanup;
    }
    json_object_object_add(j_response, FDE_JSON_HANDLE, j_handle);
    // ownership of j_sealed_key has been taken by j_handle
    j_handle =  NULL;
    result = json_object_to_json_string(j_response);

    // pass result back
    ret = set_result(result, strlen(result));

    cleanup:
        if (handle_buf)
            free(handle_buf);
        if (sealed_key_buf)
            free(sealed_key_buf);
        if (unsealed_key_buf)
            free(unsealed_key_buf);
        if (sealed_key)
            free(sealed_key);
        if (handle)
            free(handle);
        if (j_response)
            json_object_put(j_response);
        if (j_sealed_key)
            json_object_put(j_sealed_key);

        return ret;
}

int encrypt_decrypt_selftest() {
    int ret = EXIT_SUCCESS;
    unsigned char *key_buf = NULL;
    unsigned char *handle_buf = NULL;
    unsigned char *sealed_key_buf = NULL;
    unsigned char *unsealed_key_buf = NULL;
    size_t key_buf_len = 0;
    size_t handle_buf_len = 0;
    size_t sealed_key_buf_len = 0;
    size_t unsealed_key_buf_len = 0;
    char *base64_key = NULL;
    char *sealed_key = NULL;
    char *unsealed_key = NULL;

    key_buf_len = HANDLE_SIZE;
    key_buf = generate_rng(key_buf_len);
    if (!key_buf) {
        ree_log(REE_ERROR, "Failed to generate random key\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    base64_key = base64_encode(key_buf, key_buf_len);
    if (!base64_key) {
        ree_log(REE_ERROR, "Failed to encode generated key\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    } else {
        printf("Key: %s\n", base64_key);
    }

    // encrypt key
    handle_buf_len = HANDLE_SIZE;
    handle_buf = (char *)malloc(HANDLE_SIZE);
    sealed_key_buf_len = MAX_BUF_SIZE;
    sealed_key_buf = (char *)malloc(MAX_BUF_SIZE);
    if (!sealed_key_buf) {
        ree_log(REE_ERROR, "sealed_key buf alloc failed");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    ret = encrypt_key(key_buf,
                      key_buf_len,
                      handle_buf,
                      &handle_buf_len,
                      sealed_key_buf,
                      &sealed_key_buf_len);
    if (ret) {
        ree_log(REE_ERROR, "Key encrypt crypto operation failed: 0x%X", ret);
        goto cleanup;
    }

    // encode sealed key with base64
    sealed_key = base64_encode(sealed_key_buf, sealed_key_buf_len);
    if (!sealed_key) {
        ree_log(REE_ERROR, "Failed to encode sealed key");
        goto cleanup;
    } else {
        printf("Sealed Key: %s\n", sealed_key);
    }

    // call crypto operation
    unsealed_key_buf_len = MAX_BUF_SIZE;
    unsealed_key_buf = (unsigned char *)malloc(unsealed_key_buf_len);

    ret = decrypt_key(sealed_key_buf,
                      sealed_key_buf_len,
                      handle_buf,
                      handle_buf_len,
                      unsealed_key_buf,
                      &unsealed_key_buf_len);
    if (ret) {
        ree_log(REE_ERROR, "Key decrypt crypto operation failed: 0x%X", ret);
        goto cleanup;
    }

    unsealed_key = base64_encode(unsealed_key_buf, unsealed_key_buf_len);
    if (!unsealed_key) {
        ree_log(REE_ERROR, "Failed to encode unsealed key\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    } else {
        printf("Unsealed Key: %s\n", unsealed_key);
    }

    cleanup:
        if (key_buf)
            free(key_buf);
        if (base64_key)
            free(base64_key);
        if (handle_buf)
            free(handle_buf);
        if (sealed_key_buf)
            free(sealed_key_buf);
        if (unsealed_key_buf)
            free(unsealed_key_buf);
        if (sealed_key)
            free(sealed_key);
        if (unsealed_key)
            free(unsealed_key);

        return ret;
}

int handle_operation_feature(struct json_object *request_json) {
    // this operation is not supported, return default empty output
    return set_result(FDE_JSON_RESULT_FEATURES,
                                        strlen(FDE_JSON_RESULT_FEATURES));
}

int handle_fde_operation(char *request_str) {
    struct json_object *request_json;
    struct json_object *j_op;
    const char *op;
    json_bool j_ret;
    int ret = EXIT_SUCCESS;

    request_json = json_tokener_parse(request_str);
    if (!request_json) {
        ree_log(REE_ERROR, "Malformed json passed" );
        return EXIT_FAILURE;
    }
    j_ret = json_object_object_get_ex(request_json,
                                      FDE_JSON_OP,
                                      &j_op);
    if (j_ret == TRUE){
        op = json_object_get_string(j_op);
        // three operations are supported
        // - FDE_JSON_OP_REVEAL
        // - FDE_JSON_OP_LOCK
        // - FDE_JSON_OP_INITIAL_SETUP
        // - FDE_JSON_OP_FEATURES
        ree_log(REE_INFO, "Handling operation: %s\n", op);
        if (!strncmp(op, FDE_JSON_OP_REVEAL, strlen(FDE_JSON_OP_REVEAL))) {
            ret = handle_operation_reveal(request_json);
        } else if (!strncmp(op, FDE_JSON_OP_LOCK, strlen(FDE_JSON_OP_REVEAL))) {
            ret = handle_operation_lock();
        } else if (!strncmp(op, FDE_JSON_OP_INITIAL_SETUP, strlen(FDE_JSON_OP_INITIAL_SETUP))) {
            ret = handle_operation_setup(request_json);
        } else if (!strncmp(op, FDE_JSON_OP_FEATURES, strlen(FDE_JSON_OP_FEATURES))) {
            ret = handle_operation_feature(request_json);
        } else {
            ree_log(REE_ERROR, "Unknown operation requested:[%s]", op );
            ret = EXIT_FAILURE;
        }
    } else {
        ree_log(REE_ERROR, "json: parse: op failed");
    }
    json_object_put(request_json);
    return ret;
}

/**
 * There are two fde hooks, 'fde-reveal-key' and 'fde-setup'
 * 'fde-setup' hook can be called in 2 scenarios, as true snap hook
 * and as hook within initranfs. Depending on the runtime environment, hook
 * uses stdin/stdout or `snapctl` as way to retrieve input and pass the result.
 * `snapctl fde-setup-request` and `snapctl fde-setup-result` are used in snap hook
 * runtime environment.
 * Input and output are always passed as formated json.
 *
 * - 'fde-reveal-key':
 *   - supported operations:
 *     - reveal:
 *         - request: { "op": "reveal", "sealed-key": "base64-encoded-bytes",
 *                 "handle": "base64-encoded-bytes"}
 *         - result: {"key": "base64-encoded-bytes"}
 *     - lock:
 *         - request: { "op": "lock" }
 *         - result:
 *
 * - 'fde-setup':
 *   - supported operations:
 *     - fde-setup:
 *       - request: {"op": "initial-setup","key": "base64-encoded-bytes",
 *              "key-name" : "string"}
 *       - result: {"sealed-key": "base64-encoded-bytes",
 *               "handle": "base64-encoded-bytes"}
 *       - request: {"op":"features"}
 *       - result: {"features": []}
 */
int main(int argc, char *argv[]) {
    int ret = EXIT_SUCCESS;
    uint32_t lock;
    unsigned char *buf = NULL;
    char *base64_buf = NULL;
    char *baseName = NULL;
    char *request_str = NULL;
    size_t buf_len = 0;
    baseName = basename(argv[0]);
    ree_log(REE_INFO, "main: %s entry point", baseName);
    if (argc == 1) {
        // handle hook run scenarios
        // depending on hook type, we pass result on stdout or to snapctl
        if (!strncmp(baseName,
                              FDE_SETUP,
                              strlen(FDE_SETUP))) {
            // check if hook is running within initramfs or as a snap hook
            // there is not a perfect way to do this, but certain files should
            // only exist within initrd context
            if (access("/etc/initrd-release", F_OK) == 0) {
                request_str = get_initrd_fde_request();
                snapctl_output = 0;
            } else {
                request_str = get_snap_hook_fde_setup_request();
                snapctl_output = 1;
            }
        } else if (!strncmp(baseName,
                            FDE_REVEAL_KEY,
                            strlen(FDE_REVEAL_KEY))) {
            request_str = get_initrd_fde_request();
            snapctl_output = 0;
        } else {
            ree_log(REE_ERROR, "Unknown invocation" );
            print_help();
            exit(0);
        }
        if (request_str) {
            ret = handle_fde_operation(request_str);
            free(request_str);
        } else {
            ree_log(REE_ERROR, "main: empty request string");
            ret = EXIT_FAILURE;
        }
        // handle systemd bug when returning too fast can take down systempd, ups
        usleep(500000);
        return ret;
    }

    /**
     * handle test commands
     * supported operations:
     *  --ta-lock-status: get TA lock status
     *  --lock-ta: lock TA
     *  --generate-random: generate random number
     *  --enrypt-decrypt-selftest: encrypt and decrypt selftest
     *  --help: print help
     */
    if (!strcmp("--ta-lock-status", argv[1])) {
        ret = get_ta_lock(&lock);
        if(ret == TEEC_SUCCESS) {
            printf("Lock status: %s\n", lock ? "LOCKED":"UNLOCKED");
        } else {
            printf("TA operation fail, ret 0x%x\n", ret);
        }
    } else if (!strcmp("--lock-ta", argv[1])) {
        ret = lock_ta();
        if(ret == TEEC_SUCCESS) {
            printf("TA is now locked\n");
        } else {
            printf("TA operation fail, ret 0x%x\n", ret);
        }
    } else if (!strcmp("--generate-random", argv[1])) {
        // check if there is extra arg, which would be desired buf size
        if (argc > 2) {
          buf_len = atoi(argv[2]);
        } else {
          buf_len = HANDLE_SIZE;
        }
        buf = generate_rng(buf_len);
        if (!buf) {
            ree_log(REE_ERROR, "Failed to generate random buffer\n");
            ret = EXIT_FAILURE;
            goto cleanup;
        }
        base64_buf = base64_encode(buf, buf_len);
        if (!base64_buf) {
            ree_log(REE_ERROR, "Failed to encode generated random buffer\n");
            ret = EXIT_FAILURE;
        } else {
            printf("%s\n",base64_buf);
        }
    } else if (!strcmp("--encrypt-decrypt-selftest", argv[1])) {
        ret = encrypt_decrypt_selftest();
        if(ret != TEEC_SUCCESS) {
            printf("Failed to pass encrypt and decrypt selftest, ret 0x%x\n", ret);
        }
    } else if (!strcmp("--help", argv[1])) {
        print_help();
    } else {
        printf("error: NOT supported option(%s).\n", argv[1]);
        print_help();
        ret = EXIT_FAILURE;
    }

    cleanup:
      if (buf){
          free(buf);
      }
      if (base64_buf) {
          free(base64_buf);
      }
      return ret;
}
