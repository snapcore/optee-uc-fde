/**
 * Copyright (C) 2021 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>

#include <tee_client_api.h>
#include <tee_api_defines.h>

#include <json-c/json.h>

#include "base64.h"
#include "fde_key_handler_ta_type.h"
#include "fde_key_manager_ca.h"

#define MAX_JSON_BUF_SIZE   (1024 * 10)
#define MAX_BASE64_BUF_SIZE (MAX_BUF_SIZE / 3 * 4 + 4)
#define KEY_HANDLE_BUF_SIZE 32

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
#define FDE_JSON_SEALED_KEY_NAME   "sealed-key-name"
#define FDE_JSON_HANDLE            "handle"
#define FDE_JSON_RESULT_FEATURES   "{\"features\":[]}"

// helper wrapper around mbedtls_base64_encode function
char *basee64_encode(const unsigned char *in_buf, size_t in_buf_len) {
    int ret = EXIT_SUCCESS;
    size_t base64_len;
    char *encoded_buffer = NULL;
    encoded_buffer = (char *)malloc(MAX_BASE64_BUF_SIZE);
    if (!encoded_buffer) {
        ree_log(REE_ERROR, "basee64_encode failed to allock buffer");
        return NULL;
    }
    ret = mbedtls_base64_encode(encoded_buffer,
                              MAX_BASE64_BUF_SIZE,
                              &base64_len,
                              in_buf,
                              in_buf_len );
    if (ret) {
        ree_log(REE_ERROR, "basee64_encode failed with: 0x%x", ret);
        free(encoded_buffer);
        encoded_buffer = NULL;
    }
    if (strlen(encoded_buffer) != base64_len) {
        ree_log(REE_ERROR, "basee64_encode: string lengths do not align");
        free(encoded_buffer);
        encoded_buffer = NULL;
    }
    return encoded_buffer;
}

// helper wrapper around mbedtls_base64_decode function
unsigned char *basee64_decode(const char *in_buf, size_t in_buf_len, size_t *buf_len) {
    int ret = EXIT_SUCCESS;
    char *decoded_buffer = NULL;
    if (strlen(in_buf) != in_buf_len) {
        ree_log(REE_ERROR, "basee64_decode: string lengths do not align");
        return NULL;
    }
    decoded_buffer = (char *)malloc(MAX_BUF_SIZE);
    if (!decoded_buffer) {
        ree_log(REE_ERROR, "basee64_decode failed allock fail");
        return NULL;
    }
    ret = mbedtls_base64_decode(decoded_buffer,
                                MAX_BUF_SIZE,
                                buf_len,
                                in_buf,
                                in_buf_len );
    if (ret) {
        ree_log(REE_ERROR, "basee64_decode failed with: 0x%x", ret);
        free(decoded_buffer);
        decoded_buffer = NULL;
    }
    return decoded_buffer;
}

static void print_help(void)
{
    printf("This binary should be invoked only under specific context\n\n");
    printf("For testing purpose following out of context options are supported\n");
    printf("\t--ta-lock-status: get TA lock status\n");
    printf("\t--lock-ta: lock TA for any crypto operation till next reboot\n");
    printf("\t--generate-random [len in bytes]: generate random buffer and print it coded in base64\n");
    printf("\t\tby default 128bytes buffer is generated unless size is passed\n");
}

char *get_fde_setup_request() {
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

int set_fde_setup_request_result(const unsigned char * result, int len) {
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

char *get_reveal_key_request() {
    size_t b_read = 0;
    size_t size_remaining;
    char *request = NULL;
    char *pos = NULL;

    ree_log(REE_DEBUG, "get_reveal_key_request");
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
    struct json_object *j_key_name = NULL;
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

    // get other request data:
    //   FDE_JSON_SEALED_KEY | FDE_JSON_SEALED_KEY_NAME | FDE_JSON_HANDLE
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
    sealed_key_buf = basee64_decode(json_object_get_string(j_key),
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
    handle_buf = basee64_decode(json_object_get_string(j_handle),
                               strlen(json_object_get_string(j_handle)),
                               &handle_buf_len);
    if (!handle_buf) {
           ree_log(REE_ERROR, "failed to decode key handle base64");
           ret = EXIT_FAILURE;
           goto cleanup;
    }

    j_ret = json_object_object_get_ex(request_json,
                                      FDE_JSON_SEALED_KEY_NAME,
                                      &j_key_name);
    if ((j_ret != TRUE)||
        (json_type_string != json_object_get_type(j_key_name))
       ) {
        ree_log(REE_ERROR, "sealed key name json malformed[%d]", j_ret);
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

    ret = handle_key(TA_CMD_KEY_DECRYPT,
                     sealed_key_buf,
                     sealed_key_buf_len,
                     handle_buf,
                     handle_buf_len,
                     unsealed_key_buf,
                     &unsealed_key_buf_len);
    if (ret) {
        ree_log(REE_ERROR, "Key decrypt crypto operation failed: 0x%X", ret);
        goto cleanup;
    }

    unsealed_key = basee64_encode(unsealed_key_buf, unsealed_key_buf_len);
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
    fprintf( stdout, "%s\n",json_object_to_json_string(j_response));

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

int handle_operation_lock() {
    return lock_ta();
}

int handle_operation_setup(struct json_object *request_json) {
    int ret = EXIT_SUCCESS;
    struct json_object *j_key = NULL;
    struct json_object *j_key_name = NULL;
    struct json_object *j_models = NULL;
    struct json_object *j_response = NULL;
    struct json_object *j_handle = NULL;
    struct json_object *j_sealed_key = NULL;
    json_bool j_ret;
    const char *key = NULL;
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
    // FDE_JSON_SEALED_KEY | FDE_JSON_SEALED_KEY_NAME | FDE_JSON_HANDLE
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
    unsealed_key_buf = basee64_decode(json_object_get_string(j_key),
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

    // generate handle
    handle_buf_len = KEY_HANDLE_BUF_SIZE;
    handle_buf = generate_rng(handle_buf_len);
    if (!handle_buf) {
        ree_log(REE_ERROR, "Failed to generate random handle");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    // encrypt key
    sealed_key_buf_len = MAX_BUF_SIZE;
    sealed_key_buf = (char *)malloc(MAX_BUF_SIZE);
    if (!sealed_key_buf) {
        ree_log(REE_ERROR, "sealed_key buf alloc failed");
        ret = EXIT_FAILURE;
        goto cleanup;
    }
    ret = handle_key(TA_CMD_KEY_ENCRYPT,
                     unsealed_key_buf,
                     unsealed_key_buf_len,
                     handle_buf,
                     handle_buf_len,
                     sealed_key_buf,
                     &sealed_key_buf_len);
    if (ret) {
        ree_log(REE_ERROR, "Key encrypt crypto operation failed: 0x%X", ret);
        goto cleanup;
    }

    // encode sealed key with base64
    sealed_key = basee64_encode(sealed_key_buf, sealed_key_buf_len);
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

    handle = basee64_encode(handle_buf, handle_buf_len);
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
    ret = set_fde_setup_request_result(result, strlen(result));

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

int handle_operation_feature(struct json_object *request_json) {
    // this operation is not supported, return default empty output
    return set_fde_setup_request_result(FDE_JSON_RESULT_FEATURES,
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
 * There are two main modes of operation, plus test mode.
 *   Currently there are two data formats, one is provisional
 * - invoked within initrd: executable 'fde-reveal-key'
 *   input is passed as json through stdin
 *   - supported operations:
 *     - reveal:
 *         - request: { "op": "reveal", "sealed-key": "base64-encoded-bytes",
 *                 "handle": "base64-encoded-bytes", "sealed-key-name": "string"}
 *         - result: {"key": "base64-encoded-bytes"}
 *     - lock:
 *         - request: { "op": "lock" }
 *         - result:
 *   result is passed as json through stdout
 * - invoked as hook: executable 'fde-setup'
 *   input is fetched as json by snapctl `fde-setup-request`
 *   result is passed by base64/json `snapctl fde-setup-result`
 *   - supported operations:
 *     - fde-setup:
 *       - request: {"op": "initial-setup","key": "base64-encoded-bytes",
 *              "key-name" : "string"}
 *       - result: {"encrypted-key": "base64-encoded-bytes",
 *               "handle": "base64-encoded-bytes"}
 */
int main(int argc, char *argv[]) {
    int ret = EXIT_SUCCESS;
    uint32_t lock;
    unsigned char *buf = NULL;
    char *base64_buf = NULL;
    char *request_str = NULL;
    size_t buf_len = 0;
    ree_log(REE_INFO, "main: entry point");
    if (argc == 1) {
        // handle hook run scenario
        if (!strncmp(basename(argv[0]),
                              FDE_SETUP,
                              strlen(FDE_SETUP))) {
            request_str = get_fde_setup_request();
        } else if (!strncmp(basename(argv[0]),
                            FDE_REVEAL_KEY,
                            strlen(FDE_REVEAL_KEY))) {
            request_str = get_reveal_key_request();
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
        return ret;
    }

    /**
     * handle test commands
     * supported operations:
     *  --ta-lock-status: get TA locl status
     *  --lock-ta: lock TA
     *  --generate-random: generate random number
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
          buf_len = KEY_HANDLE_BUF_SIZE;
        }
        buf = generate_rng(buf_len);
        if (!buf) {
            ree_log(REE_ERROR, "Failed to generate random buffer\n");
            ret = EXIT_FAILURE;
            goto cleanup;
        }
        base64_buf = basee64_encode(buf, buf_len);
        if (!base64_buf) {
            ree_log(REE_ERROR, "Failed to encode generated random buffer\n");
            ret = EXIT_FAILURE;
        } else {
            printf("%s\n",base64_buf);
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
