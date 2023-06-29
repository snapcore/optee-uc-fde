/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2023, Canonical Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <tee_api_defines.h>
#include "tee_client_api.h"
#include <unistd.h>

#include <stdarg.h>

#include "base64.h"
#include "fde_key_handler_ta_type.h"

#include "fde_key_manager_ca.h"

// debug log definition
#define REE_LOG_LEVEL REE_DEBUG

#define MAX_BASE64_BUF_SIZE (MAX_BUF_SIZE / 3 * 4 + 4)
// helper wrapper around mbedtls_base64_encode function
char *base64_encode(const unsigned char *in_buf, size_t in_buf_len) {
    int ret = EXIT_SUCCESS;
    size_t base64_len;
    char *encoded_buffer = NULL;
    encoded_buffer = (char *)malloc(MAX_BASE64_BUF_SIZE);
    if (!encoded_buffer) {
        ree_log(REE_ERROR, "base64_encode failed to allock buffer");
        return NULL;
    }
    ret = mbedtls_base64_encode(encoded_buffer,
                              MAX_BASE64_BUF_SIZE,
                              &base64_len,
                              in_buf,
                              in_buf_len );
    if (ret) {
        ree_log(REE_ERROR, "base64_encode failed with: 0x%x", ret);
        free(encoded_buffer);
        encoded_buffer = NULL;
    }
    if (strlen(encoded_buffer) != base64_len) {
        ree_log(REE_ERROR, "base64_encode: string lengths do not align");
        free(encoded_buffer);
        encoded_buffer = NULL;
    }
    return encoded_buffer;
}

// helper wrapper around mbedtls_base64_decode function
unsigned char *base64_decode(const char *in_buf, size_t in_buf_len, size_t *buf_len) {
    int ret = EXIT_SUCCESS;
    char *decoded_buffer = NULL;
    if (strlen(in_buf) != in_buf_len) {
        ree_log(REE_ERROR, "base64_decode: string lengths do not align");
        return NULL;
    }
    decoded_buffer = (char *)malloc(MAX_BUF_SIZE);
    if (!decoded_buffer) {
        ree_log(REE_ERROR, "base64_decode failed allock fail");
        return NULL;
    }
    ret = mbedtls_base64_decode(decoded_buffer,
                                MAX_BUF_SIZE,
                                buf_len,
                                in_buf,
                                in_buf_len );
    if (ret) {
        ree_log(REE_ERROR, "base64_decode failed with: 0x%x", ret);
        free(decoded_buffer);
        decoded_buffer = NULL;
    }
    return decoded_buffer;
}

TEEC_Result invode_command(uint32_t cmd_id, TEEC_Operation *operation) {
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Result ret;
    TEEC_UUID svc_id = FDE_KEY_HANDLER_UUID_ID;
    uint32_t origin;

    ret = TEEC_InitializeContext(NULL, &context);
    if (ret != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InitializeContext fail, result=0x%x\n", ret);
        return ret;
    }

    ret = TEEC_OpenSession(&context, &session, &svc_id,
        TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (ret != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_OpenSession failed, result=0x%x, origin=0x%x\n", ret, origin);
        goto tag_exit_lock_ta_1;
    }

    ret = TEEC_InvokeCommand(&session, cmd_id, operation, &origin);
    if (ret != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InvokeCommand fail, result=0x%x, origin=0x%x\n", ret, origin);
    }

    TEEC_CloseSession(&session);
    tag_exit_lock_ta_1:
        TEEC_FinalizeContext(&context);
    return ret;
}

TEEC_Result encrypt_key(unsigned char *in_buf, size_t in_buf_len,
                        unsigned char *handle, size_t *handle_len,
                        unsigned char *out_buf, size_t *out_buf_len) {
    TEEC_Operation operation;
    TEEC_Result ret;
    memset(&operation, 0x0, sizeof(operation));
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_MEMREF_TEMP_OUTPUT,
                                            TEE_PARAM_TYPE_NONE);
    operation.params[0].tmpref.size = in_buf_len;
    operation.params[0].tmpref.buffer = in_buf;
    operation.params[1].tmpref.size = *handle_len;
    operation.params[1].tmpref.buffer = handle;
    operation.params[2].tmpref.size = *out_buf_len;
    operation.params[2].tmpref.buffer = out_buf;

    ret = invode_command(TA_CMD_KEY_ENCRYPT, &operation);
    if (ret == TEEC_SUCCESS) {
        *handle_len = operation.params[1].tmpref.size;
        *out_buf_len = operation.params[2].tmpref.size;
    }
    return ret;
}

TEEC_Result decrypt_key(unsigned char *in_buf, size_t in_buf_len,
                        unsigned char *handle, size_t handle_len,
                        unsigned char *out_buf, size_t *out_buf_len) {
    TEEC_Operation operation;
    TEEC_Result ret;
    memset(&operation, 0x0, sizeof(operation));
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_OUTPUT,
                                            TEE_PARAM_TYPE_NONE);
    operation.params[0].tmpref.size = in_buf_len;
    operation.params[0].tmpref.buffer = in_buf;
    operation.params[1].tmpref.size = handle_len;
    operation.params[1].tmpref.buffer = handle;
    operation.params[2].tmpref.size = *out_buf_len;
    operation.params[2].tmpref.buffer = out_buf;

    ret = invode_command(TA_CMD_KEY_DECRYPT, &operation);
    if (ret == TEEC_SUCCESS) {
        *out_buf_len = operation.params[2].tmpref.size;
    }
    return ret;
}

TEEC_Result get_ta_lock(uint32_t *value) {
    TEEC_Operation operation;
    TEEC_Result ret;

    memset(&operation, 0x0, sizeof(operation));
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE);

    ret = invode_command(TA_CMD_GET_LOCK, &operation);
    if (ret == TEEC_SUCCESS) {
        *value = operation.params[0].value.a;
    }
    return ret;
}

TEEC_Result lock_ta() {
    TEEC_Operation operation;

    memset(&operation, 0x0, sizeof(operation));
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE);

    return invode_command(TA_CMD_LOCK, &operation);
}

// generate random buffer
unsigned char *generate_rng(size_t len) {
    TEEC_Operation operation;
    TEEC_Result ret;
    unsigned char * buf = NULL;

    buf  = malloc(len);
    if (!buf){
        fprintf(stderr, "rng buf alloc failed\n");
        return NULL;
    }

    memset(&operation, 0x0, sizeof(operation));
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE);
    operation.params[0].tmpref.size = len;
    operation.params[0].tmpref.buffer = buf;
    ret = invode_command(TA_CMD_GEN_RANDOM, &operation);
    if (TEEC_SUCCESS != ret) {
        free(buf);
        return NULL;
    }
    return buf;
}

void ree_log(int log_level, const char *format, ...) {
    va_list args;
    char buf[2048];

    if(log_level > REE_LOG_LEVEL) {
        return;
    }
    va_start (args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    fprintf(stderr, "%s\n", buf);
}
