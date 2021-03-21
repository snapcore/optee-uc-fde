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

#include "fde_key_handler_ta_type.h"

#include "fde_key_manager_ca.h"

// debug log definition
#define REE_LOG_LEVEL REE_DEBUG

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

TEEC_Result handle_key(uint32_t op,
                       unsigned char *in_buf, size_t in_buf_len,
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

    ret = invode_command(op, &operation);
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
