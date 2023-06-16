/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2023, Canonical Ltd.
 */

#include <tee_internal_api.h>
#include <trace.h>

#include "fde_key_handler_ta_type.h"
#include "fde_key_handler_ta_handle.h"

// TA lock status
static int _ta_lock;

static TEE_Result lock_ta( uint32_t param_types,
                           TEE_Param params[TEE_NUM_PARAMS]);
static TEE_Result get_ta_lock( uint32_t param_types,
                               TEE_Param params[TEE_NUM_PARAMS]);


TEE_Result TA_CreateEntryPoint(void) {
    DMSG("fde_key_handler: TA_CreateEntryPoint\n");
    _ta_lock = TA_UNLOCKED;
    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint( uint32_t paramTypes,
                               TEE_Param __maybe_unused params[TEE_NUM_PARAMS],
                               void __maybe_unused **sessionContext) {

    DMSG("fde_key_handler: TA_OpenSessionEntryPoint\n");
    UNUSED(paramTypes);
    UNUSED(params);
    UNUSED(sessionContext);
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint( void __maybe_unused *session_context) {
    DMSG("fde_key_handler: TA_CloseSessionEntryPoint\n");
    UNUSED(session_context);
}

void TA_DestroyEntryPoint(void) {
    DMSG("fde_key_handler: TA_DestroyEntryPoint\n");
}

TEE_Result TA_InvokeCommandEntryPoint( void __maybe_unused *session_context,
                                       uint32_t cmd_id,
                                       uint32_t paramTypes,
                                       TEE_Param params[TEE_NUM_PARAMS]) {

    DLOG("FDE cmd_id = %#"PRIx32"\n", cmd_id);
    switch (cmd_id) {
        case TA_CMD_KEY_ENCRYPT:
            return key_crypto(TEE_MODE_ENCRYPT, paramTypes, params);
        case TA_CMD_KEY_DECRYPT:
            // make sure crypto opperations are not locked
            if ( _ta_lock == TA_LOCKED) {
                EMSG("fde_key_handler: TA is locked for further decrypt oprerations!!");
                return TEE_ERROR_ACCESS_DENIED;
            }
            return key_crypto(TEE_MODE_DECRYPT, paramTypes, params);
        case TA_CMD_LOCK:
            return lock_ta(paramTypes, params);
        case TA_CMD_GET_LOCK:
            return get_ta_lock(paramTypes, params);
        case TA_CMD_GEN_RANDOM:
            return generate_random(paramTypes, params);
        default:
            EMSG("fde_key_handler: Command ID %#"PRIx32" is not supported", cmd_id);
            return TEE_ERROR_NOT_SUPPORTED;
    }
}

static TEE_Result lock_ta( uint32_t paramTypes,
                           TEE_Param params[TEE_NUM_PARAMS]) {

    UNUSED(params);
    if (paramTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    DMSG("fde_key_handler: Locking TA for further use\n");
    _ta_lock = TA_LOCKED;
    return TEE_SUCCESS;
}

static TEE_Result get_ta_lock( uint32_t paramTypes,
                               TEE_Param params[TEE_NUM_PARAMS]) {

    if (paramTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    params[0].value.a = _ta_lock;
    return TEE_SUCCESS;
}
