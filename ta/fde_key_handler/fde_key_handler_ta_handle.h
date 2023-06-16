/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2023, Canonical Ltd.
 */

#ifndef FDE_KEY_HANDLER_TA_HANDLE_H_
#define FDE_KEY_HANDLER_TA_HANDLE_H_

#define TA_UNLOCKED  0
#define TA_LOCKED    1

extern TEE_Result key_crypto( TEE_OperationMode mode,
                              unsigned int paramTypes,
                              TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result generate_random(uint32_t types,
                                  TEE_Param params[TEE_NUM_PARAMS]);
#endif
