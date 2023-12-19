/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2023, Canonical Ltd.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <fde_key_handler_ta_type.h>

#define TA_UUID FDE_KEY_HANDLER_UUID_ID

#define TA_FLAGS                    (TA_FLAG_SINGLE_INSTANCE | \
                                     TA_FLAG_MULTI_SESSION | \
                                     TA_FLAG_DEVICE_ENUM | \
                                     TA_FLAG_INSTANCE_KEEP_ALIVE)
#define TA_STACK_SIZE               (4 * 1024)
#define TA_DATA_SIZE                (32 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
      "fde key handling via aes" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0100 } }

#endif /*USER_TA_HEADER_DEFINES_H*/
