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
