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
