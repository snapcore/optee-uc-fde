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

#ifndef FDE_KEY_MANAGER_H_
#define FDE_KEY_MANAGER_H_

extern TEEC_Result handle_key(uint32_t op,
                       unsigned char *in_buf, size_t in_buf_len,
                       unsigned char *handle, size_t handle_len,
                       unsigned char *out_buf, size_t *out_buf_len);
extern TEEC_Result lock_ta();
extern TEEC_Result get_ta_lock(uint32_t *value);
extern unsigned char *generate_rng(size_t buf_len);

// ree_log helper wrapper
#define REE_ERROR   1
#define REE_WARNING 2
#define REE_INFO    3
#define REE_DEBUG   4
extern void ree_log(int log_level, const char *format, ...);
#endif // FDE_KEY_MANAGER_H_
