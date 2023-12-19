/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2023, Canonical Ltd.
 */

#ifndef FDE_KEY_MANAGER_H_
#define FDE_KEY_MANAGER_H_

// helper wrapper around mbedtls_base64_encode function
extern char *base64_encode(const unsigned char *in_buf, size_t in_buf_len);
// helper wrapper around mbedtls_base64_decode function
extern unsigned char *base64_decode(const char *in_buf,
                                     size_t in_buf_len, size_t *buf_len);

extern TEEC_Result encrypt_key(unsigned char *in_buf, size_t in_buf_len,
                               unsigned char *handle, size_t *handle_len,
                               unsigned char *out_buf, size_t *out_buf_len);
extern TEEC_Result decrypt_key(unsigned char *in_buf, size_t in_buf_len,
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
