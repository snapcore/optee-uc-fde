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

#include <assert.h>
#include <util.h>
#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <tee_internal_api_extensions.h>
#include <pta_system.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>

#include "fde_key_handler_ta_type.h"
#include "fde_key_handler_ta_handle.h"

#define IV_SIZE         16
#define NONCE_SIZE      32
#define TAG_SIZE        16

// Trusted Key Handle
struct key_handle {
    uint8_t iv[IV_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t tag[TAG_SIZE];
};

/**
 * Derive TA unique key
 * use passed handle as extra data for key derivation
 *  key: buffer to created key
 *  key_size: size of derived key buffer
 *  handle: buffer with handle
 *  handle_size: size handle buffer
 */
static TEE_Result derive_ta_unique_key(uint8_t *key,
                                       uint16_t key_size,
                                       uint8_t *handle,
                                       uint32_t handle_size) {

  TEE_TASessionHandle sess = TEE_HANDLE_NULL;
  TEE_Param params[TEE_NUM_PARAMS];
  TEE_Result res = TEE_ERROR_GENERIC;
  uint32_t ret_orig = 0;
  uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                         TEE_PARAM_TYPE_NONE,
                                         TEE_PARAM_TYPE_NONE);

  res = TEE_OpenTASession(&(const TEE_UUID)PTA_SYSTEM_UUID,
                          TEE_TIMEOUT_INFINITE,
                          0,
                          NULL,
                          &sess,
                          &ret_orig);
  if (res) {
    return res;
  }

  if (handle && handle_size) {
    params[0].memref.buffer = handle;
    params[0].memref.size = handle_size;
  }

  params[1].memref.buffer = key;
  params[1].memref.size = key_size;

  res = TEE_InvokeTACommand(sess,
                            TEE_TIMEOUT_INFINITE,
                            PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY,
                            param_types,
                            params,
                            &ret_orig);

  TEE_CloseTASession(sess);

  return res;
}

static TEE_Result do_key_encrypt( TEE_OperationHandle crypto_op,
                                  uint8_t *key, uint32_t key_sz,
                                  uint8_t *enc_key, uint32_t *enc_key_sz,
                                  struct key_handle *handle) {

    TEE_Result res = TEE_ERROR_GENERIC;
    uint32_t tag_len = TAG_SIZE;

    res = TEE_AEInit(crypto_op, handle->iv, IV_SIZE, TAG_SIZE * 8, 0, 0);
    if (res)
      return res;

    res = TEE_AEEncryptFinal(crypto_op, key, key_sz, enc_key,
                             enc_key_sz, handle->tag, &tag_len);
    if (res || tag_len != TAG_SIZE || *enc_key_sz != key_sz)
      return TEE_ERROR_SECURITY;

    return res;
}

static TEE_Result do_key_decrypt( TEE_OperationHandle crypto_op,
                                  uint8_t *enc_key, uint32_t enc_key_sz,
                                  uint8_t *key, uint32_t *key_sz,
                                  struct key_handle *handle) {

    TEE_Result res = TEE_ERROR_GENERIC;
    uint8_t tag[TAG_SIZE] = { 0 };

    res = TEE_AEInit(crypto_op, handle->iv, IV_SIZE, TAG_SIZE * 8, 0, 0);
    if (res)
      return res;

    memcpy(tag, handle->tag, TAG_SIZE);
    res = TEE_AEDecryptFinal(crypto_op, enc_key, enc_key_sz, key,
           key_sz, tag, TAG_SIZE);

    if (res || enc_key_sz != *key_sz)
      res = TEE_ERROR_SECURITY;

    return res;
}

static TEE_Result do_key_crypto( TEE_OperationMode mode,
                                 uint8_t *in, uint32_t in_size,
                                 uint8_t *out, uint32_t *out_size,
                                 struct key_handle *handle) {

    TEE_Result res = TEE_ERROR_GENERIC;
    TEE_OperationHandle crypto_op = TEE_HANDLE_NULL;
    TEE_ObjectHandle hkey = TEE_HANDLE_NULL;
    uint8_t huk_key[TA_DERIVED_KEY_MAX_SIZE] = { };
    TEE_Attribute attr = { };

    res = TEE_AllocateOperation(&crypto_op, TEE_ALG_AES_GCM, mode,
              sizeof(huk_key) * 8);
    if (res)
      return res;

    res = derive_ta_unique_key(huk_key, sizeof(huk_key), handle->nonce, sizeof(handle->nonce));
    if (res) {
      EMSG("derive_unique_key failed: returned %#"PRIx32, res);
      goto out_op;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, sizeof(huk_key) * 8,
              &hkey);
    if (res)
      goto out_op;

    attr.attributeID = TEE_ATTR_SECRET_VALUE;
    attr.content.ref.buffer = huk_key;
    attr.content.ref.length = sizeof(huk_key);

    if (TEE_PopulateTransientObject(hkey, &attr, 1)) {
      goto out_key;
    }

    if (TEE_SetOperationKey(crypto_op, hkey)) {
      goto out_key;
    }

    if (mode == TEE_MODE_ENCRYPT) {
      res = do_key_encrypt(crypto_op, in, in_size, out, out_size, handle);
    } else if (mode == TEE_MODE_DECRYPT) {
      res = do_key_decrypt(crypto_op, in, in_size, out, out_size, handle);
    } else {
      TEE_Panic(0);
    }
    if (res) {
      EMSG("do_key_*crypt failed: returned %#"PRIx32"\n", res);
    }

    out_key:
      TEE_FreeTransientObject(hkey);
    out_op:
      TEE_FreeOperation(crypto_op);
      memzero_explicit(huk_key, sizeof(huk_key));
    return res;
}

TEE_Result key_crypto( TEE_OperationMode mode,
                       unsigned int paramTypes,
                       TEE_Param params[TEE_NUM_PARAMS]) {

    TEE_Result res = TEE_SUCCESS;
    uint8_t *in = NULL;
    uint32_t in_size = 0;
    uint8_t *out = NULL;
    uint32_t out_size = 0;
    struct key_handle * handle = NULL;
    uint8_t *handle_buf = NULL;
    uint32_t handle_buf_size = 0;

    DMSG("Handle key crypto");

    if (mode == TEE_MODE_ENCRYPT) {
      if (paramTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    } else if (mode == TEE_MODE_DECRYPT) {
      if (paramTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    } else {
      return TEE_ERROR_BAD_PARAMETERS;
    }

    in = params[0].memref.buffer;
    in_size = params[0].memref.size;
    handle_buf = params[1].memref.buffer;
    handle_buf_size = params[1].memref.size;
    out = params[2].memref.buffer;
    out_size = params[2].memref.size;

    if ((!in && in_size) || in_size > MAX_BUF_SIZE) {
      return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((!out && out_size) || out_size > MAX_BUF_SIZE) {
      return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((!handle_buf && handle_buf_size) || handle_buf_size != sizeof(struct key_handle)) {
      return TEE_ERROR_BAD_PARAMETERS;
    }

    handle = (struct key_handle *)handle_buf;
    // generate random iv and handle for encryption operation
    if (mode == TEE_MODE_ENCRYPT) {
      TEE_GenerateRandom(handle->nonce, NONCE_SIZE);
      TEE_GenerateRandom(handle->iv, IV_SIZE);
    }

    res = do_key_crypto(mode, in, in_size, out, &out_size, handle);
    if (res == TEE_SUCCESS) {
      // check size of output buffer, depending on op
      assert(out_size == in_size);
      params[2].memref.size = out_size;
      if (mode == TEE_MODE_ENCRYPT) {
        params[1].memref.size = sizeof(struct key_handle);
      }
    }
    return res;
}

TEE_Result generate_random( uint32_t types, TEE_Param params[TEE_NUM_PARAMS]) {
    uint8_t *rng_buf = NULL;

    DMSG("generate_random");

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE))
      return TEE_ERROR_BAD_PARAMETERS;

    if (!params[0].memref.buffer || !params[0].memref.size)
      return TEE_ERROR_BAD_PARAMETERS;

    rng_buf = TEE_Malloc(params[0].memref.size, TEE_MALLOC_FILL_ZERO);
    if (!rng_buf)
      return TEE_ERROR_OUT_OF_MEMORY;

    TEE_GenerateRandom(rng_buf, params[0].memref.size);
    memcpy(params[0].memref.buffer, rng_buf, params[0].memref.size);
    memzero_explicit(rng_buf, params[0].memref.size);

    TEE_Free(rng_buf);

    return TEE_SUCCESS;
}
