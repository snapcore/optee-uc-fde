/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2023, Canonical Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>

#include <libcryptsetup.h>

#include <tee_client_api.h>
#include <tee_api_defines.h>

#include <json-c/json.h>

#include "fde_key_handler_ta_type.h"
#include "fde_key_manager_ca.h"

#define MAX_JSON_BUF_SIZE                 (1024 * 10)

#define FDE_JSON_TYPE                     "type"
#define FDE_JSON_TYPE_OPTEE               "optee-ta"
#define FDE_JSON_KEYSLOTS                 "keyslots"
#define FDE_JSON_SEALED_KEY               "sealed-key"
#define FDE_JSON_HANDLE                   "handle"
#define FDE_JSON_LABEL                    "label"

#define FDE_KEY_SIZE                      60
#define CRYPT_ACTIVATE_FLAG               0
#define CRYPT_SLOT_ID                     1
#define CRYPT_TOKEN_ID                    1
#define DEFAULT_CIPHER                    "aes"
#define DEFAULT_CIPHER_MODE               "xts-plain64"
#define DEFAULT_HASH                      "sha256"
#define DEFAULT_KEY_SIZE                  512
#define DEFAULT_SECTOR_SIZE               512

#define DEFAULT_LUKS2_ITER_TIME           2000
#define DEFAULT_LUKS2_MEMORY_KB           1048576
#define DEFAULT_LUKS2_PARALLEL_THREADS    4
#define DEFAULT_LUKS2_PBKDF               CRYPT_KDF_ARGON2I

#define MAX_CIPHER_LEN		              32
#define MAX_CIPHER_LEN_STR                "31"

#if !defined(TRUE)
  #define TRUE ((json_bool)1)
#endif
#if !defined(FALSE)
  #define FALSE ((json_bool)0)
#endif

static int opt_key_size                   = 0;
static int opt_sector_size                = 0;
int opt_disable_locks                     = 0;
static const char *opt_cipher             = NULL;
static const char *opt_hash               = DEFAULT_HASH;
static const char *opt_pbkdf              = DEFAULT_LUKS2_PBKDF;
static long opt_pbkdf_memory              = DEFAULT_LUKS2_MEMORY_KB;
static long opt_pbkdf_parallel            = DEFAULT_LUKS2_PARALLEL_THREADS;
static long opt_pbkdf_iterations          = 0;
static long opt_iteration_time            = DEFAULT_LUKS2_ITER_TIME;
static uint64_t opt_luks2_metadata_size   = 0;
static uint64_t opt_luks2_keyslots_size   = 0;

enum Modes {unknown, automatic, manual};



/*
 * Device size string parsing, suffixes:
 * s|S - 512 bytes sectors
 * k  |K  |m  |M  |g  |G  |t  |T   - 1024 base
 * kiB|KiB|miB|MiB|giB|GiB|tiB|TiB - 1024 base
 * kb |KB |mM |MB |gB |GB |tB |TB  - 1000 base
 */
int tools_string_to_size(const char *s, uint64_t *size) {
	char *endp = NULL;
	size_t len;
	uint64_t mult_base, mult, tmp;

	*size = strtoull(s, &endp, 10);
	if (!isdigit(s[0]) ||
	    (errno == ERANGE && *size == ULLONG_MAX) ||
	    (errno != 0 && *size == 0))
		return -EINVAL;

	if (!endp || !*endp)
		return 0;

	len = strlen(endp);
	/* Allow "B" and "iB" suffixes */
	if (len > 3 ||
	   (len == 3 && (endp[1] != 'i' || endp[2] != 'B')) ||
	   (len == 2 && endp[1] != 'B'))
		return -EINVAL;

	if (len == 1 || len == 3)
		mult_base = 1024;
	else
		mult_base = 1000;

	mult = 1;
	switch (endp[0]) {
	case 's':
	case 'S': mult = 512;
		break;
	case 't':
	case 'T': mult *= mult_base;
		 /* Fall through */
	case 'g':
	case 'G': mult *= mult_base;
		 /* Fall through */
	case 'm':
	case 'M': mult *= mult_base;
		 /* Fall through */
	case 'k':
	case 'K': mult *= mult_base;
		break;
	default:
		return -EINVAL;
	}

	tmp = *size * mult;
	if (*size && (tmp / *size) != mult) {
		ree_log(REE_ERROR, "Device size overflow.");
		return -EINVAL;
	}

	*size = tmp;
	return 0;
}

int crypt_parse_name_and_mode(const char *s,
                              char *cipher,
			                  char *cipher_mode) {
	if (!s || !cipher || !cipher_mode)
		return -EINVAL;

	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]-%" MAX_CIPHER_LEN_STR "s",
		   cipher, cipher_mode) == 2) {
		if (!strcmp(cipher_mode, "plain"))
			strcpy(cipher_mode, DEFAULT_CIPHER_MODE);

		return 0;
	}

	/* Short version for "empty" cipher */
	if (!strcmp(s, "null") || !strcmp(s, "cipher_null")) {
		strcpy(cipher, "cipher_null");
		strcpy(cipher_mode, "ecb");
		return 0;
	}

	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]", cipher) == 1) {
		strcpy(cipher_mode, DEFAULT_CIPHER_MODE);
		return 0;
	}

	return -EINVAL;
}

static void print_help(void) {
    printf("Helper to self encrypt raw partition\n\n");
    printf("FDE helper encrypts defined device, seals the key and stores it in LUKS header token store.\n");
    printf("If device is already ecnrypted and there is sealed key in token store, device is unlocked instead.\n\n");
    printf("Usage:\n");
    printf("\t--help: invoke this help\n");
    printf("Required options:\n");
    printf("\t\t--device=<device path>            The device to be encrypted.\n");
    printf("\t\t--label=<mapper device label>     The mapper device lable to be used.\n");
    printf("\tOptional parameters\n");
    printf("\t\t--cipher=STRING                   The cipher used to encrypt the disk (see /proc/crypto).\n");
    printf("\t\t\tdefault: %s-%s\n", DEFAULT_CIPHER, DEFAULT_CIPHER_MODE);
    printf("\t\t--hash=STRING                     The hash used to create the encryption key from the passphrase\n");
    printf("\t\t\tdefault: %s\n", DEFAULT_HASH);
    printf("\t\t--key-size=BITS                   The size of the encryption key\n");
    printf("\t\t\tdefault: %d\n", DEFAULT_KEY_SIZE);
    printf("\t\t--sector-size=INT                 Encryption sector size\n");
    printf("\t\t\tdefault: %d\n", DEFAULT_SECTOR_SIZE);
    printf("\t\t--pbkdf=STRING                    PBKDF algorithm (for LUKS2): argon2i, argon2id, pbkdf2\n");
    printf("\t\t\tdefault: %s\n", DEFAULT_LUKS2_PBKDF);
    printf("\t\t--pbkdf-memory=kilobytes          PBKDF memory cost limit\n");
    printf("\t\t\tdefault: %d\n", DEFAULT_LUKS2_MEMORY_KB);
    printf("\t\t--pbkdf-parallel=threads          PBKDF parallel cost\n");
    printf("\t\t\tdefault: %d\n", DEFAULT_LUKS2_PARALLEL_THREADS);
    printf("\t\t--pbkdf-force-iterations=LONG     PBKDF iterations cost (forced, disables benchmark)\n");
    printf("\t\t--iter-time=msecs                 PBKDF iteration time for LUKS (in ms)\n");
    printf("\t\t\tdefault: %d\n", DEFAULT_LUKS2_ITER_TIME);
    printf("\t\t--luks2-metadata-size=bytes       LUKS2 header metadata area size\n");
    printf("\t\t--luks2-keyslots-size=bytes       LUKS2 header keyslots area size\n");
    printf("\n");
}

int store_sealed_key(struct crypt_device *cd, 
                     char* key,
                     int key_len,
                     int key_slot_id,
                     int token_id) {

    unsigned char *sealed_key_buf = NULL;
    unsigned char *handle_buf = NULL;
    char *sealed_key = NULL;
    char *handle = NULL;
    size_t sealed_key_buf_len = 0;
    size_t handle_buf_len = 0;
    char key_slot_str[5]; // int within quotes
    struct json_object *j_token = NULL;
    struct json_object *j_type = NULL;
    struct json_object *j_keyslots = NULL;
    struct json_object *j_keyslot_x = NULL;
    struct json_object *j_handle = NULL;
    struct json_object *j_sealed_key = NULL;
    const char *result = NULL;
    int ret;
    int token;

    // seal key before writting it to the token slot
    // encrypt key
    handle_buf_len = HANDLE_SIZE;
    handle_buf = (char *)malloc(HANDLE_SIZE);
    sealed_key_buf_len = MAX_BUF_SIZE;
    sealed_key_buf = (char *)malloc(MAX_BUF_SIZE);
    if (!sealed_key_buf) {
        ree_log(REE_ERROR, "sealed_key buf alloc failed");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    ret = encrypt_key(key,
                      key_len,
                      handle_buf,
                      &handle_buf_len,
                      sealed_key_buf,
                      &sealed_key_buf_len);

    if (ret) {
        ree_log(REE_ERROR, "Key encrypt crypto operation failed: 0x%X", ret);
        goto cleanup;
    }

    // write token to the free slot

    // create key token json object
    j_token = json_object_new_object();
    if (!j_token) {
        ree_log(REE_ERROR, "Failed to create key token json obj");
        goto cleanup;
    }

    j_type = json_object_new_string(FDE_JSON_TYPE_OPTEE);
    if (!j_type) {
        ree_log(REE_ERROR, "Failed to create json obj with type");
        goto cleanup;
    }
    json_object_object_add(j_token, FDE_JSON_TYPE, j_type);
    // ownership of j_type has been taken by j_response
    j_type =  NULL;

    j_keyslots = json_object_new_array ();
    if (!j_keyslots) {
        ree_log(REE_ERROR, "Failed to create json obj with keyslots");
        goto cleanup;
    }

    snprintf(key_slot_str, sizeof(key_slot_str), "%d", key_slot_id);
    j_keyslot_x = json_object_new_string(key_slot_str);
    if (!j_keyslot_x) {
        ree_log(REE_ERROR, "Failed to create json obj with keyslots 0");
        goto cleanup;
    }

    json_object_array_add(j_keyslots, j_keyslot_x);
    j_keyslot_x = NULL;

    json_object_object_add(j_token, FDE_JSON_KEYSLOTS, j_keyslots);
    // ownership of j_keyslots has been taken by j_response
    j_keyslots =  NULL;

    // encode sealed key with base64
    sealed_key = base64_encode(sealed_key_buf, sealed_key_buf_len);
    if (!sealed_key) {
        ree_log(REE_ERROR, "Failed to base64 encode sealed key");
        goto cleanup;
    }

    j_sealed_key = json_object_new_string(sealed_key);
    if (!j_sealed_key) {
        ree_log(REE_ERROR, "Failed to create json obj with sealed key");
        goto cleanup;
    }
    json_object_object_add(j_token, FDE_JSON_SEALED_KEY, j_sealed_key);
    // ownership of j_sealed_key has been taken by j_response
    j_sealed_key =  NULL;

    handle = base64_encode(handle_buf, handle_buf_len);
    if (!handle) {
        ree_log(REE_ERROR, "Failed to base64 encode key handle");
        goto cleanup;
    }
    j_handle = json_object_new_string(handle);
    if (!j_handle) {
        ree_log(REE_ERROR, "Failed to create json obj with key handle");
        goto cleanup;
    }
    json_object_object_add(j_token, FDE_JSON_HANDLE, j_handle);
    // ownership of j_sealed_key has been taken by j_handle
    j_handle =  NULL;
    result = json_object_to_json_string(j_token);

    // store token to the luks header, first clean desired token and ignore error(it's likely empty anyway)
    (void) crypt_token_json_set(cd, token_id, NULL);
    ret = crypt_token_json_set(cd, token_id, result);
    if (ret < 0) {
        ree_log(REE_ERROR, 
                "Failed to store sealed key token to the token slot %d, in LUKS header",
                token_id);
        goto cleanup;
    }
    token = ret;
    if (ret != token_id) {
        ree_log(REE_WARNING,
                "Other than desired token was used!!"); 
    }
    if (key_slot_id != CRYPT_ANY_SLOT) {
        ret = crypt_token_assign_keyslot(cd, token, key_slot_id);
        if (ret < 0) {
			ree_log(REE_WARNING, "Failed to assign token %d to keyslot %d.", token, key_slot_id);
            // we still carry on, as we use defined token and key slot, so we should handle this
			ret = 0;
		}
    }

    cleanup:
        if (sealed_key_buf)
            free(sealed_key_buf);
        if (sealed_key)
            free(sealed_key);
        if (handle_buf)
            free(handle_buf);
        if (handle)
            free(handle);
        if (j_type)
            json_object_put(j_type);
        if (j_keyslots)
            json_object_put(j_keyslots);
        if (j_keyslot_x)
            json_object_put(j_keyslot_x);
        if (j_handle)
            json_object_put(j_handle);
        if (j_sealed_key)
            json_object_put(j_sealed_key);
        if (j_token)
            json_object_put(j_token);
        return ret;
}

int unlock_volume(struct crypt_device *cd,
                  const char *label,
                  const char* key,
                  int key_len,
                  int key_slot_id,
                  uint32_t activate_flags) {
    int ret;

    // active mapper device
    ret = crypt_activate_by_passphrase(cd,
                                       label,
                                       key_slot_id,
                                       key,
                                       key_len,
                                       activate_flags);
    if (ret<0) {
        ree_log(REE_ERROR, "Failed to activate %d.", label);
        return ret;
    } else {
        // possitive number is unlocked key slot number
        ree_log(REE_INFO, "Key slot (%d) unlocked.", ret);
        return EXIT_SUCCESS;
    }
}

int unlock_from_token(struct crypt_device *cd,
                      int token_id,
                      const char *label,
                      uint32_t activate_flags) {
    const char *token;
    json_bool j_ret;
    int ret = EXIT_SUCCESS;
    struct json_object *j_token = NULL;
    struct json_object *j_sealed_key = NULL;
    struct json_object *j_handle = NULL;
    struct json_object *j_keyslots = NULL;
    struct json_object *j_keyslot_id = NULL;
    unsigned char *sealed_key_buf = NULL;
    unsigned char *handle_buf = NULL;
    unsigned char *unsealed_key_buf = NULL;
    size_t sealed_key_buf_len = 0;
    size_t handle_buf_len = 0;
    size_t unsealed_key_buf_len = 0;
    char *unsealed_key = NULL;
    int key_slot_id;

    ret = crypt_token_json_get(cd, token_id, &token);
    if (ret < 0) {
        ree_log(REE_ERROR, "Failed to get token %d from LUKS header.", token_id);
         return ret;
    }

    // extract sealed key and handle and slot id
    j_token = json_tokener_parse(token);
    if (!j_token) {
        ree_log(REE_ERROR, "Malformed token json from LUKS header" );
        return -1;
    }

    // get other request data:
    // FDE_JSON_SEALED_KEY | FDE_JSON_HANDLE
    j_ret = json_object_object_get_ex(j_token,
                                      FDE_JSON_SEALED_KEY,
                                      &j_sealed_key);
    if ((j_ret != TRUE) ||
        (json_type_string != json_object_get_type(j_sealed_key))
       ) {
        ree_log(REE_ERROR, "sealed key json malformed[%d]", j_ret);
        ret = EXIT_FAILURE;
        goto cleanup;
    }
    sealed_key_buf = base64_decode(json_object_get_string(j_sealed_key),
                                    strlen(json_object_get_string(j_sealed_key)),
                                    &sealed_key_buf_len);

    if (!sealed_key_buf){
        ree_log(REE_ERROR, "failed to decode sealed key from base64");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    j_ret = json_object_object_get_ex(j_token,
                                      FDE_JSON_HANDLE,
                                      &j_handle);
    if ((j_ret != TRUE) ||
        (json_type_string != json_object_get_type(j_handle))
       ) {
       ree_log(REE_ERROR, "handle json malformed[%d]", j_ret);
       ret = EXIT_FAILURE;
       goto cleanup;
    }
    handle_buf = base64_decode(json_object_get_string(j_handle),
                               strlen(json_object_get_string(j_handle)),
                               &handle_buf_len);
    if (!handle_buf) {
           ree_log(REE_ERROR, "failed to decode key handle base64");
           ret = EXIT_FAILURE;
           goto cleanup;
    }

    j_ret = json_object_object_get_ex(j_token,
                                      FDE_JSON_KEYSLOTS,
                                      &j_keyslots);
    if ((j_ret != TRUE) ||
        (json_type_array != json_object_get_type(j_keyslots))
       ) {
       ree_log(REE_ERROR, "keyslot json malformed[%d]", j_ret);
       ret = EXIT_FAILURE;
       goto cleanup;
    }
    if (!json_object_array_length(j_keyslots)) {
       ree_log(REE_ERROR, "keyslots arry is empty");
       ret = EXIT_FAILURE;
       goto cleanup;
    }
    // use first key slot id
    j_keyslot_id = json_object_array_get_idx(j_keyslots, 0);
    if ((j_keyslot_id == NULL) ||
        (json_type_string != json_object_get_type(j_keyslot_id))
       ) {
       ree_log(REE_ERROR, "keyslot id json malformed");
       ret = EXIT_FAILURE;
       goto cleanup;
    }
    
    // keyslot id is string, we need to get int
    key_slot_id = atoi(json_object_get_string(j_keyslot_id));

    // call crypto operation
    unsealed_key_buf_len = MAX_BUF_SIZE;
    unsealed_key_buf = (unsigned char *)malloc(unsealed_key_buf_len);
    if (!unsealed_key_buf){
        ree_log(REE_ERROR, "unsealed_key buf alloc failed");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    ret = decrypt_key(sealed_key_buf,
                      sealed_key_buf_len,
                      handle_buf,
                      handle_buf_len,
                      unsealed_key_buf,
                      &unsealed_key_buf_len);
    if (ret) {
        ree_log(REE_ERROR, "Key decrypt crypto operation failed: 0x%X", ret);
        goto cleanup;
    }

    // unlock
    ret = unlock_volume(cd,
                        label,
                        unsealed_key_buf,
                        unsealed_key_buf_len,
                        key_slot_id,
                        activate_flags);

    cleanup:
        if (sealed_key_buf)
            free(sealed_key_buf);
        if (handle_buf)
            free(handle_buf);
        if (unsealed_key_buf)
            free(unsealed_key_buf);
        if (unsealed_key)
            free(unsealed_key);

        return ret;
}

static int format_and_add_key(struct crypt_device *cd,
                              const char *label,
                              int key_slot_id,
                              int token_id,
                              uint32_t activate_flags) {
    unsigned char *key = NULL;
    size_t key_len = 0;
    int ret;
    int key_size = DEFAULT_KEY_SIZE/8;
    char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	struct crypt_pbkdf_type pbkdf = {
		.type = opt_pbkdf,
		.hash = opt_hash,
		.parallel_threads = opt_pbkdf_parallel,
		.max_memory_kb = (uint32_t)opt_pbkdf_memory,
        .time_ms = opt_iteration_time
	}, pbkdf_tmp;
	struct crypt_params_luks2 params = {
		.pbkdf = &pbkdf,
		.data_device = NULL,
		.sector_size = opt_sector_size ?:DEFAULT_SECTOR_SIZE
	};

	if (opt_pbkdf_iterations) {
		pbkdf.iterations = opt_pbkdf_iterations;
		pbkdf.flags |= CRYPT_PBKDF_NO_BENCHMARK;
	}
    if (opt_key_size) {
		key_size = opt_key_size / 8; // size is in bytes
    }
    // // set luks2 sizes if needed
	if (opt_luks2_keyslots_size || opt_luks2_metadata_size) {
		ret = crypt_set_metadata_size(cd, opt_luks2_metadata_size, opt_luks2_keyslots_size);
		if (ret < 0) {
			ree_log(REE_ERROR, "Unsupported LUKS2 metadata size options.");
			return ret;
		}
	}

    if (opt_cipher) {
        if (0 > crypt_parse_name_and_mode(opt_cipher, cipher, cipher_mode)) {
            ree_log(REE_ERROR, "No known cipher specification pattern detected.");
            return EXIT_FAILURE;
        }
    } else {
        // use default cipher and cipher mode
        strcpy(cipher, DEFAULT_CIPHER);
        strcpy(cipher_mode, DEFAULT_CIPHER_MODE);
    }

    ree_log(REE_INFO, "crypt_format....");
    /*
     * NULLs for uuid and volume_key means that these attributes will be
     * generated during crypt_format().
     */
    ret = crypt_format(cd,               /* crypt context */
                       CRYPT_LUKS2,      /* LUKS2 is a new LUKS format; use CRYPT_LUKS1 for LUKS1 */
                       cipher,       /* used cipher */
                       cipher_mode,  /* used block mode and IV */
                       NULL,             /* generate UUID */
                       NULL,             /* generate volume key from RNG */
                       key_size,         /* key size in bytes */
                       &params);         /* default parameters */
 
    if (ret < 0) {
        ree_log(REE_ERROR, "crypt_format() failed on device %s", crypt_get_device_name(cd));
        return ret;
    }

    ree_log(REE_INFO, "Device successfully crypt-formated");
 
    // generate new random key
    key_len = FDE_KEY_SIZE;
    key = generate_rng(key_len);

    /*
     * The device now contains a LUKS header, but there is no active keyslot.
     * crypt_keyslot_add_* call stores the volume_key in the encrypted form into the keyslot.
     * After format, the volume key is stored internally.
     */
    ret = crypt_keyslot_add_by_volume_key(cd,                 /* crypt context */
                                          key_slot_id,        /* use defined key slot */
                                          NULL,               /* use internal volume key */
                                          0,                  /* unused (size of volume key) */
                                          key,                /* passphrase - NULL means query*/
                                          key_len);           /* size of passphrase */

    if (ret < 0) {
            ree_log(REE_ERROR, "Adding keyslot failed.");
            return ret;
    }

    ree_log(REE_INFO, "Keyslot is initialized.");

    // store sealed key token
    store_sealed_key(cd, key, key_len, key_slot_id, token_id);

    // unlock the volume
    ret = unlock_volume(cd,
                        label,
                        key,
                        key_len,
                        key_slot_id,
                        activate_flags);

    cleanup:
        if (key)
            free(key);
        return ret;
}

int unlock_from_any_token(struct crypt_device *cd,
                          const char *label,
                          uint32_t activate_flags) {
    // int maxTokens = crypt_token_max(CRYPT_LUKS2);
    // ree_log(REE_ERROR, "maximum tokens %d.", maxTokens);
    return EXIT_SUCCESS;
}

int setup_block_device(const char *path,
                       const char *label) {

    struct crypt_device *cd;
    int ret;

    // initialize crypt_device context with device path
    ret = crypt_init(&cd, path);
    if (ret < 0) {
        ree_log(REE_ERROR, "crypt_init() failed for %s, ignoring.", path);
        return EXIT_SUCCESS;
    }
    ree_log(REE_INFO, "Context is attached to block device %s.", crypt_get_device_name(cd));

    // check if the device has LUKS setup
    ret = crypt_load(cd, CRYPT_LUKS, NULL);
    if (ret < 0) {
        ree_log(REE_INFO, "Device %s is not a valid LUKS device (%d)", crypt_get_device_name(cd), ret);
        ret = format_and_add_key(cd,
                                 label,
                                 CRYPT_SLOT_ID,
                                 CRYPT_TOKEN_ID,
                                 CRYPT_ACTIVATE_FLAG);
    } else {
        // unseal the key from token and unlock the volume
        ret =  unlock_from_token(cd,
                                 CRYPT_TOKEN_ID,
                                 label,
                                 CRYPT_ACTIVATE_FLAG);
        if (ret != 0) {
            // if we failed, try other tokens
            ret = unlock_from_any_token(cd,
                                        label,
                                        CRYPT_ACTIVATE_FLAG);
        }
    }
    crypt_free(cd);
    return ret;
}

/**
 * @brief Helper to setup encryption on block device
 *   Block device is formated and new encryption setup. FDE passphrase is sealed
 *   with Trusted Application and sealed key + handler is stored in
 *   LUKS header token slot.
 *   If block device has already encryption configured, it is unlocked instead
 *   using sealed key and handle stored in the LUKS header token slot
 */
int main(int argc, char *argv[]) {
    int ret = EXIT_SUCCESS;
    uint32_t lock;
    unsigned char *buf = NULL;
    char *base64_buf = NULL;
    char *request_str = NULL;
    size_t buf_len = 0;
    int opt = 0;
    int long_index =0;
    char *device;
    char *label;
    char *eptr;

    static struct option long_options[] = {
        // long name              | has argument  | flag | short value
        { "help",                   no_argument,       0, 'h'},
        { "device",                 required_argument, 0, 'd'},
        { "label",                  required_argument, 0, 'l'},
        { "hash",                   required_argument, 0, 'H'},
        { "cipher",                 required_argument, 0, 'c'},
        { "key-size",               required_argument, 0, 's'},
        { "sector-size",            required_argument, 0, 'S'},
        { "pbkdf",                  required_argument, 0, 'p'},
        { "pbkdf-memory",           required_argument, 0, 'm'},
        { "pbkdf-force-iterations", required_argument, 0, 'i'},
        { "iter-time",              required_argument, 0, 'I'},
        { "pbkdf-parallel",         required_argument, 0, 'j'},
        { "luks2-metadata-size",    required_argument, 0, 'M'},
        { "luks2-keyslots-size",    required_argument, 0, 'K'},
        {0, 0, 0, 0 }
    };

    if (argc <= 1) {
        printf("Missing compulsory arguments.");
        print_help();
        exit(EXIT_FAILURE);
    }
    while ((opt = getopt_long(argc, argv, "", long_options, &long_index )) != -1) {
        switch (opt) {
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
                break;
            case 'd':
                if(!optarg) {
                    printf("Missing argument for %c option\n", opt);
                    print_help();
                    exit(EXIT_FAILURE);
                }
                device = optarg;
                break;
            case 'l':
                if(!optarg) {
                    printf("Missing argument for %c option\n", opt);
                    print_help();
                    exit(EXIT_FAILURE);
                }
                label = optarg;
                break;
            case 'H': // hash
                opt_hash = optarg;
                break;
            case 'c': // cipher
                opt_cipher = optarg;
                break;
            case 's': // key-size
                opt_key_size = atoi(optarg);
                break;
            case 'S': // sector-size
                opt_sector_size = atoi(optarg);
                break;
            case 'p': // pbkdf
                opt_pbkdf = optarg;
                break;
            case 'm': // pbkdf-memory
                opt_pbkdf_memory = strtol(optarg, &eptr, 10);
                break;
            case 'i': // pbkdf-force-iterations
                opt_pbkdf_iterations = strtol(optarg, &eptr, 10);
                break;
            case 'I': // iter-time
                opt_iteration_time = strtol(optarg, &eptr, 10);
                break;
            case 'j': // pbkdf-parallel
                opt_pbkdf_parallel  = strtol(optarg, &eptr, 10);
                break;
            case 'M': // luks2-metadata-size
                if (tools_string_to_size(optarg, &opt_luks2_metadata_size)) {
                    printf("error: invalid value passed to --luks2-metadata-size (%s).\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'K': // luks2-keyslots-size
                if (tools_string_to_size(optarg, &opt_luks2_keyslots_size)) {
                    printf("error: invalid value passed to --luks2-keyslots-size (%s).\n", optarg);
                    exit(EXIT_FAILURE);      
                }
                break;
            default:
              printf("error: unsupported option(%c).\n", opt);
              print_help();
              exit(EXIT_FAILURE);
        }
    }
    // check we have minimal amount of options
    if (!device) {
        ree_log(REE_ERROR, "Missing label option");
        exit(EXIT_FAILURE);
    }
    return setup_block_device(device, label);
}
