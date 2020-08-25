/*

Copyright 2019 Comcast Cable Communications Management, LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
SPDX-License-Identifier: Apache-2.0

*/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <spake2plus.h>


/*! \file spake2plus.c
 * SPAKE2+ library source code.
 * */

#ifdef __cplusplus
extern "C"
{
#endif

    const uint8_t prime256v1_M[] =
        {
            0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e,
            0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
            0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab,
            0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
            0x2f};
    const uint8_t prime256v1_N[] =
        {
            0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29,
            0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
            0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49,
            0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
            0x49};

    const uint8_t secp384r1_M[] =
        {
            0x03, 0x0f, 0xf0, 0x89, 0x5a, 0xe5, 0xeb, 0xf6,
            0x18, 0x70, 0x80, 0xa8, 0x2d, 0x82, 0xb4, 0x2e,
            0x27, 0x65, 0xe3, 0xb2, 0xf8, 0x74, 0x9c, 0x7e,
            0x05, 0xeb, 0xa3, 0x66, 0x43, 0x4b, 0x36, 0x3d,
            0x3d, 0xc3, 0x6f, 0x15, 0x31, 0x47, 0x39, 0x07,
            0x4d, 0x2e, 0xb8, 0x61, 0x3f, 0xce, 0xec, 0x28,
            0x53};
    const uint8_t secp384r1_N[] =
        {
            0x02, 0xc7, 0x2c, 0xf2, 0xe3, 0x90, 0x85, 0x3a,
            0x1c, 0x1c, 0x4a, 0xd8, 0x16, 0xa6, 0x2f, 0xd1,
            0x58, 0x24, 0xf5, 0x60, 0x78, 0x91, 0x8f, 0x43,
            0xf9, 0x22, 0xca, 0x21, 0x51, 0x8f, 0x9c, 0x54,
            0x3b, 0xb2, 0x52, 0xc5, 0x49, 0x02, 0x14, 0xcf,
            0x9a, 0xa3, 0xf0, 0xba, 0xab, 0x4b, 0x66, 0x5c,
            0x10};

    const uint8_t secp521r1_M[] =
        {
            0x02, 0x00, 0x3f, 0x06, 0xf3, 0x81, 0x31, 0xb2,
            0xba, 0x26, 0x00, 0x79, 0x1e, 0x82, 0x48, 0x8e,
            0x8d, 0x20, 0xab, 0x88, 0x9a, 0xf7, 0x53, 0xa4,
            0x18, 0x06, 0xc5, 0xdb, 0x18, 0xd3, 0x7d, 0x85,
            0x60, 0x8c, 0xfa, 0xe0, 0x6b, 0x82, 0xe4, 0xa7,
            0x2c, 0xd7, 0x44, 0xc7, 0x19, 0x19, 0x35, 0x62,
            0xa6, 0x53, 0xea, 0x1f, 0x11, 0x9e, 0xef, 0x93,
            0x56, 0x90, 0x7e, 0xdc, 0x9b, 0x56, 0x97, 0x99,
            0x62, 0xd7, 0xaa};
    const uint8_t secp521r1_N[] =
        {
            0x02, 0x00, 0xc7, 0x92, 0x4b, 0x9e, 0xc0, 0x17,
            0xf3, 0x09, 0x45, 0x62, 0x89, 0x43, 0x36, 0xa5,
            0x3c, 0x50, 0x16, 0x7b, 0xa8, 0xc5, 0x96, 0x38,
            0x76, 0x88, 0x05, 0x42, 0xbc, 0x66, 0x9e, 0x49,
            0x4b, 0x25, 0x32, 0xd7, 0x6c, 0x5b, 0x53, 0xdf,
            0xb3, 0x49, 0xfd, 0xf6, 0x91, 0x54, 0xb9, 0xe0,
            0x04, 0x8c, 0x58, 0xa4, 0x2e, 0x8e, 0xd0, 0x4c,
            0xef, 0x05, 0x2a, 0x3b, 0xc3, 0x49, 0xd9, 0x55,
            0x75, 0xcd, 0x25};

    const uint8_t ed25519_M[] =
        {
            0xd0, 0x48, 0x03, 0x2c, 0x6e, 0xa0, 0xb6, 0xd6,
            0x97, 0xdd, 0xc2, 0xe8, 0x6b, 0xda, 0x85, 0xa3,
            0x3a, 0xda, 0xc9, 0x20, 0xf1, 0xbf, 0x18, 0xe1,
            0xb0, 0xc6, 0xd1, 0x66, 0xa5, 0xce, 0xcd, 0xaf};
    const uint8_t ed25519_N[] =
        {
            0xd3, 0xbf, 0xb5, 0x18, 0xf4, 0x4f, 0x34, 0x30,
            0xf2, 0x9d, 0x0c, 0x92, 0xaf, 0x50, 0x38, 0x65,
            0xa1, 0xed, 0x32, 0x81, 0xdc, 0x69, 0xb3, 0x5d,
            0xd8, 0x68, 0xba, 0x85, 0xf8, 0x86, 0xc4, 0xab};

    const uint8_t ed448_M[] =
        {
            0xb6, 0x22, 0x10, 0x38, 0xa7, 0x75, 0xec, 0xd0,
            0x07, 0xa4, 0xe4, 0xdd, 0xe3, 0x9f, 0xd7, 0x6a,
            0xe9, 0x1d, 0x3c, 0xf0, 0xcc, 0x92, 0xbe, 0x8f,
            0x0c, 0x2f, 0xa6, 0xd6, 0xb6, 0x6f, 0x9a, 0x12,
            0x94, 0x2f, 0x5a, 0x92, 0x64, 0x61, 0x09, 0x15,
            0x22, 0x92, 0x46, 0x4f, 0x3e, 0x63, 0xd3, 0x54,
            0x70, 0x1c, 0x78, 0x48, 0xd9, 0xfc, 0x3b, 0x88,
            0x80};
    const uint8_t ed448_N[] =
        {
            0x60, 0x34, 0xc6, 0x5b, 0x66, 0xe4, 0xcd, 0x7a,
            0x49, 0xb0, 0xed, 0xec, 0x3e, 0x3c, 0x9c, 0xcc,
            0x45, 0x88, 0xaf, 0xd8, 0xcf, 0x32, 0x4e, 0x29,
            0xf0, 0xa8, 0x4a, 0x07, 0x25, 0x31, 0xc4, 0xdb,
            0xf9, 0x7f, 0xf9, 0xaf, 0x19, 0x5e, 0xd7, 0x14,
            0xa6, 0x89, 0x25, 0x1f, 0x08, 0xf8, 0xe0, 0x6e,
            0x2d, 0x1f, 0x24, 0xa0, 0xff, 0xc0, 0x14, 0x66,
            0x00};

    M_and_N_by_NID m_n_points_prime256v1 =
        {
            .nid = NID_X9_62_prime256v1,
            .M = prime256v1_M,
            .M_len = sizeof(prime256v1_M),
            .N = prime256v1_N,
            .N_len = sizeof(prime256v1_N),
            .generator = ""};

    M_and_N_by_NID m_n_points_secp384r1 =
        {
            .nid = NID_secp384r1,
            .M = secp384r1_M,
            .M_len = sizeof(secp384r1_M),
            .N = secp384r1_N,
            .N_len = sizeof(secp384r1_N),
            .generator = ""};

    M_and_N_by_NID m_n_points_secp521r1 =
        {
            .nid = NID_secp521r1,
            .M = secp521r1_M,
            .M_len = sizeof(secp521r1_M),
            .N = secp521r1_N,
            .N_len = sizeof(secp521r1_N),
            .generator = ""};

    M_and_N_by_NID *m_n_points[] =
        {
            &m_n_points_prime256v1,
            &m_n_points_secp384r1,
            &m_n_points_secp521r1};

    /* Wrapper for printf for optional debug output, optionally with printing a BIGNUM*/
    void spake2plus_printf_debug(int do_printf, FILE *stream, const BIGNUM *bn_to_be_printed, const char *fmt)
    {
        if (do_printf)
        {
            if (stream == NULL)
                stream = stdout;
            fprintf(stream, "%s", fmt);
            if (bn_to_be_printed != NULL)
            {
                BN_print_fp(stream, bn_to_be_printed);
                printf("\n");
            }
            ERR_print_errors_fp(stderr);
        }
    }

    /* Wrapper for printf for optional debug output, optionally with printing an EC_POINT*/
    int spake2plus_print_ec_point(int do_printf,
                                  FILE *stream,
                                  SPAKE2PLUS *instance,
                                  const EC_POINT *ec_to_be_printed,
                                  point_conversion_form_t form,
                                  const char *fmt)
    {
        int return_value = SPAKE2PLUS_OK;
        if (do_printf)
        {
            if (stream == NULL)
                stream = stdout;
            if (ec_to_be_printed != NULL)
            {
                BIGNUM *tmp = NULL;
                BN_CTX *ctx = NULL;
                if (NULL == (tmp = BN_secure_new()))
                {
                    spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                            "FATAL: Failed to allocate memory for BIGNUM in spake2plus_print_ec_point.\n");
                    return_value = (SPAKE2PLUS_OPENSSL_BN_SECURE_NEW_FAILED);
                    goto err;
                }
                if (NULL == (ctx = BN_CTX_secure_new()))
                {
                    spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                            "FATAL: Failed to allocate memory for BIGNUM in spake2plus_get_w0_w1_L.\n");
                    return_value = (SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED);
                    goto err;
                }
                BN_CTX_start(ctx);
                if (NULL == EC_POINT_point2bn(
                                instance->group,
                                ec_to_be_printed,
                                form,
                                tmp, ctx))
                {
                    spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                            "FATAL: Failed to convert EC point to a BIGNUM.\n");
                    return_value = (SPAKE2PLUS_EC_POINT_POINT2BN_FAILED);
                    goto err;
                }
                spake2plus_printf_debug(do_printf, stream, tmp, fmt);
            err:
                BN_CHECK_NULL_AND_FREE(tmp);
                BN_CTX_CHECK_NULL_AND_FREE(ctx);
            }
        }
        return (return_value);
    }

    void spake2plus_print_array(int do_printf, FILE *stream, const uint8_t *array, const size_t len)
    {
        size_t i = 0;
        if (stream == NULL)
            stream = stdout;
        if (do_printf)
        {
            fprintf(stream, "Length: %zu\n", len);
            for (i = 0; i < len; ++i)
                fprintf(stream, "%02hhX", array[i]);
            fprintf(stream, "\n");
        }
    }

    void spake2plus_set_ec_point_from_uncompressed(
        EC_GROUP *group,
        EC_POINT *point,
        uint8_t *uncompressed_point,
        size_t uncompressed_point_len)
    {
        BN_CTX *ctx = NULL;
        BIGNUM *x = NULL;
        BIGNUM *y = NULL;
        void *res_ptr = NULL;
        int res_ssl = 0;

        //Make use for these variables because they will be thrown out by optimizer in Release configuration
        (void)res_ssl;
        (void)res_ptr;

        assert(NULL != group);
        assert(NULL != point);
        assert(NULL != uncompressed_point);
        //check uncompressed format
        assert(0x04 == uncompressed_point[0]);

        ctx = BN_CTX_secure_new();
        assert(NULL != ctx);
        BN_CTX_start(ctx);
        x = BN_secure_new();
        y = BN_secure_new();
        assert(NULL != x);
        assert(NULL != y);

        res_ptr = BN_bin2bn(((unsigned char *)uncompressed_point) + 1,
                                 uncompressed_point_len / 2, x);
        assert(NULL != res_ptr);
        spake2plus_printf_debug(COMMON_DEBUG, stdout, x, "[COMMON_DEBUG]: x coordinate:\n");

        res_ptr = BN_bin2bn(((unsigned char *)uncompressed_point) + 1 + (uncompressed_point_len / 2),
                                 uncompressed_point_len / 2, y);
        assert(NULL != res_ptr);
        spake2plus_printf_debug(COMMON_DEBUG, stdout, y, "[COMMON_DEBUG]: y coordinate:\n");

        res_ssl = EC_POINT_SET_AFFINE_COORDINATES(group, point, x, y, ctx);
        assert(SPAKE2PLUS_OPENSSL_COMMON_OK == res_ssl);

        BN_CTX_CHECK_NULL_AND_FREE(ctx);
        BN_CHECK_NULL_AND_FREE(x);
        BN_CHECK_NULL_AND_FREE(y);
    }

    int spake2plus_check_password(uint8_t *pw, size_t pw_len)
    {
        int return_value = SPAKE2PLUS_OK;
        if (pw_len <= 0)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: password length should be 0.\n");
            return (SPAKE2PLUS_PW_WRONG_LEN);
        }
        if (NULL == pw)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: password is NULL.\n");
            return_value = SPAKE2PLUS_PW_IS_NULL;
        }
        return (return_value);
    }

    int spake2plus_mac_check_inputs(
        uint8_t *return_hash,
        size_t *return_hash_len,
        uint8_t *key,
        size_t key_len,
        uint8_t *message,
        size_t message_len,
        const EVP_MD *evp_md)
    {

        /* Input sanity checks */
        if (NULL == return_hash)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: no buffer for return_hash is provided.\n");
            return (SPAKE2PLUS_MAC_NULL_RETURN);
        }

        if (NULL == return_hash_len)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: no buffer for return_hash_len is provided.\n");
            return (SPAKE2PLUS_MAC_NULL_RETURN_LEN);
        }

        if (NULL == key)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: key is NULL pointer.\n");
            return (SPAKE2PLUS_MAC_NULL_KEY);
        }

        if ((EVP_MD_size(evp_md) / 2) != (int)key_len)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: key_len is not correct.\n");
            return (SPAKE2PLUS_MAC_WRONG_KEY_LEN);
        }

        if (NULL == message)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: message is NULL pointer.\n");
            return (SPAKE2PLUS_MAC_NULL_MSG);
        }

        if (0 == message_len)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: message_len is zero.\n");
            return (SPAKE2PLUS_MAC_ZERO_MSG_LEN);
        }
        return (SPAKE2PLUS_OK);
    }

    int spake2plus_cmac_aes_128_rfc4493(
        uint8_t *return_hash,
        size_t *return_hash_len,
        uint8_t *key,
        size_t key_len,
        uint8_t *message,
        size_t message_len,
        const EVP_MD *evp_md)
    {
        int return_value = SPAKE2PLUS_OK;
        CMAC_CTX *ctx = NULL;

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: CMAC-AES-128 function is used.\n");

        if (SPAKE2PLUS_OK != (return_value = spake2plus_mac_check_inputs(
                                  return_hash,
                                  return_hash_len,
                                  key,
                                  key_len,
                                  message,
                                  message_len,
                                  evp_md)))
            return (return_value);

        /* Algorithm itself */
        ctx = CMAC_CTX_new();
        if (NULL == ctx)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot create CMAC_CTX.\n");
            return_value = (SPAKE2PLUS_CMAC_NULL_CTX);
            goto spake2plus_cmac_aes_128_rfc4493_cleanup_point;
        }
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != CMAC_Init(ctx, key, SPAKE2PLUS_128_BIT_IN_BYTES, EVP_aes_128_cbc(), NULL))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: failed CMAC_Init.\n");
            return_value = (SPAKE2PLUS_CMAC_INIT_FAILED);
            goto spake2plus_cmac_aes_128_rfc4493_cleanup_point;
        }
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != CMAC_Update(ctx, message, message_len))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: failed CMAC_Update.\n");
            return_value = (SPAKE2PLUS_CMAC_UPDATE_FAILED);
            goto spake2plus_cmac_aes_128_rfc4493_cleanup_point;
        }
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != CMAC_Final(ctx, (unsigned char *)return_hash, return_hash_len))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: failed CMAC_Final.\n");
            return_value = (SPAKE2PLUS_CMAC_FINAL_FAILED);
            goto spake2plus_cmac_aes_128_rfc4493_cleanup_point;
        }
    spake2plus_cmac_aes_128_rfc4493_cleanup_point:
        CMAC_CTX_free(ctx);

        return (return_value);
    }

    int spake2plus_hmac_rfc2104(
        uint8_t *return_hash,
        size_t *return_hash_len,
        uint8_t *key,
        size_t key_len,
        uint8_t *message,
        size_t message_len,
        const EVP_MD *evp_md)
    {
        int return_value = SPAKE2PLUS_OK;

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: HMAC function is used.\n");

        if (SPAKE2PLUS_OK != (return_value = spake2plus_mac_check_inputs(
                                  return_hash,
                                  return_hash_len,
                                  key,
                                  key_len,
                                  message,
                                  message_len,
                                  evp_md)))
            return (return_value);

        if (NULL == evp_md)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Hash function is NULL for HMAC.\n");
            return (SPAKE2PLUS_HMAC_NULL_EVP_MD);
        }

        unsigned int return_hash_len_uint = 0;
        if (NULL == (HMAC(
                        evp_md,
                        key,
                        key_len,
                        (unsigned char *)message,
                        message_len,
                        (unsigned char *)return_hash,
                        &return_hash_len_uint)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: OpenSSL HMAC Failed.\n");
            return (SPAKE2PLUS_OPENSSL_HMAC_FAILED);
        }
        assert(sizeof(*return_hash_len) >= sizeof(return_hash_len_uint));
        *return_hash_len = return_hash_len_uint;
        return (return_value);
    }

    int spake2plus_get_mac_function_by_name(
        Spake2plus_MAC *mac_func,
        char *MAC_func_name)
    {
        assert(NULL != mac_func);
        *mac_func = NULL;
        if (NULL == MAC_func_name)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Function name for MAC is NULL.\n");
            return (SPAKE2PLUS_MAC_NULL_NAME);
        }
        if (0 == strcmp(MAC_func_name, SPAKE2PLUS_HMAC_SEARCH_NAME))
            *mac_func = spake2plus_hmac_rfc2104;
        if (0 == strcmp(MAC_func_name, SPAKE2PLUS_CMAC_SEARCH_NAME))
            *mac_func = spake2plus_cmac_aes_128_rfc4493;
        if (NULL == *mac_func)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: MAC function was not found for name.\n");
            return (SPAKE2PLUS_MAC_FUNC_NOT_FOUND);
        }
        else
            return (SPAKE2PLUS_OK);
    }

    int spake2plus_concatenate_arrays(uint8_t *target, size_t *index, uint8_t **arrays,
                                      const size_t *lengths, const size_t count)
    {
        size_t i = 0;
        void *check_pointer = NULL;
        assert(NULL != target);
        assert(NULL != index);
        assert(NULL != arrays);
        assert(NULL != lengths);
        (void)(check_pointer);
        if (1 == count)
        {
            check_pointer = memcpy(target + (*index),
                                   arrays[0],
                                   lengths[0]);
            assert(NULL != check_pointer);
            *index += lengths[0];
        }
        if (count > 1)
        {
            for (i = 0; i < count; ++i)
            {
                spake2plus_print_array(CONCATENATE_ARRAYS_DEBUG, NULL, arrays[i], lengths[i]);
                check_pointer = memcpy(target + (*index),
                                       lengths + i,
                                       sizeof(lengths[i]));
                assert(NULL != check_pointer);
                spake2plus_printf_debug(CONCATENATE_ARRAYS_DEBUG, NULL, NULL,
                                        "[CONCATENATE_ARRAYS_DEBUG]: after first memcpy\n");
                (*index) += sizeof(size_t);
                spake2plus_print_array(CONCATENATE_ARRAYS_DEBUG, NULL, target, (*index));
                check_pointer = memcpy(target + (*index),
                                       arrays[i],
                                       lengths[i]);
                assert(NULL != check_pointer);
                spake2plus_printf_debug(CONCATENATE_ARRAYS_DEBUG, NULL, NULL,
                                        "[CONCATENATE_ARRAYS_DEBUG]: after second memcpy\n");
                (*index) += lengths[i];
                spake2plus_print_array(CONCATENATE_ARRAYS_DEBUG, NULL, target, (*index));
            }
        }
        return (SPAKE2PLUS_OK);
    }

    int spake2plus_augment_password(
        uint8_t *pw_augmented,
        size_t *pw_augmented_len,
        uint8_t *pw,
        size_t pw_len,
        uint8_t *client_id,
        size_t client_id_len,
        uint8_t *server_id,
        size_t server_id_len)
    {
        uint8_t *pw_augmented_arrays[SPAKE2PLUS_PBKDF2_ARG_ARRAYS_COUNT];
        size_t pw_augmented_lengths[SPAKE2PLUS_PBKDF2_ARG_ARRAYS_COUNT];
        size_t pw_augmented_count_elements;
        size_t i = 0;
        int return_value = SPAKE2PLUS_OK;

        if ((NULL == pw_augmented) || (NULL == pw_augmented_len))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: No valid pointer provided for pw_augmented or pw_augmented.\n");
            return (SPAKE2PLUS_CLIENT_ID_DATA_ERROR);
        }
        *pw_augmented_len = 0;

        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_password(pw, pw_len)))
            return (return_value);
        pw_augmented_count_elements = 0;
        pw_augmented_arrays[pw_augmented_count_elements] = pw;
        pw_augmented_lengths[pw_augmented_count_elements] = pw_len;
        ++pw_augmented_count_elements;

        if ((client_id_len > 0) && (NULL != client_id))
        {
            pw_augmented_arrays[pw_augmented_count_elements] = client_id;
            pw_augmented_lengths[pw_augmented_count_elements] = client_id_len;
            ++pw_augmented_count_elements;
        }
        else if (((client_id_len > 0) && (NULL == client_id)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: client_id is NULL, but its length is non-zero.\n");
            return (SPAKE2PLUS_CLIENT_ID_DATA_ERROR);
        }

        if ((server_id_len > 0) && (NULL != server_id))
        {
            pw_augmented_arrays[pw_augmented_count_elements] = server_id;
            pw_augmented_lengths[pw_augmented_count_elements] = server_id_len;
            ++pw_augmented_count_elements;
        }
        else if ((server_id_len > 0) && (NULL == server_id))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: server_id is NULL, but its length is non-zero.\n");
            return (SPAKE2PLUS_SERVER_ID_DATA_ERROR);
        }

        for (i = pw_augmented_count_elements;
             i < (sizeof(pw_augmented_arrays) / sizeof(pw_augmented_arrays[0]));
             ++i)
        {
            pw_augmented_arrays[i] = NULL;
            pw_augmented_lengths[i] = 0;
        }

        for (i = 0; i < pw_augmented_count_elements; ++i)
        {
            spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                    "[CONCATENATE_ARRAYS_DEBUG]: pw_augmented_array[i]:\n");
            spake2plus_print_array(COMMON_DEBUG, NULL,
                                   pw_augmented_arrays[i], pw_augmented_lengths[i]);
        }
        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[CONCATENATE_ARRAYS_DEBUG]: before spake2plus_concatenate_arrays:\n");

        return (spake2plus_concatenate_arrays(
            pw_augmented,
            pw_augmented_len,
            pw_augmented_arrays,
            pw_augmented_lengths,
            pw_augmented_count_elements));
    }

    int spake2plus_get_group_points(
        SPAKE2PLUS *instance,
        int nid)
    {
        int return_value = SPAKE2PLUS_OK;
        BN_CTX *ctx = NULL;
        BIGNUM *M_N_x = NULL;
        size_t i;
        assert(nid);
        assert(NULL != instance);
        assert(NULL != instance->M);
        assert(NULL != instance->N);
        assert(NULL != instance->group);
        if (NULL == (ctx = BN_CTX_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to allocate memory for BIGNUM in spake2plus_get_w0_w1_L.\n");
            return_value = (SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED);
            goto err;
        }
        BN_CTX_start(ctx);

        for (i = 0; i < (sizeof(m_n_points) / sizeof(m_n_points[0])); ++i)
            if (m_n_points[i]->nid == nid)
            {
                if (NULL == (M_N_x = BN_secure_new()))
                {
                    spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                            "FATAL: Failed to allocate memory for BIGNUM M_N_x.\n");
                    return_value = (SPAKE2PLUS_OPENSSL_BN_SECURE_NEW_FAILED);
                    break;
                }
                if (NULL == BN_bin2bn(
                                (m_n_points[i]->M + 1),
                                (m_n_points[i]->M_len - 1),
                                M_N_x))
                {
                    spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                            "FATAL: Failed to convert M point coordinates from byte array to BIGNUMs.\n");
                    return_value = SPAKE2PLUS_BN2BIN_FAILED;
                    break;
                }
                if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_POINT_SET_COMPRESSED_COORDINATES(
                                                        instance->group,
                                                        instance->M,
                                                        M_N_x,
                                                        (int)(m_n_points[i]->M[0] & 1),
                                                        ctx))
                {
                    spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                            "FATAL: Failed to convert uint8_t* number to a EC_POINT for M.\n");
                    return_value = (SPAKE2PLUS_EC_POINT_SET_COORD_FAILED);
                    break;
                }
                if (NULL == BN_bin2bn(
                                (m_n_points[i]->N + 1),
                                (m_n_points[i]->N_len - 1),
                                M_N_x))
                {
                    spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                            "FATAL: Failed to convert N point coordinates from byte array to BIGNUMs.\n");
                    return_value = SPAKE2PLUS_BN2BIN_FAILED;
                    break;
                }
                if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_POINT_SET_COMPRESSED_COORDINATES(
                                                        instance->group,
                                                        instance->N,
                                                        M_N_x,
                                                        (int)(m_n_points[i]->N[0] & 1),
                                                        ctx))
                {
                    spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                            "FATAL: Failed to convert uint8_t* number to a EC_POINT for N.\n");
                    return_value = (SPAKE2PLUS_EC_POINT_SET_COORD_FAILED);
                    break;
                }
                return_value = SPAKE2PLUS_OK;

                spake2plus_print_ec_point(COMMON_DEBUG, NULL, instance, instance->M, POINT_CONVERSION_COMPRESSED,
                                          "[COMMON_DEBUG]:  below is point for M:\n");
                spake2plus_print_ec_point(COMMON_DEBUG, NULL, instance, instance->N, POINT_CONVERSION_COMPRESSED,
                                          "[COMMON_DEBUG]:  below is point for N:\n");
            }
    err:
        BN_CTX_CHECK_NULL_AND_FREE(ctx);
        BN_clear_free(M_N_x);

        return (return_value);
    }

    int spake2plus_openssl_init()
    {
        /* Load the human readable error strings for libcrypto */
        int return_value = SPAKE2PLUS_OPENSSL_COMMON_OK;
        ERR_load_crypto_strings();

        /* Load all digest and cipher algorithms */
        OpenSSL_add_all_algorithms();

        /* Load config file, and other important initialization */
        if (CONF_modules_load_file(NULL, "spake2plus",
                                   CONF_MFLAGS_IGNORE_MISSING_FILE) <= 0)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to load configuration file.\n");
            return (SPAKE2PLUS_OPENSSL_CONF_LOAD_ERROR);
        }

        /* Allocate memory for password and parties identities to be sent to PBKDF2 */
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != (return_value = CRYPTO_secure_malloc_init(SPAKE2PLUS_REQUIRED_HEAP_SIZE, SPAKE2PLUS_MIN_SIZE_TO_ALLOC)))
        {
            if (2 == return_value)
                spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                        "[COMMON_DEBUG]: CRYPTO_secure_malloc_init finished but the heap cannot be protected.");
            else if (0 == return_value)
                spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                        "[COMMON_DEBUG]: CRYPTO_secure_malloc_init could not initialize secure heap.");
            else
                spake2plus_printf_debug(COMMON_DEBUG, stderr, NULL,
                                        "[COMMON_DEBUG]: Unexpected error during CRYPTO_secure_malloc_init.\n");
        }
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != CRYPTO_secure_malloc_initialized())
        {
            spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                    "[COMMON_DEBUG]: CRYPTO_secure_malloc_init has not yet initialized secure heap, another check comes in a few moments.");
            if (SPAKE2PLUS_OPENSSL_COMMON_OK != CRYPTO_secure_malloc_initialized())
            {
                spake2plus_printf_debug(COMMON_DEBUG, stderr, NULL,
                                        "[COMMON_DEBUG]: WARNING: Secure heap has not been initialized. Ordinary heap will be used.\n");
            }
        }

        return (SPAKE2PLUS_OK);
    }

    void spake2plus_openssl_cleanup()
    {

        /* Removes all digests and ciphers */
        EVP_cleanup();

        /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
        CRYPTO_cleanup_all_ex_data();

        /* Remove error strings */
        ERR_free_strings();

        /* OpenSSL deinitialize and cleanup*/
        OPENSSL_cleanup();

        if (SPAKE2PLUS_OPENSSL_COMMON_OK != CRYPTO_secure_malloc_done())
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot release secure heap after OPENSSL_cleanup().\n");
        }

    }

    void spake2plus_free(SPAKE2PLUS *instance)
    {
        if (NULL != instance)
        {
            BN_CHECK_NULL_AND_FREE(instance->prime);
            BN_CHECK_NULL_AND_FREE(instance->cofactor);
            BN_CHECK_NULL_AND_FREE(instance->w0);
            BN_CHECK_NULL_AND_FREE(instance->w1);
            EC_POINT_CHECK_NULL_AND_FREE(instance->M);
            EC_POINT_CHECK_NULL_AND_FREE(instance->N);
            EC_POINT_CHECK_NULL_AND_FREE(instance->pA);
            EC_POINT_CHECK_NULL_AND_FREE(instance->pB);
            BN_CHECK_NULL_AND_FREE(instance->random_value);
            EC_GROUP_CHECK_NULL_AND_FREE(instance->group);
            EC_POINT_CHECK_NULL_AND_FREE(instance->L);
            OPENSSL_CHECK_NULL_AND_FREE(instance->AAD);
            OPENSSL_CHECK_NULL_AND_FREE(instance->idA);
            OPENSSL_CHECK_NULL_AND_FREE(instance->idB);
            OPENSSL_CHECK_NULL_AND_FREE(instance->KcAKcB);
            OPENSSL_CHECK_NULL_AND_FREE(instance);
        }
    }

    int spake2plus_get_w0_w1_L(SPAKE2PLUS *instance,
                               uint8_t *w0sw1s,
                               int keylen,
                               BN_CTX *ctx)
    {
        int return_value = SPAKE2PLUS_OK;
        BIGNUM* tmp = NULL;
        assert(NULL != instance);
        assert(NULL != w0sw1s);
        assert(NULL != ctx);
        assert((keylen > 0) && ((keylen % 2) == 0));
        assert(NULL != instance->w0);
        assert(NULL != instance->w1);
        assert(NULL != instance->prime);
        assert((SPAKE2PLUS_CLIENT == instance->client_server) ||
               (SPAKE2PLUS_SERVER == instance->client_server));

        if (NULL == (tmp = BN_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to allocate memory for BIGNUMs a and b.\n");
            return (SPAKE2PLUS_OPENSSL_BN_SECURE_NEW_FAILED);
        }
        BN_zero(tmp);
        if (NULL == (BN_bin2bn(w0sw1s, (keylen / 2), instance->w0)))
        {
            spake2plus_printf_debug(COMMON_DEBUG, stderr, NULL,
                                    "FATAL: error extracting w0s from w0s||w1s as a BIGNUM.\n");
            return_value = (SPAKE2PLUS_GET_W0S_FAILED);
            goto exit;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, instance->w0,
                                "[COMMON_DEBUG]: below is w0s:\n");

        if (NULL == (BN_bin2bn(w0sw1s + (keylen / 2), (keylen / 2), instance->w1)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: error extracting w1s from w0s||w1s as a BIGNUM.\n");
            return_value = (SPAKE2PLUS_GET_W1S_FAILED);
            goto exit;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, instance->w1,
                                "[COMMON_DEBUG]: below is w1s:\n");

        if (SPAKE2PLUS_OPENSSL_COMMON_OK != BN_mod(
                                                instance->w0, instance->w0, instance->prime, ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: could not calculate w0 = w0s mod p.\n");
            return_value = (SPAKE2PLUS_GET_W0_FAILED);
            goto exit;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, instance->w0,
                                "[COMMON_DEBUG]: below is w0:\n");

        if (SPAKE2PLUS_OPENSSL_COMMON_OK != BN_mod(
                                                instance->w1, instance->w1, instance->prime, ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: could not calculate w1 = w1s mod p.\n");
            return_value = (SPAKE2PLUS_GET_W1_FAILED);
            goto exit;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, instance->w1,
                                "[COMMON_DEBUG]: below is w1:\n");

        /* Value L=w1*generator is computed here to be stored on the server's part
     * ("B" according to the standard). */

        if (SPAKE2PLUS_SERVER == instance->client_server)
        {
            if (SPAKE2PLUS_OPENSSL_COMMON_OK != (EC_POINT_mul(
                                                    instance->group,
                                                    instance->L,
                                                    instance->w1,
                                                    instance->L, tmp, ctx)))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                        "FATAL: Failed to calculate L.\n");
                return_value = (SPAKE2PLUS_GET_L_FAILED);
                goto exit;
            }

            if (SPAKE2PLUS_OK != (return_value = spake2plus_print_ec_point(
                                      COMMON_DEBUG, NULL, instance, instance->L,
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      "[COMMON_DEBUG]: below is L:\n")))
                goto exit;
        }
    exit:
        BN_CHECK_NULL_AND_FREE(tmp);
        return (return_value);
    }

    int spake2plus_get_group_data_by_group(SPAKE2PLUS *instance,
                                           EC_GROUP *group,
                                           BN_CTX *ctx)
    {
        int return_value = SPAKE2PLUS_OK;
        BIGNUM *a = NULL;
        BIGNUM *b = NULL;
        assert(NULL != group);
        assert(NULL != ctx);
        assert(NULL != instance);
        assert(NULL != instance->prime);
        assert(NULL != instance->cofactor);

        if ((NULL == (a = BN_secure_new())) || (NULL == (b = BN_secure_new())))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to allocate memory for BIGNUMs a and b.\n");
            return_value = (SPAKE2PLUS_OPENSSL_BN_SECURE_NEW_FAILED);
            goto spake2plus_get_group_data_exit;
        }
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_GROUP_GET_CURVE(group, instance->prime, a, b, ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot determine elliptic curve group parameters.\n");
            return_value = (SPAKE2PLUS_EC_GROUP_GET_CURVE_FAILED);
            goto spake2plus_get_group_data_exit;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, instance->prime,
                                "[COMMON_DEBUG]: below is prime (p according to the standard):\n");
        spake2plus_printf_debug(COMMON_DEBUG, NULL, a,
                                "[COMMON_DEBUG]: below is parameter a of the elliptic curve:\n");
        spake2plus_printf_debug(COMMON_DEBUG, NULL, b,
                                "[COMMON_DEBUG]: below is parameter b of the elliptic curve:\n");

        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_GROUP_get_cofactor(group, instance->cofactor, ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot get the cofactor.\n");
            return_value = (SPAKE2PLUS_EC_GROUP_GET_COFACTOR_FAILED);
            goto spake2plus_get_group_data_exit;
        }
        spake2plus_printf_debug(COMMON_DEBUG, NULL, instance->cofactor,
                                "[COMMON_DEBUG]: below is cofactor (h according to the standard):\n");

        if (NULL == (instance->generator = EC_GROUP_get0_generator(group)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot get point for group generation.\n");
            return_value = (SPAKE2PLUS_EC_GROUP_GET0_GENERATOR_FAILED);
            goto spake2plus_get_group_data_exit;
        }

        spake2plus_print_ec_point(COMMON_DEBUG, NULL, instance, instance->generator,
                                  POINT_CONVERSION_UNCOMPRESSED,
                                  "[COMMON_DEBUG]: below is generator (P according to the standard):\n");

    spake2plus_get_group_data_exit:
        BN_CHECK_NULL_AND_FREE(a);
        BN_CHECK_NULL_AND_FREE(b);

        return (return_value);
    }
    int spake2plus_get_group_data(SPAKE2PLUS *instance,
                                  EC_GROUP *group,
                                  int nid,
                                  BN_CTX *ctx)
    {
        int return_value = SPAKE2PLUS_OK;

        assert(((NULL != group) || (NID_undef != nid)));
        assert(NULL != ctx);
        assert(NULL != instance);
        assert(NULL != instance->prime);
        assert(NULL != instance->cofactor);

        if (NULL != group)
        {
            return_value = (spake2plus_get_group_data_by_group(
                instance,
                group,
                ctx));
            if (SPAKE2PLUS_OK != return_value)
                return (return_value);
        }
        else
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot determine elliptic curve id.\n");
            return (return_value);
        }

        if (SPAKE2PLUS_OK != (return_value = spake2plus_get_group_points(
                                  instance,
                                  nid)))
            return (return_value);

        return (return_value);
    }

    int spake2plus_pwd_init(
        SPAKE2PLUS *instance,
        char *pw,
        size_t pw_len)
    {

        if (NULL == instance)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: NULL instance, cannot initialize.\n");
            return (SPAKE2PLUS_INSTANCE_IS_NULL);
        }

        int return_value = ~(SPAKE2PLUS_OK);
        uint8_t *pw_augmented = NULL;
        size_t pw_augmented_len = pw_len + ((instance->idA_len > 0) ? (instance->idA_len + sizeof(instance->idA_len)) : 0) + ((instance->idB_len > 0) ? (instance->idB_len + sizeof(instance->idB_len)) : 0) + (((instance->idA_len > 0) || (instance->idB_len > 0)) ? sizeof(pw_len) : 0);
        ;

        BN_CTX *ctx = NULL;
        int keylen = -1;
        uint8_t *w0sw1s = NULL;

        /* Input sanity checks */
        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_password((uint8_t *)pw, pw_len)))
            return (return_value);

        if (NULL == (pw_augmented = OPENSSL_secure_malloc(pw_augmented_len)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to allocate memory for augmented password data.\n");
            return_value = (SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED);
            goto spake2plus_pwd_init_exit;
        }

        if (SPAKE2PLUS_OK != (return_value = spake2plus_augment_password(
                                  pw_augmented,
                                  &pw_augmented_len,
                                  (uint8_t *)pw,
                                  pw_len,
                                  instance->idA,
                                  instance->idA_len,
                                  instance->idB,
                                  instance->idB_len)))
            goto spake2plus_pwd_init_exit;
        assert((NULL != pw_augmented));
        assert(0 != pw_augmented_len);
        spake2plus_print_array(COMMON_DEBUG, NULL, pw_augmented, pw_augmented_len);

        if (NULL == (ctx = BN_CTX_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot allocate enough memory.\n");
            return_value = (SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED);
            goto spake2plus_pwd_init_exit;
        }
        BN_CTX_start(ctx);

        /*int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                      const unsigned char *salt, int saltlen, int iter,
                      const EVP_MD *digest,
                      int keylen, unsigned char *KcAKcB);
     *
     * int iter >= 1000 according to rfc2898
     * saltlen >= 8 (bytes) (random part >= 8 bytes) according to rfc2898
     * */
        /* TODO add salt*/

        /* NIST.SP.800-56Ar3 suggest taking mod p of a hash
     * value that is 64 bits longer than that needed to represent p.
     * Since w0s||w1s is split into two, keylen below shows the minimal
     * recommended length*/
        keylen = 2 * (BN_num_bytes(instance->prime) + 8);

        /* w0sw1s should be split in two parts of similar length, */
        /* so let's make its length even if it is not*/
        keylen = ((keylen + 1) / 2) << 1;

        if (NULL == (w0sw1s = OPENSSL_secure_malloc(keylen)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: error allocating memory for result of PBKDF2.\n");
            return_value = (SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED);
            goto spake2plus_pwd_init_exit;
        }

        /* PKCS5_PBKDF2_HMAC returns 1 on success and 0 on fail */
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != PKCS5_PBKDF2_HMAC((char *)pw_augmented, pw_augmented_len, NULL, 0,
                                                              SPAKE2PLUS_PBDKF2_ITERATION_COUNT,
                                                              instance->evp_md,
                                                              keylen, w0sw1s))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: PBKDF2 function failed.\n");
            return_value = (SPAKE2PLUS_OPENSSL_PBKDF2_FAILED);
            goto spake2plus_pwd_init_exit;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: w0sw1s:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, w0sw1s, keylen);

        if (SPAKE2PLUS_OK != (return_value = spake2plus_get_w0_w1_L(
                                  instance,
                                  w0sw1s,
                                  keylen,
                                  ctx)))
            goto spake2plus_pwd_init_exit;

        /* Clean up */
    spake2plus_pwd_init_exit:
        BN_CTX_CHECK_NULL_AND_FREE(ctx);
        OPENSSL_CHECK_NULL_AND_FREE(w0sw1s);
        OPENSSL_CHECK_NULL_AND_FREE(pw_augmented);
        return (return_value);
    }

    int spake2plus_load_L_w0(
        SPAKE2PLUS *instance,
        uint8_t *pL,
        size_t pL_len,
        uint8_t *pw0,
        size_t pw0_len)
    {
        int return_value = SPAKE2PLUS_OK;
        BN_CTX *ctx = NULL;
        /* Sanity check */
        if (NULL == instance)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Spake2+ instance is NULL.\n");
            return (SPAKE2PLUS_INSTANCE_IS_NULL);
        }
        if ((NULL == pL) || (pL_len == 0))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: pL array is empty.\n");
            return (SPAKE2PLUS_PL_WRONG);
        }
        if ((NULL == pw0) || (pw0_len == 0))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: pw0 array is empty.\n");
            return (SPAKE2PLUS_PW0_WRONG);
        }

        if (NULL == (ctx = BN_CTX_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to create BN_CTX.\n");
            return (SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED);
        }
        BN_CTX_start(ctx);

        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_POINT_oct2point(instance->group, instance->L, pL, pL_len, ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to load pL value.\n");
            return_value = SPAKE2PLUS_PL_WRONG;
            goto err;
        }
        if (NULL == BN_bin2bn(pw0, pw0_len, instance->w0))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to load pw0 value.\n");
            return_value = SPAKE2PLUS_PW0_WRONG;
            goto err;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, instance->w0,
                                "[COMMON_DEBUG]: below is w0:\n");

        spake2plus_print_ec_point(COMMON_DEBUG, NULL, instance, instance->L,
                                  POINT_CONVERSION_UNCOMPRESSED,
                                  "[COMMON_DEBUG]: below is L:\n");

        if ((BN_is_zero(instance->w0)) || (BN_ucmp(instance->prime, instance->w0) <= 0))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Incorrect w0 value, should be between zero and prime, not including.\n");
            return_value = (SPAKE2PLUS_INCORRECT_W0);
            goto err;
        }

        if (SPAKE2PLUS_OPENSSL_COMMON_OK !=
            EC_POINT_is_on_curve(instance->group, instance->L, ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Incorrect L point is not on elliptic curve.\n");
            return_value = (SPAKE2PLUS_POINT_NOT_ON_EC);
            goto err;
        }

    err:
        BN_CTX_CHECK_NULL_AND_FREE(ctx);
        return (return_value);
    }

    int spake2plus_init(
        SPAKE2PLUS **instance,
        char *client_id,
        size_t client_id_len,
        char *server_id,
        size_t server_id_len,
        char *additional_authenticated_data,
        size_t additional_authenticated_data_len,
        char *group_name,
        char *evp_md_name,
        char *MAC_func_name,
        int client_or_server)
    {
        int return_value = ~(SPAKE2PLUS_OK);

        BN_CTX *ctx = NULL;
        EC_GROUP *group = NULL;
        Spake2plus_MAC mac_func = NULL;
        int nid = 0;
        const EVP_MD *evp_md = NULL;

        if (NULL == instance)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: NULL pointer to instance, cannot initialize.\n");
            return (SPAKE2PLUS_INSTANCE_IS_NULL);
        }
        *instance = NULL;

        /* Input sanity checks */
        if ((SPAKE2PLUS_SERVER != client_or_server) && (SPAKE2PLUS_CLIENT != client_or_server))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Client or server role is not specified.\n");
            return (SPAKE2PLUS_CLIENT_SERVER_UNEXPECTED);
        }
        if (NULL == group_name)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Elliptic curve group name is empty.\n");
            return (SPAKE2PLUS_EC_NULL_NAME);
        }

        if (NULL == evp_md_name)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: server_id is NULL, but its length is non-zero.\n");
            return (SPAKE2PLUS_HASH_NAME_IS_NULL);
        }

        evp_md = EVP_get_digestbyname(evp_md_name);
        if (NULL == evp_md)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Hash function is not set.\n");
            return (SPAKE2PLUS_HASH_NOT_SET);
        }

        if (SPAKE2PLUS_OK != (return_value = spake2plus_get_mac_function_by_name(
                                  &mac_func, MAC_func_name)))
            return (return_value);
        assert(NULL != mac_func);

        if ((NULL == additional_authenticated_data) && (additional_authenticated_data_len > 0))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: additional_authenticated_data is NULL, but its length is non-zero.\n");
            return (SPAKE2PLUS_AAD_DATA_ERROR);
        }
        if ((NULL == client_id) && (client_id_len > 0))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: client_id is NULL, but its length is non-zero.\n");
            return (SPAKE2PLUS_CLIENT_ID_DATA_ERROR);
        }

        if ((NULL == server_id) && (server_id_len > 0))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: server_id is NULL, but its length is non-zero.\n");
            return (SPAKE2PLUS_SERVER_ID_DATA_ERROR);
        }

        /* OpenSSL initialization */
        if (SPAKE2PLUS_OK != (return_value = spake2plus_openssl_init()))
            goto spake2plus_init_exit;

        nid = EC_curve_nist2nid(group_name);
        if (NID_undef == nid)
            nid = OBJ_txt2nid(group_name);
        else
            group = EC_GROUP_new_by_curve_name(nid);
        if ((NULL == group) || (NID_undef == nid))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot determine elliptic curve id.\n");
            return_value = (SPAKE2PLUS_EC_NOT_FOUND);
            goto spake2plus_init_exit;
        }

        /* SPAKE2+ instance initialization */
        if (NULL == (*instance = OPENSSL_secure_malloc(sizeof(SPAKE2PLUS))))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to allocate memory for SPAKE2+ instance.\n");
            return_value = (SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED);
            goto spake2plus_init_exit;
        }
        (*instance)->client_server = client_or_server;
        (*instance)->evp_md = evp_md;
        (*instance)->MAC_func = mac_func;
        (*instance)->AAD = NULL;
        (*instance)->AAD_len = additional_authenticated_data_len;
        (*instance)->idA = NULL;
        (*instance)->idB = NULL;
        memset((*instance)->Ke, 0, EVP_MAX_MD_SIZE);
        (*instance)->Ke_len = 0;
        (*instance)->KcAKcB_len = EVP_MD_size((*instance)->evp_md);
        (*instance)->group = EC_GROUP_new_by_curve_name(nid);
        (*instance)->L = EC_POINT_new((*instance)->group);
        (*instance)->idA_len = client_id_len;
        (*instance)->idB_len = server_id_len;
        (*instance)->cofactor = NULL;
        (*instance)->KcAKcB = NULL;
        (*instance)->prime = NULL;
        (*instance)->w0 = NULL;
        (*instance)->w1 = NULL;
        (*instance)->M = NULL;
        (*instance)->N = NULL;
        (*instance)->pA = NULL;
        (*instance)->pB = NULL;
        (*instance)->random_value = NULL;


        if (NULL == ((*instance)->KcAKcB = OPENSSL_secure_malloc((*instance)->KcAKcB_len)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot allocate memory for instance->KcAKcB.\n");
            return_value = SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED;
            goto spake2plus_init_exit;
        }

        if (NULL == ((*instance)->idA = OPENSSL_secure_malloc(client_id_len)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to allocate memory for client_id data.\n");
            return_value = (SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED);
            goto spake2plus_init_exit;
        }
        memcpy((*instance)->idA, client_id, client_id_len);
        assert((NULL != (*instance)->idA) || (0 == (*instance)->idA_len));

        if (NULL == ((*instance)->idB = OPENSSL_secure_malloc(server_id_len)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to allocate memory for server_id data.\n");
            return_value = (SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED);
            goto spake2plus_init_exit;
        }
        memcpy((*instance)->idB, server_id, server_id_len);
        assert((NULL != (*instance)->idB) || (0 == (*instance)->idB_len));

        if (NULL == ((*instance)->AAD = OPENSSL_secure_malloc((*instance)->AAD_len)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to allocate memory for additional authenticated data.\n");
            return_value = (SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED);
            goto spake2plus_init_exit;
        }
        memcpy((*instance)->AAD, additional_authenticated_data, (*instance)->AAD_len);
        assert((NULL != (*instance)->AAD) || (0 == (*instance)->AAD_len));

        if ((NULL == ((*instance)->prime = BN_secure_new())) || (NULL == ((*instance)->N = EC_POINT_new((*instance)->group))) || (NULL == ((*instance)->M = EC_POINT_new((*instance)->group))) || (NULL == ((*instance)->cofactor = BN_secure_new())) || (NULL == ((*instance)->w0 = BN_secure_new())) || (NULL == ((*instance)->w1 = BN_secure_new())) || (NULL == ((*instance)->pA = EC_POINT_new((*instance)->group))) || (NULL == ((*instance)->pB = EC_POINT_new((*instance)->group))) || (NULL == ((*instance)->random_value = BN_secure_new())))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to allocate memory for BIGNUMs prime, M, N, cofactor, w0, w1, pA,pB, random_value or L.\n");
            return_value = (SPAKE2PLUS_OPENSSL_BN_SECURE_NEW_FAILED);
            goto spake2plus_init_exit;
        }
        BN_zero((*instance)->w0);
        BN_zero((*instance)->w1);
        BN_zero((*instance)->random_value);

        if (NULL == (ctx = BN_CTX_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot allocate enough memory.\n");
            return_value = (SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED);
            goto spake2plus_init_exit;
        }
        BN_CTX_start(ctx);

        if (SPAKE2PLUS_OK != (return_value = spake2plus_get_group_data(
                                  (*instance),
                                  group,
                                  nid,
                                  ctx)))
            goto spake2plus_init_exit;

        /* Clean up */
    spake2plus_init_exit:
        BN_CTX_CHECK_NULL_AND_FREE(ctx);
        EC_GROUP_CHECK_NULL_AND_FREE(group);

        /* Below is for cleanup in case of fail. */
        if (SPAKE2PLUS_OK != return_value)
        {
            spake2plus_free(*instance);
            *instance = NULL;
        }

        return (return_value);
    }

    inline int spake2plus_choose_side(SPAKE2PLUS *instance,
                                      int choose_own)
    {
        return ((choose_own) ? (instance->client_server)
                             : ((SPAKE2PLUS_CLIENT == instance->client_server) ? SPAKE2PLUS_SERVER
                                                                               : ((SPAKE2PLUS_SERVER == instance->client_server) ? SPAKE2PLUS_CLIENT
                                                                                                                                 : SPAKE2PLUS_CLIENT_SERVER_UNDEFINED)));
    }

    EC_POINT **spake2plus_select_pointer_pA_pB(SPAKE2PLUS *instance,
                                               int choose_own)
    {
        assert(NULL != instance);
        assert(NULL != instance->pA);
        assert(NULL != instance->pB);
        assert((SPAKE2PLUS_CLIENT == instance->client_server) || (SPAKE2PLUS_SERVER == instance->client_server));
        return ((SPAKE2PLUS_CLIENT == spake2plus_choose_side(instance, choose_own)) ? &(instance->pA)
                                                                                    : ((SPAKE2PLUS_SERVER == spake2plus_choose_side(instance, choose_own)) ? &(instance->pB) : NULL));
    }

    inline EC_POINT *spake2plus_select_pA_pB(SPAKE2PLUS *instance,
                                             int choose_own)
    {
        return (*(spake2plus_select_pointer_pA_pB(instance, choose_own)));
    }

    EC_POINT *spake2plus_select_M_N(SPAKE2PLUS *instance,
                                    int choose_own)
    {
        assert(NULL != instance);
        assert(NULL != instance->M);
        assert(NULL != instance->N);
        assert((SPAKE2PLUS_CLIENT == instance->client_server) || (SPAKE2PLUS_SERVER == instance->client_server));
        return ((SPAKE2PLUS_CLIENT == spake2plus_choose_side(instance, choose_own)) ? instance->M
                                                                                    : ((SPAKE2PLUS_SERVER == spake2plus_choose_side(instance, choose_own)) ? instance->N : NULL));
    }

    int spake2plus_check_instance(SPAKE2PLUS *instance)
    {
        int return_value = SPAKE2PLUS_OK;
        if (NULL == instance)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: NULL instance was supplied.\n");
            return (SPAKE2PLUS_INSTANCE_IS_NULL);
        }
        if ((NULL == instance->prime) || (NULL == instance->cofactor) || (NULL == instance->w0) || (NULL == instance->w1) || (NULL == instance->M) || (NULL == instance->N) || (NULL == instance->pA) || (NULL == instance->pB) || (NULL == instance->random_value) || ((NULL == instance->AAD) && (0 != instance->AAD_len)) || ((NULL == instance->idA) && (0 != instance->idA_len)) || ((NULL == instance->idB) && (0 != instance->idB_len)) || (NULL == instance->MAC_func) || (NULL == instance->evp_md))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: At least one NULL field of instance was supplied.\n");
            return (SPAKE2PLUS_INSTANCE_IS_NULL);
        }

        if ((BN_is_zero(instance->w0)) || (1 > BN_ucmp(instance->prime, instance->w0)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, instance->w0,
                                    "FATAL: Incorrect w0 value, should be between zero and prime, not including.\n");
            return (SPAKE2PLUS_INCORRECT_W0);
        }
        if (SPAKE2PLUS_CLIENT == instance->client_server)
        {
            if ((BN_is_zero(instance->w1)) || (BN_ucmp(instance->prime, instance->w1) <= 0))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, instance->w1,
                                        "FATAL: Incorrect w1 value, should be between zero and prime, not including:\n");
                spake2plus_printf_debug(FATAL_DEBUG, stderr, instance->prime,
                                        "FATAL: Incorrect w1 value, should be between zero and prime, not including; prime is:\n");
                return (SPAKE2PLUS_INCORRECT_W1_OR_L);
            }
        }
        else
        {
            BN_CTX *ctx = NULL;

            if (NULL == (ctx = BN_CTX_secure_new()))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                        "FATAL: Cannot allocate memory for BN_CTX object.\n");
                return (SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED);
            }
            BN_CTX_start(ctx);

            if (SPAKE2PLUS_OPENSSL_COMMON_OK !=
                EC_POINT_is_on_curve(instance->group, instance->L, ctx))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                        "FATAL: Incorrect L value, should be on elliptic curve.\n");
                return_value = (SPAKE2PLUS_POINT_NOT_ON_EC);
                goto err;
            }
        err:
            BN_CTX_CHECK_NULL_AND_FREE(ctx);
        }

        return (return_value);
    }

    int spake2plus_generate_setup_protocol_values(
        SPAKE2PLUS *instance,
        BN_CTX *ctx)
    {
        EC_POINT *tmp = NULL;
        int is_X_identity = 1;
        int return_value = SPAKE2PLUS_OK;

        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_instance(instance)))
            return (return_value);

        do
        {
            if (SPAKE2PLUS_OPENSSL_COMMON_OK != BN_PRIV_RAND_RANGE(instance->random_value, instance->prime))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                        "FATAL: could not get random value.\n");
                return_value = (SPAKE2PLUS_BN_RAND_FAILED);
                break;
            }

            spake2plus_printf_debug(COMMON_DEBUG, NULL, instance->random_value,
                                    "[COMMON_DEBUG]: below is random_value:\n");

            if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_POINT_mul(
                                                    instance->group,
                                                    spake2plus_select_pA_pB(instance, 1),
                                                    instance->random_value,
                                                    spake2plus_select_M_N(instance, 1),
                                                    instance->w0,
                                                    ctx))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                        "FATAL: Failed to calculate setup key (pA or pB).\n");
                return_value = SPAKE2PLUS_BN_ARITHM_FAILED;
                break;
            }

            spake2plus_print_ec_point(COMMON_DEBUG, NULL, instance, spake2plus_select_pA_pB(instance, 1), POINT_CONVERSION_COMPRESSED,
                                      "[COMMON_DEBUG]: below is spake2plus_select_pA_pB(instance, 1):\n");

            if (NULL == (tmp = EC_POINT_dup(spake2plus_select_M_N(instance, 1), instance->group)))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                        "FATAL: Cannot create temporary EC_POINT.\n");
                return_value = (SPAKE2PLUS_OPENSSL_BN_SECURE_NEW_FAILED);
                break;
            }

            if (SPAKE2PLUS_OPENSSL_COMMON_OK !=
                EC_POINT_is_on_curve(instance->group, spake2plus_select_pA_pB(instance, 1), ctx))
            {
                spake2plus_print_ec_point(FATAL_DEBUG, stderr, instance,
                                          spake2plus_select_pA_pB(instance, 1),
                                          POINT_CONVERSION_UNCOMPRESSED,
                                          "FATAL: Obtained point is not on elliptic curve.\n");
                return_value = SPAKE2PLUS_POINT_NOT_ON_EC;
                break;
            }
            is_X_identity = EC_POINT_is_at_infinity(instance->group, spake2plus_select_pA_pB(instance, 1));

            if (is_X_identity)
                spake2plus_print_ec_point(COMMON_DEBUG, stdout, instance,
                                          spake2plus_select_pA_pB(instance, 1),
                                          POINT_CONVERSION_UNCOMPRESSED,
                                          "[COMMON_DEBUG]: Obtainted value is group identity:\n");
            else
                spake2plus_print_ec_point(COMMON_DEBUG, stdout, instance,
                                          spake2plus_select_pA_pB(instance, 1),
                                          POINT_CONVERSION_UNCOMPRESSED,
                                          "[COMMON_DEBUG]: Obtainted setup key that is not group identity:\n");
        } while (is_X_identity);

        EC_POINT_CHECK_NULL_AND_FREE(tmp);

        return (return_value);
    }

    int spake2plus_setup_protocol(
        SPAKE2PLUS *instance)
    {
        int return_value = SPAKE2PLUS_GENERAL_ERROR_CODE;
        BN_CTX *ctx = NULL;

        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_instance(instance)))
            return (return_value);

        if (BN_is_zero(instance->w0))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: w0 is zero, there was no password initialization.\n");
            return (SPAKE2PLUS_PASSWORD_NOT_INITIALIZED);
        }

        if (NULL == (ctx = BN_CTX_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot allocate memory for BN_CTX object.\n");
            return (SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED);
        }
        BN_CTX_start(ctx);

        if (SPAKE2PLUS_OK !=
            (return_value = spake2plus_generate_setup_protocol_values(
                 instance,
                 ctx)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to generate setup protocol value.\n");
            goto spake2plus_setup_protocol_exit;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, instance->random_value,
                                "[COMMON_DEBUG]: below is random_value:\n");

        spake2plus_print_ec_point(COMMON_DEBUG, NULL, instance,
                                  spake2plus_select_pA_pB(instance, 1),
                                  POINT_CONVERSION_UNCOMPRESSED,
                                  "[COMMON_DEBUG]: below is setup protocol value:\n");

    spake2plus_setup_protocol_exit:
        BN_CTX_CHECK_NULL_AND_FREE(ctx);
        return (return_value);
    }

    int spake2plus_get_own_pA_or_pB(
        uint8_t *pA_or_pB,
        size_t *pA_or_pB_len,
        SPAKE2PLUS *instance)
    {
        int return_value = SPAKE2PLUS_OK;
        BN_CTX *ctx = NULL;
        if (NULL == pA_or_pB_len)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: pA_or_pB_len is NULL pointer.\n");
            return (SPAKE2PLUS_PA_OR_PB_LEN_NULL_POINTER);
        }
        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_instance(instance)))
            return (return_value);
        if (NULL == spake2plus_select_pA_pB(instance, 1))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: pA or pB is NULL, SPAKE2+ setup value was not set up, call spake2plus_setup_protocol first.\n");
            return (SPAKE2PLUS_PA_OR_PB_IS_NULL);
        }
        if (EC_POINT_is_at_infinity(instance->group, spake2plus_select_pA_pB(instance, 1)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: pA or pB is group identity, SPAKE2+ setup value was not set up, call spake2plus_setup_protocol first.\n");
            return (SPAKE2PLUS_IS_GROUP_IDENTITY);
        }
        if (NULL == (ctx = BN_CTX_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to create BN_CTX.\n");
            return_value = SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED;
            goto exit;
        }
        BN_CTX_start(ctx);

        *pA_or_pB_len = EC_POINT_point2oct(instance->group,
                                           spake2plus_select_pA_pB(instance, 1),
                                           POINT_CONVERSION_UNCOMPRESSED,
                                           NULL,
                                           0, ctx);
        if (NULL == pA_or_pB)
            goto exit;

        if (*pA_or_pB_len != EC_POINT_point2oct(instance->group,
                                                spake2plus_select_pA_pB(instance, 1),
                                                POINT_CONVERSION_UNCOMPRESSED,
                                                (unsigned char *)pA_or_pB,
                                                *pA_or_pB_len, ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot convert EC_POINT to uint8_t*.\n");
            return_value = SPAKE2PLUS_EC_POINT_POINT2OCT_FAILED;
            goto exit;
        }
        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below is own pA or pB:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, pA_or_pB, *pA_or_pB_len);
    exit:
        BN_CTX_CHECK_NULL_AND_FREE(ctx);
        return (return_value);
    }

    int spake2plus_generate_keys_Z_V(
        EC_POINT *Z,
        EC_POINT *V,
        SPAKE2PLUS *instance,
        BN_CTX *ctx)
    {

        int return_value = SPAKE2PLUS_OK;
        EC_POINT *tmp_p = NULL;
        BIGNUM *tmp = NULL;
        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_instance(instance)))
            return (return_value);
        assert(NULL != Z);
        assert(NULL != V);
        assert(NULL != ctx);

        if (SPAKE2PLUS_OPENSSL_COMMON_OK == BN_is_zero(instance->random_value))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Random value is zero.\n");
            return (SPAKE2PLUS_ZERO_RANDOM_VAL);
        }

        if (NULL == (tmp = BN_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot create temporary BIGNUM.\n");
            return (SPAKE2PLUS_OPENSSL_BN_SECURE_NEW_FAILED);
        }

        if (NULL == (tmp_p = EC_POINT_dup(spake2plus_select_M_N(instance, 0), instance->group)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot create temporary EC_POINT.\n");
            return (SPAKE2PLUS_OPENSSL_BN_SECURE_NEW_FAILED);
        }

        spake2plus_print_ec_point(COMMON_DEBUG, NULL, instance, tmp_p, POINT_CONVERSION_COMPRESSED,
                                  "[COMMON_DEBUG]: below is N or M:\n");

        EC_POINT_invert(instance->group, tmp_p, ctx);

        spake2plus_print_ec_point(COMMON_DEBUG, NULL, instance, tmp_p, POINT_CONVERSION_COMPRESSED,
                                  "[COMMON_DEBUG]: below is -N or -M:\n");

        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_POINT_mul(
                                                instance->group,
                                                Z,
                                                NULL,
                                                tmp_p,
                                                instance->w0,
                                                ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot multiply ((-w0) * N or M).\n");
            return_value = (SPAKE2PLUS_EC_POINT_MUL_FAILED);
            goto err;
        }

        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_POINT_add(instance->group,
                                                         Z,
                                                         spake2plus_select_pA_pB(instance, 0),
                                                         Z,
                                                         ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot add Y + ((-w0) * N or M).\n");
            return_value = (SPAKE2PLUS_EC_POINT_ADD_FAILED);
            goto err;
        }

        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_POINT_mul(
                                                instance->group,
                                                Z,
                                                NULL,
                                                Z,
                                                instance->cofactor,
                                                ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot multiply cofactor * (Y + ((-w0) * N or M)).\n");
            return_value = (SPAKE2PLUS_EC_POINT_MUL_FAILED);
            goto err;
        }

        if (SPAKE2PLUS_CLIENT == instance->client_server)
        {
            if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_POINT_mul(
                                                    instance->group,
                                                    V,
                                                    NULL,
                                                    Z,
                                                    instance->w1,
                                                    ctx))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                        "FATAL: cannot multiply cofactor * w1 * (Y + ((-w0) * N or M)).\n");
                return_value = (SPAKE2PLUS_EC_POINT_MUL_FAILED);
                goto err;
            }
            spake2plus_print_ec_point(COMMON_DEBUG, NULL, instance, V,
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      "[COMMON_DEBUG]: below is V for client (A):\n");
            spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                    "[COMMON_DEBUG]: below is Z for client (A):\n");
        }
        else if (SPAKE2PLUS_SERVER == instance->client_server)
        {
            if (SPAKE2PLUS_OPENSSL_COMMON_OK != BN_mul(tmp, instance->cofactor, instance->random_value, ctx))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                        "FATAL: cannot multiply cofactor and y.\n");
                return_value = (SPAKE2PLUS_GET_V_RANDOM_MUL_COFACTOR_FAILED);
                goto err;
            }
            spake2plus_printf_debug(COMMON_DEBUG, NULL, tmp,
                                    "[COMMON_DEBUG]: below is cofactor*y:\n");

            if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_POINT_mul(
                                                    instance->group,
                                                    V,
                                                    NULL,
                                                    instance->L,
                                                    tmp,
                                                    ctx))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                        "FATAL: cannot multiply cofactor * y * L.\n");
                return_value = (SPAKE2PLUS_GET_V_FAILED);
                goto err;
            }

            spake2plus_print_ec_point(COMMON_DEBUG, NULL, instance, V,
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      "[COMMON_DEBUG]: below is V for server (B):\n");
            spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                    "[COMMON_DEBUG]: below is Z for server (B):\n");
        }

        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_POINT_mul(
                                                instance->group,
                                                Z,
                                                NULL,
                                                Z,
                                                instance->random_value,
                                                ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot multiply (x or y) * cofactor * (Y + ((-w0) * N or M)).\n");
            return (SPAKE2PLUS_GET_Z_FAILED);
        }
        spake2plus_print_ec_point(COMMON_DEBUG, NULL, instance, Z, POINT_CONVERSION_UNCOMPRESSED, "");

    err:
        EC_POINT_CHECK_NULL_AND_FREE(tmp_p);
        BN_CHECK_NULL_AND_FREE(tmp);
        return (return_value);
    }

    int spake2plus_get_hash(
        uint8_t *md_value,
        size_t *md_len,
        SPAKE2PLUS *instance,
        uint8_t *TT,
        size_t TT_len)
    {
        int return_value = SPAKE2PLUS_OK;
        EVP_MD_CTX *mdctx;

        assert(NULL != TT);
        assert(0 != TT_len);
        assert(NULL != md_value);
        assert(NULL != md_len);
        assert(NULL != instance);
        assert(NULL != instance->evp_md);
        if (NULL == (mdctx = EVP_MD_CTX_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot create mdctx.\n");
            return (SPAKE2PLUS_EVP_MD_CTX_NEW_FAILED);
        }
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EVP_DigestInit_ex(mdctx, instance->evp_md, NULL))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot execute EVP_DigestInit_ex.\n");
            return_value = SPAKE2PLUS_EVP_DIGESTINIT_EX_FAILED;
            goto spake2plus_get_hash_exit;
        }
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EVP_DigestUpdate(mdctx, TT, TT_len))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot execute EVP_DigestUpdate.\n");
            return_value = SPAKE2PLUS_EVP_DIGESTUPDATE_FAILED;
            goto spake2plus_get_hash_exit;
        }
        unsigned int md_len_uint = 0;
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EVP_DigestFinal_ex(mdctx, md_value, &md_len_uint))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot execute EVP_DigestFinal_ex.\n");
            return_value = SPAKE2PLUS_EVP_DIGESTFINAL_EX_FAILED;
            goto spake2plus_get_hash_exit;
        }
        assert(sizeof(*md_len) >= sizeof(md_len_uint));
        *md_len = md_len_uint;

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: Hash is below:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, md_value, *md_len);

        /* Ke is the secret key for message signing */
        instance->Ke_len = ((*md_len) / 2);
        memcpy(instance->Ke, (md_value + (instance->Ke_len)), (instance->Ke_len));

    spake2plus_get_hash_exit:
        EVP_MD_CTX_free(mdctx);

        return (return_value);
    }

    int spake2plus_generate_TT(
        uint8_t **TT,
        size_t *TT_len,
        SPAKE2PLUS *instance,
        EC_POINT *Z,
        EC_POINT *V)
    {
        int return_value = SPAKE2PLUS_OK;
        const size_t bignums_for_TT_concatenation_count = 5;
        const size_t array_for_TT_concatenation_count = bignums_for_TT_concatenation_count + 2;
        uint8_t **arrays_for_TT_concatenation = NULL;
        size_t arrays_for_TT_concatenation_len[array_for_TT_concatenation_count];
        size_t i = 0;
        size_t j = 0;
        size_t k;
        BN_CTX *ctx = NULL;
        BIGNUM *pA_bn = NULL;
        BIGNUM *pB_bn = NULL;
        BIGNUM *Z_bn = NULL;
        BIGNUM *V_bn = NULL;
        point_conversion_form_t form;

        assert(NULL != Z);
        assert(NULL != V);
        assert(NULL != TT);
        assert(NULL != TT_len);
        /* It is here because instance may be NULL or something like that. */
        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_instance(instance)))
            return (return_value);

        *TT_len = 0;
        form = EC_GROUP_get_point_conversion_form(instance->group);
        if (NULL == (ctx = BN_CTX_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to create BN_CTX.\n");
            return_value = SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED;
            goto err;
        }
        BN_CTX_start(ctx);
        if ((NULL == (pA_bn = BN_secure_new())) || (NULL == (pB_bn = BN_secure_new())) || (NULL == (Z_bn = BN_secure_new())) || (NULL == (V_bn = BN_secure_new())))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to create BIGNUMS.\n");
            return_value = SPAKE2PLUS_OPENSSL_BN_SECURE_NEW_FAILED;
            goto err;
        }

        if ((NULL == EC_POINT_point2bn(instance->group, instance->pA, form, pA_bn, ctx)) || (NULL == EC_POINT_point2bn(instance->group, instance->pB, form, pB_bn, ctx)) || (NULL == EC_POINT_point2bn(instance->group, Z, form, Z_bn, ctx)) || (NULL == EC_POINT_point2bn(instance->group, V, form, V_bn, ctx)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to convert EC_POINTs to BIGNUMs.\n");
            return_value = SPAKE2PLUS_EC_POINT_POINT2BN_FAILED;
            goto err;
        }

        size_t bignums_for_TT_concatenation_len[] =
            {
                BN_num_bytes(pA_bn),
                BN_num_bytes(pB_bn),
                BN_num_bytes(Z_bn),
                BN_num_bytes(V_bn),
                BN_num_bytes(instance->w0)};
        BIGNUM *bignums_for_TT_concatenation[] =
            {
                pA_bn,
                pB_bn,
                Z_bn,
                V_bn,
                instance->w0};

        if (NULL == (arrays_for_TT_concatenation = OPENSSL_secure_malloc(array_for_TT_concatenation_count * sizeof(uint8_t *))))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot allocate memory for arrays_for_TT_concatenation.\n");
            return_value = SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED;
            goto err;
        }
        else
            for(j = 0; j < array_for_TT_concatenation_count; ++j)
            {
                arrays_for_TT_concatenation[j] = NULL;
            }
        if (instance->idA_len > 0)
        {
            arrays_for_TT_concatenation[i] = instance->idA;
            arrays_for_TT_concatenation_len[i++] = instance->idA_len;
            *TT_len += instance->idA_len + sizeof(instance->idA_len);
        }

        if (instance->idB_len > 0)
        {
            arrays_for_TT_concatenation[i] = instance->idB;
            arrays_for_TT_concatenation_len[i++] = instance->idB_len;
            *TT_len += instance->idB_len + sizeof(instance->idB_len);
        }

        if (i < 2)
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "WARNING: client_id or server_id are empty. Unknown Key Share attack is possible.\n");

        for (j = 0; j < bignums_for_TT_concatenation_count; ++j)
        {
            if (NULL == (arrays_for_TT_concatenation[i + j] =
                             OPENSSL_secure_malloc(bignums_for_TT_concatenation_len[j])))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                        "FATAL: cannot allocate memory for byte representations of BIGNUMs to be concatenated into TT.\n");
                return_value = SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED;
                break;
            }
            if (bignums_for_TT_concatenation_len[j] !=
                (arrays_for_TT_concatenation_len[i + j] =
                     BN_bn2bin(bignums_for_TT_concatenation[j],
                               (unsigned char *)(arrays_for_TT_concatenation[i + j]))))
            {
                spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                        "FATAL: cannot convert BIGNUMs to be concatenated into TT into byte representations.\n");
                return_value = SPAKE2PLUS_BN2BIN_FAILED;
                break;
            }
            *TT_len += arrays_for_TT_concatenation_len[i + j] + sizeof(bignums_for_TT_concatenation_len[j]);
        }
        if (SPAKE2PLUS_OK != return_value)
            goto err;

        if (NULL == (*TT = OPENSSL_secure_malloc(*TT_len)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot allocate memory for TT.\n");
            return_value = SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED;
            goto err;
        }

        for (j = 0; j < (bignums_for_TT_concatenation_count + i); ++j)
        {
            spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                    "[COMMON_DEBUG]: arrays_for_TT_concatenation[j]:\n");
            spake2plus_print_array(COMMON_DEBUG, NULL,
                                   arrays_for_TT_concatenation[j],
                                   arrays_for_TT_concatenation_len[j]);
        }

        j = 0;
        spake2plus_concatenate_arrays(
            *TT,
            &j,
            arrays_for_TT_concatenation,
            arrays_for_TT_concatenation_len,
            (bignums_for_TT_concatenation_count + i));

        assert(*TT_len == j);

    err:
        if (SPAKE2PLUS_OK != return_value)
            OPENSSL_CHECK_NULL_AND_FREE(*TT);
        if (NULL != arrays_for_TT_concatenation)
            for (k = 0; k < bignums_for_TT_concatenation_count; ++k)
            {
                if (SPAKE2PLUS_OPENSSL_COMMON_OK == CRYPTO_secure_allocated(arrays_for_TT_concatenation[i + k]))
                {
                    OPENSSL_CHECK_NULL_AND_FREE(arrays_for_TT_concatenation[i + k]);
                    arrays_for_TT_concatenation[i + k] = NULL;
                }
            }
        OPENSSL_CHECK_NULL_AND_FREE(arrays_for_TT_concatenation);
        BN_CHECK_NULL_AND_FREE(pA_bn);
        BN_CHECK_NULL_AND_FREE(pB_bn);
        BN_CHECK_NULL_AND_FREE(Z_bn);
        BN_CHECK_NULL_AND_FREE(V_bn);
        BN_CTX_CHECK_NULL_AND_FREE(ctx);
        return (return_value);
    }

    int spake2plus_generate_hash_of_TT(
        uint8_t *md_value,
        size_t *md_len,
        SPAKE2PLUS *instance,
        EC_POINT *Z,
        EC_POINT *V)
    {
        int return_value = SPAKE2PLUS_OK;
        uint8_t *TT = NULL;
        size_t TT_len = 0;

        assert(NULL != md_value);
        assert(NULL != md_len);
        assert(EVP_MAX_MD_SIZE == *md_len);
        assert(NULL != Z);
        assert(NULL != V);

        /* It is here because instance may be NULL or something like that. */
        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_instance(instance)))
            return (return_value);

        if (SPAKE2PLUS_OK != (return_value = spake2plus_generate_TT(
                                  &TT, &TT_len, instance, Z, V)))
            goto err;

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below is TT:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, TT, TT_len);

        if (SPAKE2PLUS_OK != (return_value = spake2plus_get_hash(
                                  md_value,
                                  md_len,
                                  instance,
                                  TT,
                                  TT_len)))
            goto err;

    err:
        OPENSSL_CHECK_NULL_AND_FREE(TT);
        return (return_value);
    }

    int spake2plus_calculate_HKDF(
        uint8_t *KcAKcB,
        size_t *KcAKcB_len,
        SPAKE2PLUS *instance,
        uint8_t *Ka,
        size_t Ka_len)
    {
        int return_value = SPAKE2PLUS_OK;
        EVP_PKEY_CTX *pctx = NULL;
        uint8_t label[] = "ConfirmationKeys";
        uint8_t *info = NULL;
        int info_len = 0;
        size_t size_of_label = 0;

        assert(NULL != KcAKcB);
        assert(NULL != KcAKcB_len);
        assert(NULL != Ka);
        assert(0 != Ka_len);
        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_instance(instance)))
            return (return_value);

        if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot allocate memory for info.\n");
            return (SPAKE2PLUS_EVP_PKEY_CTX_NEW_FAILED);
        }

        size_of_label = sizeof(label) - 1;
        info_len = size_of_label + instance->AAD_len;
        if (NULL == (info = OPENSSL_secure_malloc(info_len)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot allocate memory for info.\n");
            return_value = SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED;
            goto spake2plus_calculate_HKDF_exit;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below is label:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, label, size_of_label);
        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below are Additional Authenticated Data (AAD):\n");
        spake2plus_print_array(
            COMMON_DEBUG,
            NULL,
            instance->AAD,
            instance->AAD_len);

        if (NULL == memcpy(info, label, size_of_label))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot copy label to info.\n");
            return_value = SPAKE2PLUS_MEMCPY_FAILED;
            goto spake2plus_calculate_HKDF_exit;
        }
        if (NULL == memcpy((info + size_of_label), instance->AAD, instance->AAD_len))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot copy Additional Authenticated Data (AAD) to info.\n");
            return_value = SPAKE2PLUS_MEMCPY_FAILED;
            goto spake2plus_calculate_HKDF_exit;
        }
        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: info:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, info,
                               size_of_label + instance->AAD_len);

        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EVP_PKEY_derive_init(pctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: EVP_PKEY_derive_init failed.\n");
            return_value = SPAKE2PLUS_EVP_PKEY_DERIVE_INIT_FAILED;
            goto spake2plus_calculate_HKDF_exit;
        }
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EVP_PKEY_CTX_set_hkdf_md(pctx, instance->evp_md))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: EVP_PKEY_CTX_set_hkdf_md failed.\n");
            return_value = SPAKE2PLUS_EVP_PKEY_CTX_SET_HKDF_MD_FAILED;
            goto spake2plus_calculate_HKDF_exit;
        }
        /* Salt should be nil according to the SPAKE2+.
     * This seems reasonable because how can we share the salt?*/
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: EVP_PKEY_CTX_set1_hkdf_salt failed.\n");
            return_value = SPAKE2PLUS_EVP_PKEY_CTX_SET_HKDF_SALT_FAILED;
            goto spake2plus_calculate_HKDF_exit;
        }
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EVP_PKEY_CTX_set1_hkdf_key(pctx, Ka, Ka_len))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: EVP_PKEY_CTX_set1_hkdf_key failed.\n");
            return_value = SPAKE2PLUS_EVP_PKEY_CTX_SET_HKDF_KEY_FAILED;
            goto spake2plus_calculate_HKDF_exit;
        }
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: EVP_PKEY_CTX_add1_hkdf_info failed.\n");
            return_value = SPAKE2PLUS_EVP_PKEY_CTX_SET_HKDF_INFO_FAILED;
            goto spake2plus_calculate_HKDF_exit;
        }
        /* TODO make clear the following: */
        /* OpenSSL: "The EVP_PKEY_derive() derives a shared secret using ctx.
     * If key is NULL then the maximum size of the output buffer is written
     * to the keylen parameter."
     * This doesn't show to be true for calculating HKDF. */
        /*
 *  if(SPAKE2PLUS_OPENSSL_COMMON_OK !=
 *          EVP_PKEY_derive(pctx, NULL, KcAKcB_len);
 *          )
 *  {
 *      spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                "FATAL: EVP_PKEY_derive called for KcAKcB_len failed.\n");
 *      ERR_print_errors_fp(stderr);
 *      goto spake2plus_calculate_HKDF_exit;
 *  } */

        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EVP_PKEY_derive(pctx, KcAKcB, KcAKcB_len))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: EVP_PKEY_derive call failed, cannot calculate KcAKcB.\n");
            return_value = SPAKE2PLUS_EVP_PKEY_DERIVE_FAILED;
            goto spake2plus_calculate_HKDF_exit;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below is KcAKcB:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, KcAKcB, *KcAKcB_len);

    spake2plus_calculate_HKDF_exit:
        OPENSSL_CHECK_NULL_AND_FREE(info);
        EVP_PKEY_CTX_free(pctx);

        return (return_value);
    }

    inline uint8_t *spake2plus_select_KcA_KcB(
        SPAKE2PLUS *instance,
        int choose_own)
    {
        assert(NULL != instance);
        assert(NULL != instance->KcAKcB);
        assert((SPAKE2PLUS_CLIENT == instance->client_server) || (SPAKE2PLUS_SERVER == instance->client_server));
        return ((SPAKE2PLUS_CLIENT == spake2plus_choose_side(instance, choose_own)) ? instance->KcAKcB
                                                                                    : ((SPAKE2PLUS_SERVER == spake2plus_choose_side(instance, choose_own)) ? (instance->KcAKcB + (instance->KcAKcB_len / 2)) : NULL));
    }

    int spake2plus_check_received_pA_or_pB(SPAKE2PLUS *instance,
                                           EC_POINT *point_to_be_checked)
    {
        int return_value = SPAKE2PLUS_OK;
        BN_CTX *ctx = NULL;
        EC_POINT *tmp = NULL;
        assert(NULL != instance);
        assert(NULL != point_to_be_checked);
        assert(NULL != instance->prime);

        if (NULL == (ctx = BN_CTX_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot allocate enough memory.\n");
            return_value = (SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED);
            goto spake2plus_check_L_exit;
        }
        BN_CTX_start(ctx);

        switch (EC_POINT_is_on_curve(instance->group, point_to_be_checked, ctx))
        {
        case 0:
            spake2plus_print_ec_point(FATAL_DEBUG, stderr, instance,
                                      point_to_be_checked,
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      "FATAL: Obtained point is not on elliptic curve.\n");
            return_value = (SPAKE2PLUS_POINT_NOT_ON_EC);
            break;
        case -1:
            spake2plus_print_ec_point(FATAL_DEBUG, stderr, instance,
                                      point_to_be_checked,
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      "FATAL: Could not check if obtained point belong to the elliptic curve.\n");
            return_value = SPAKE2PLUS_FAILED_TO_CHECK_IF_POINT_ON_EC;
            break;
        }

        if (EC_POINT_is_at_infinity(instance->group, point_to_be_checked))
        {
            spake2plus_print_ec_point(FATAL_DEBUG, stderr, instance,
                                      point_to_be_checked,
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      "FATAL: Obtained point is not on elliptic curve.\n");
            return_value = SPAKE2PLUS_IS_GROUP_IDENTITY;
            goto spake2plus_check_L_exit;
        }

    spake2plus_check_L_exit:
        EC_POINT_CHECK_NULL_AND_FREE(tmp);
        BN_CTX_CHECK_NULL_AND_FREE(ctx);
        return (return_value);
    }

    int spake2plus_get_own_Fa_or_Fb(
        uint8_t *Fa_or_Fb,
        size_t *Fa_or_Fb_len,
        SPAKE2PLUS *instance,
        BN_CTX *ctx)
    {
        int return_value = SPAKE2PLUS_OK;
        uint8_t *message = NULL;
        size_t message_len = 0;

        message_len = EC_POINT_point2oct(instance->group,
                                         spake2plus_select_pA_pB(instance, 0),
                                         EC_GROUP_get_point_conversion_form(instance->group),
                                         NULL,
                                         0,
                                         ctx);

        if (NULL == (message = OPENSSL_secure_malloc(message_len)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot allocate memory for message to be passed to MAC function.\n");
            return_value = SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED;
            goto spake2plus_derive_confirmation_keys_exit;
        }

        if (message_len != EC_POINT_point2oct(instance->group,
                                              spake2plus_select_pA_pB(instance, 0),
                                              EC_GROUP_get_point_conversion_form(instance->group),
                                              message,
                                              message_len,
                                              ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot convert BIGNUM to uint8_t*.\n");
            return_value = SPAKE2PLUS_EC_POINT_POINT2OCT_FAILED;
            goto spake2plus_derive_confirmation_keys_exit;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below is pB or pA as an array of bytes:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, message, message_len);

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below is KcA or KcB as an array of bytes:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL,
                               spake2plus_select_KcA_KcB(instance, 1),
                               (instance->KcAKcB_len / 2));

        if (SPAKE2PLUS_OK != (return_value = instance->MAC_func(
                                  Fa_or_Fb,
                                  Fa_or_Fb_len,
                                  spake2plus_select_KcA_KcB(instance, 1),
                                  (instance->KcAKcB_len / 2),
                                  message,
                                  message_len,
                                  instance->evp_md)))
            goto spake2plus_derive_confirmation_keys_exit;

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below is Fa_or_Fb:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, Fa_or_Fb, *Fa_or_Fb_len);

    spake2plus_derive_confirmation_keys_exit:
        OPENSSL_CHECK_NULL_AND_FREE(message);
        return (return_value);
    }

    int spake2plus_derive_confirmation_keys(
        uint8_t *Fa_or_Fb,
        size_t *Fa_or_Fb_len,
        SPAKE2PLUS *instance,
        uint8_t *pA_or_pB,
        size_t pA_or_pB_len)
    {
        int return_value = SPAKE2PLUS_OK;
        EC_POINT *Z = NULL;
        EC_POINT *V = NULL;
        BN_CTX *ctx = NULL;
        uint8_t md_value[EVP_MAX_MD_SIZE];
        size_t md_len = EVP_MAX_MD_SIZE;
        EC_POINT **pointer_to_counterparts_pA_or_pB = NULL;
        BIGNUM *x = NULL;
        BIGNUM *y = NULL;

        /* Input sanity checks */
        if (NULL == Fa_or_Fb_len)
            return (SPAKE2PLUS_FA_OR_FB_LEN_NULL_POINTER);
        *Fa_or_Fb_len = 0;
        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_instance(instance)))
            return (return_value);
        if (NULL == pA_or_pB)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Received protocol setup key is NULL.\n");
            return (SPAKE2PLUS_PA_OR_PB_IS_NULL);
        }
        if (0 == pA_or_pB_len)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Received protocol setup key length is zero.\n");
            return (SPAKE2PLUS_PA_OR_PB_LEN_IS_ZERO);
        }

        /* Main initializations */
        if (NULL == (ctx = BN_CTX_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot allocate enough memory.\n");
            return_value = (SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED);
            goto spake2plus_derive_confirmation_keys_exit;
        }
        BN_CTX_start(ctx);

        if ((NULL == (Z = EC_POINT_new(instance->group))) || (NULL == (V = EC_POINT_new(instance->group))))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot allocate memory for EC points Z, V.\n");
            return_value = SPAKE2PLUS_EC_POINT_NEW_FAILED;
            goto spake2plus_derive_confirmation_keys_exit;
        }

        if ((NULL == (x = BN_secure_new())) || (NULL == (y = BN_secure_new())))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to allocate memory for BIGNUMs in spake2plus_derive_confirmation_keys.\n");
            return_value = (SPAKE2PLUS_OPENSSL_BN_SECURE_NEW_FAILED);
            goto spake2plus_derive_confirmation_keys_exit;
        }

        /* Main operations */
        if ((NULL == BN_bin2bn((unsigned char *)(pA_or_pB + 1), pA_or_pB_len / 2, x)) || (NULL == BN_bin2bn((unsigned char *)(pA_or_pB + 1 + ((pA_or_pB_len) / 2)),
                                                                                                            pA_or_pB_len / 2, y)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to convert pA or pB point coordinates from byte array to BIGNUMs.\n");
            return_value = SPAKE2PLUS_BN2BIN_FAILED;
            goto spake2plus_derive_confirmation_keys_exit;
        }

        pointer_to_counterparts_pA_or_pB = spake2plus_select_pointer_pA_pB(instance, 0);
        if (SPAKE2PLUS_OPENSSL_COMMON_OK != EC_POINT_SET_AFFINE_COORDINATES(
                                                instance->group,
                                                (*pointer_to_counterparts_pA_or_pB),
                                                x, y, ctx))
        {
            spake2plus_printf_debug(COMMON_DEBUG, stderr, NULL,
                                    "FATAL: error extracting counterparts_pA_or_pB as an EC_POINT.\n");
            return_value = (SPAKE2PLUS_EC_POINT_SET_COORD_FAILED);
            goto spake2plus_derive_confirmation_keys_exit;
        }

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below is pA_or_pB in confirmation derivation function:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, pA_or_pB, pA_or_pB_len);

        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_received_pA_or_pB(
                                  instance,
                                  (*pointer_to_counterparts_pA_or_pB))))
            goto spake2plus_derive_confirmation_keys_exit;

        if (SPAKE2PLUS_OK != (return_value = spake2plus_generate_keys_Z_V(Z, V, instance, ctx)))
            goto spake2plus_derive_confirmation_keys_exit;

        if (SPAKE2PLUS_OK != (return_value = spake2plus_generate_hash_of_TT(md_value, &md_len, instance, Z, V)))
            goto spake2plus_derive_confirmation_keys_exit;

        if (SPAKE2PLUS_OK != (return_value = spake2plus_calculate_HKDF(
                                  instance->KcAKcB,
                                  &instance->KcAKcB_len,
                                  instance,
                                  md_value,
                                  instance->Ke_len)))
            goto spake2plus_derive_confirmation_keys_exit;

        if (SPAKE2PLUS_OK != (return_value = spake2plus_get_own_Fa_or_Fb(Fa_or_Fb, Fa_or_Fb_len, instance, ctx)))
            goto spake2plus_derive_confirmation_keys_exit;

    spake2plus_derive_confirmation_keys_exit:
        BN_CTX_CHECK_NULL_AND_FREE(ctx);
        EC_POINT_CHECK_NULL_AND_FREE(Z);
        EC_POINT_CHECK_NULL_AND_FREE(V);
        BN_CHECK_NULL_AND_FREE(x);
        BN_CHECK_NULL_AND_FREE(y);

        return (return_value);
    }

    int spake2plus_get_key_Ke(
        uint8_t *Ke,
        size_t *Ke_len,
        SPAKE2PLUS *instance)
    {
        int return_value = SPAKE2PLUS_OK;
        if (NULL == Ke_len)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Ke_len is NULL pointer.\n");
            return (SPAKE2PLUS_KE_LEN_NULL);
        }
        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_instance(instance)))
            return (return_value);
        if (0 == instance->Ke_len)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Ke_len is zero, SPAKE2+ shared secret key was not set up.\n");
            return (SPAKE2PLUS_KE_NOT_AVAILABLE);
        }
        *Ke_len = instance->Ke_len;
        if (NULL == Ke)
            return (return_value);
        memcpy(Ke, instance->Ke, instance->Ke_len);
        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below is Ke:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, instance->Ke, instance->Ke_len);
        return (return_value);
    }

    int spake2plus_verify(
        SPAKE2PLUS *instance,
        uint8_t *Fa_or_Fb,
        size_t Fa_or_Fb_len)
    {
        int return_value = SPAKE2PLUS_OK;
        uint8_t Fa_local[EVP_MAX_MD_SIZE] = {0};
        size_t Fa_local_len = 0;
        uint8_t *pB_local = NULL;
        BN_CTX *ctx;

        size_t pB_local_len = 0;

        if (SPAKE2PLUS_OK != (return_value = spake2plus_check_instance(instance)))
            return (return_value);
        if (NULL == instance->KcAKcB)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: KcAKcB key is NULL.\n");
            return (SPAKE2PLUS_KCAKCB_IS_NULL);
        }
        if (NULL == Fa_or_Fb)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Received confirmation key is NULL.\n");
            return (SPAKE2PLUS_FA_OR_FB_IS_NULL);
        }
        if (NULL == (ctx = BN_CTX_secure_new()))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Cannot allocate enough memory.\n");
            return_value = (SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED);
            goto spake2plus_verify_exit;
        }
        BN_CTX_start(ctx);

        pB_local_len = EC_POINT_point2oct(instance->group,
                                          spake2plus_select_pA_pB(instance, 1),
                                          EC_GROUP_get_point_conversion_form(instance->group),
                                          NULL,
                                          0,
                                          ctx);
        if (NULL == (pB_local = OPENSSL_secure_malloc(pB_local_len)))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: Failed to allocate memory for augmented password data.\n");
            return_value = (SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED);
            goto spake2plus_verify_exit;
        }
        if (pB_local_len != EC_POINT_point2oct(instance->group,
                                               spake2plus_select_pA_pB(instance, 1),
                                               EC_GROUP_get_point_conversion_form(instance->group),
                                               (unsigned char *)pB_local,
                                               pB_local_len,
                                               ctx))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: cannot convert BIGNUM to uint8_t*.\n");
            return_value = SPAKE2PLUS_EC_POINT_POINT2OCT_FAILED;
            goto spake2plus_verify_exit;
        }

        if (SPAKE2PLUS_OK != (return_value = instance->MAC_func(
                                  Fa_local,
                                  &Fa_local_len,
                                  spake2plus_select_KcA_KcB(instance, 0),
                                  ((instance->KcAKcB_len) / 2),
                                  pB_local,
                                  pB_local_len,
                                  instance->evp_md)))
            goto spake2plus_verify_exit;

        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below is local F*:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, Fa_local, Fa_local_len);
        spake2plus_printf_debug(COMMON_DEBUG, NULL, NULL,
                                "[COMMON_DEBUG]: below is foreign F*:\n");
        spake2plus_print_array(COMMON_DEBUG, NULL, Fa_or_Fb, Fa_or_Fb_len);

        if (Fa_or_Fb_len != Fa_local_len)
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: local and foreign F* key length differ.\n");
            return_value = (SPAKE2PLUS_FA_FB_KEY_LEN_MISMATCH);
            goto spake2plus_verify_exit;
        }

        if (0 != memcmp(Fa_or_Fb, Fa_local, Fa_or_Fb_len))
        {
            spake2plus_printf_debug(FATAL_DEBUG, stderr, NULL,
                                    "FATAL: local and foreign F* keys differ.\n");
            return_value = (SPAKE2PLUS_FA_FB_KEY_MISMATCH);
            goto spake2plus_verify_exit;
        }
    spake2plus_verify_exit:
        OPENSSL_CHECK_NULL_AND_FREE(pB_local);
        BN_CTX_CHECK_NULL_AND_FREE(ctx);

        return (return_value);
    }

    const char *spake2plus_version()
    {
        return SPAKE2PLUS_VERSION;
    }

#ifdef __cplusplus
}
#endif
