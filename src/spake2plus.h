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

#ifndef INCLUDE_SPAKE2PLUS_H_
#define INCLUDE_SPAKE2PLUS_H_

// R=Release, ##=Version, ##=month, ##=yr
#define SPAKE2PLUS_VERSION "R-020820"

//#include <SPAKE2plusConfig.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/opensslv.h>

/*! \file spake2plus.h
 * Common SPAKE2+ library declarations.
 * */

/*! \defgroup spake2plus_public SPAKE2+ main functions
 *
 * \brief These functions are intended for end user of the library.
 *
 * Run them on a client or a server as follows.
 *
 * -# Run spake2plus_init in order to setup elliptic curve group,
 * hash and MAC functions, client or server type of instance,
 * client and server identities and additional authenticated data.
 *
 * -# Run spake2plus_pwd_init to initialize instance with
 * hashed augmented password data. This creates values w0, w1 and L.
 *
 * -# [Server only] Run spake2plus_load_L_w0 to load previously stored value w0 and
 * elliptic curve point L to the server instance.
 *
 * -# Run spake2plus_setup_protocol to create elliptic curve points X = pA on client
 * and Y = pB on server for setup protocol values.
 *
 * -# Run spake2plus_get_own_pA_or_pB to obtain setup protocol values pA for client
 * or pB for server as byte strings in uncompressed from the corresponding elliptic
 * curve points X or Y.
 *
 * -# Run spake2plus_derive_confirmation_keys to obtain confirmation keys Fa for client
 * or Fb for server, providing a pointer to an initialized instance and
 * foreign setup key pB for client or pA for server.
 *
 * -# Run spake2plus_verify to check if foreign confirmation key Fb for client
 * or Fa for server is correct and shared secret is established.
 *
 * -# Run spake2plus_get_key_Ke to obtain shared secret Ke.
 *
 * -# Run spake2plus_free to destroy SPAKE2+ instance.
 *
 * -# Run spake2plus_openssl_cleanup after finishing all OpenSSL operations. After that
 * OpenSSL cannot be reinitialized. As an option, own OpenSSL cleanup procedure can be used,
 * executing calls to EVP_cleanup, CRYPTO_cleanup_all_ex_data, OPENSSL_cleanup and
 * CRYPTO_secure_malloc_done functions or their equivalents. If omitting cleanup procedures,
 * memory leaks can arise.
 */

/*! \def COMMON_DEBUG
  Enables printing messages with functions like spake2plus_print*(COMMON_DEBUG, ....
*/

#ifndef COMMON_DEBUG
#define COMMON_DEBUG 0
#endif

/*! \def FATAL_DEBUG
  Enables printing messages with functions like spake2plus_print*(FATAL_DEBUG, ....
*/
#ifndef FATAL_DEBUG
#define FATAL_DEBUG 0
#endif

/*! \def CONCATENATE_ARRAYS_DEBUG
  Enables printing messages with functions like spake2plus_print*(CONCATENATE_ARRAYS_DEBUG, ....
*/
#ifndef CONCATENATE_ARRAYS_DEBUG
#define CONCATENATE_ARRAYS_DEBUG 0
#endif


/*! \def SPAKE2PLUS_OPENSSL_COMMON_OK
  The common OK return value for the most of OPENSSL functions.
*/
#define SPAKE2PLUS_OPENSSL_COMMON_OK 1
/*! \def SPAKE2PLUS_128_BIT_IN_BYTES
  The constant for 16 bytes or 128 bits.
*/
#define SPAKE2PLUS_128_BIT_IN_BYTES (128 >> 3)
/*! \def SPAKE2PLUS_PBKDF2_ARG_ARRAYS_COUNT
  The constant for 3 that is the number of byte arrays concatenated as input for PBKDF2 function.
*/
#define SPAKE2PLUS_PBKDF2_ARG_ARRAYS_COUNT 3
/*! \def SPAKE2PLUS_REQUIRED_HEAP_SIZE
  The size of OPENSSL secure heap, to be enlarged in case of memory allocation errors.
*/
#define SPAKE2PLUS_REQUIRED_HEAP_SIZE (1 << 18)
/*! \def SPAKE2PLUS_MIN_SIZE_TO_ALLOC
  The constant for 8 byte (64 bit) as a minimal platform-dependent memory granulation.
*/
#define SPAKE2PLUS_MIN_SIZE_TO_ALLOC 8
/*! \def SPAKE2PLUS_HMAC_SEARCH_NAME
  The string constant for using HMAC function in spake2plus_init.
*/
#define SPAKE2PLUS_HMAC_SEARCH_NAME "HMAC"
/*! \def SPAKE2PLUS_CMAC_SEARCH_NAME
  The string constant for using CMAC-AES-128 function in spake2plus_init.
*/
#define SPAKE2PLUS_CMAC_SEARCH_NAME "CMAC"
/*! \def SPAKE2PLUS_GROUP_P256_SEARCH_NAME
  The string constant for using P-256 EC group in spake2plus_init.
*/
#define SPAKE2PLUS_GROUP_P256_SEARCH_NAME "P-256"
/*! \def SPAKE2PLUS_GROUP_P384_SEARCH_NAME
  The string constant for using P-384 EC group in spake2plus_init.
*/
#define SPAKE2PLUS_GROUP_P384_SEARCH_NAME "P-384"
/*! \def SPAKE2PLUS_GROUP_P521_SEARCH_NAME
  The string constant for using P-521 EC group in spake2plus_init.
*/
#define SPAKE2PLUS_GROUP_P521_SEARCH_NAME "P-521"
/*! \def SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME
  Yet unsupported. The string constant for using edwards25519 EC group in spake2plus_init.
*/
#define SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME "ED25519"
/*! \def SPAKE2PLUS_GROUP_ED448_SEARCH_NAME
  Yet unsupported. The string constant for using edwards448 EC group in spake2plus_init.
*/
#define SPAKE2PLUS_GROUP_ED448_SEARCH_NAME "ED448"
/*! \def SPAKE2PLUS_HASH_SHA256_SEARCH_NAME
  The string constant for using SHA256 hash function in spake2plus_init.
*/
#define SPAKE2PLUS_HASH_SHA256_SEARCH_NAME "SHA256"
/*! \def SPAKE2PLUS_HASH_SHA512_SEARCH_NAME
  The string constant for using SHA512 hash function in spake2plus_init.
*/
#define SPAKE2PLUS_HASH_SHA512_SEARCH_NAME "SHA512"
/*! \def SPAKE2PLUS_PBDKF2_ITERATION_COUNT
  The iteration count used for PBKDF2 function in spake2plus_init.
*/

#define SPAKE2PLUS_PBDKF2_ITERATION_COUNT 2000

#if ((OPENSSL_VERSION_NUMBER >> 8) == 0x101000)
    #define BN_PRIV_RAND_RANGE BN_rand_range
    #define EC_POINT_SET_COMPRESSED_COORDINATES EC_POINT_set_compressed_coordinates_GFp
    #define EC_GROUP_GET_CURVE EC_GROUP_get_curve_GFp
    #define EC_POINT_SET_AFFINE_COORDINATES EC_POINT_set_affine_coordinates_GFp
#elif ((OPENSSL_VERSION_NUMBER >> 8) == 0x101010)
    #define BN_PRIV_RAND_RANGE BN_priv_rand_range
    #define EC_POINT_SET_COMPRESSED_COORDINATES EC_POINT_set_compressed_coordinates
    #define EC_GROUP_GET_CURVE EC_GROUP_get_curve
    #define EC_POINT_SET_AFFINE_COORDINATES EC_POINT_set_affine_coordinates
#else
    #error "OpenSSL other that 1.1.0 or 1.1.1 is not supported!"
#endif

/*! \def BN_CHECK_NULL_AND_FREE(bn)
 * \brief Check if NULL and make free and NULL BIGNUM pointer.
 *
  The macros checks if \a bn BIGNUM pointer is NULL
  and if it is not, makes \a bn free and NULL.
*/
#define BN_CHECK_NULL_AND_FREE(bn) \
    do                             \
        if (NULL != (bn))          \
        {                          \
            BN_clear_free((bn));   \
            (bn) = NULL;           \
        }                          \
    while (0)


/*! \def OPENSSL_CHECK_NULL_AND_FREE(ptr)
 * \brief Check if NULL and make free and NULL pointer.
 *
  The macros checks if a securely allocated with OPENSSL \a ptr pointer is NULL
  and if it is not, makes \a ptr free and NULL.
*/
#define OPENSSL_CHECK_NULL_AND_FREE(ptr) \
    do                                   \
        if (NULL != (ptr))               \
        {                                \
            OPENSSL_secure_free((ptr));  \
            (ptr) = NULL;                \
        }                                \
    while (0)

/*! \def EC_POINT_CHECK_NULL_AND_FREE(ec_point)
 * \brief Check if NULL and make free and NULL EC_POINT pointer.
 *
  The macros checks if an EC_POINT \a ec_point pointer is NULL
  and if it is not, makes \a ec_point free and NULL.
*/
#define EC_POINT_CHECK_NULL_AND_FREE(ec_point) \
    do                                         \
        if (NULL != (ec_point))                \
        {                                      \
            EC_POINT_clear_free((ec_point));   \
            (ec_point) = NULL;                 \
        }                                      \
    while (0)


/*! \def EC_GROUP_CHECK_NULL_AND_FREE(ec_group)
 * \brief Check if NULL and make free and NULL EC_GROUP pointer.
 *
  The macros checks if an EC_GROUP \a ec_group pointer is NULL
  and if it is not, makes \a ec_group free and NULL.
*/
#define EC_GROUP_CHECK_NULL_AND_FREE(ec_group) \
    do                                         \
        if (NULL != (ec_group))                \
        {                                      \
            EC_GROUP_free((ec_group));         \
            (ec_group) = NULL;                 \
        }                                      \
    while (0)


/*! \def BN_CTX_CHECK_NULL_AND_FREE(ctx)
 * \brief Check if NULL and make free and NULL BN_CTX pointer.
 *
  The macros checks if a BN_CTX \a ctx pointer is NULL
  and if it is not, makes \a ctx free and NULL.
*/
#define BN_CTX_CHECK_NULL_AND_FREE(ctx) \
    do                                  \
        if (NULL != (ctx))              \
        {                               \
            BN_CTX_end(ctx);            \
            BN_CTX_free((ctx));         \
            (ctx) = NULL;               \
        }                               \
    while (0)
/*! \struct M_and_N_by_NID
 * \brief Structure for storing M and N points from SPAKE2+ standard.
 *
 * This structure stores EC_POINTs
 * M and N in uncompressed form.
 */
typedef struct
{
    /*! \brief NID, the numeric group identifier used in OPENSSL. */
    int nid;
    /*! \brief The EC point M in compressed byte string format. */
    const uint8_t *M;
    /*! \brief The length of compressed byte string for EC point M. */
    size_t M_len;
    /*! \brief The EC point N in compressed byte string format. */
    const uint8_t *N;
    /*! \brief The length of compressed byte string for EC point N. */
    size_t N_len;
    /*! \brief [UNSUPPORTED] The byte string for EC generator. */
    const char *generator;
} M_and_N_by_NID;

/*! \enum spake2plus_return_codes
 * A list of codes that are returned by spake2plus_* functions.
 */
enum spake2plus_return_codes
{
    /*! \brief */
    SPAKE2PLUS_GENERAL_ERROR_CODE = -1,
    /*! \brief */
    SPAKE2PLUS_OK = 0,
    /*! \brief */
    SPAKE2PLUS_EC_NULL_NAME,
    /*! \brief */
    SPAKE2PLUS_EC_NOT_FOUND,
    /*! \brief */
    SPAKE2PLUS_PW_WRONG_LEN,
    /*! \brief */
    SPAKE2PLUS_PW_IS_NULL,
    /*! \brief */
    SPAKE2PLUS_PL_WRONG,
    /*! \brief */
    SPAKE2PLUS_PW0_WRONG,
    /*! \brief */
    SPAKE2PLUS_HASH_NAME_IS_NULL,
    /*! \brief */
    SPAKE2PLUS_HASH_NOT_SET,
    /*! \brief */
    SPAKE2PLUS_CLIENT_ID_DATA_ERROR,
    /*! \brief */
    SPAKE2PLUS_SERVER_ID_DATA_ERROR,
    /*! \brief */
    SPAKE2PLUS_AAD_DATA_ERROR,
    /*! \brief */
    SPAKE2PLUS_MAC_NULL_NAME,
    /*! \brief */
    SPAKE2PLUS_MAC_FUNC_NOT_FOUND,
    /*! \brief */
    SPAKE2PLUS_MAC_NULL_RETURN,
    /*! \brief */
    SPAKE2PLUS_MAC_NULL_RETURN_LEN,
    /*! \brief */
    SPAKE2PLUS_MAC_NULL_KEY,
    /*! \brief */
    SPAKE2PLUS_MAC_WRONG_KEY_LEN,
    /*! \brief */
    SPAKE2PLUS_MAC_NULL_MSG,
    /*! \brief */
    SPAKE2PLUS_MAC_ZERO_MSG_LEN,
    /*! \brief */
    SPAKE2PLUS_CMAC_NULL_CTX,
    /*! \brief */
    SPAKE2PLUS_CMAC_INIT_FAILED,
    /*! \brief */
    SPAKE2PLUS_CMAC_UPDATE_FAILED,
    /*! \brief */
    SPAKE2PLUS_CMAC_FINAL_FAILED,
    /*! \brief */
    SPAKE2PLUS_HMAC_NULL_EVP_MD,
    /*! \brief */
    SPAKE2PLUS_OPENSSL_HMAC_FAILED,
    /*! \brief */
    SPAKE2PLUS_OPENSSL_CONF_LOAD_ERROR,
    /*! \brief */
    SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED,
    /*! \brief */
    SPAKE2PLUS_OPENSSL_PBKDF2_FAILED,
    /*! \brief */
    SPAKE2PLUS_OPENSSL_BN_SECURE_NEW_FAILED,
    /*! \brief */
    SPAKE2PLUS_OPENSSL_BN_CTX_SECURE_NEW_FAILED,
    /*! \brief */
    SPAKE2PLUS_EC_GROUP_GET_CURVE_FAILED,
    /*! \brief */
    SPAKE2PLUS_EC_GROUP_GET_COFACTOR_FAILED,
    /*! \brief */
    SPAKE2PLUS_EC_GROUP_GET0_GENERATOR_FAILED,
    /*! \brief */
    SPAKE2PLUS_EC_GROUP_POINT2BN_FAILED,
    /*! \brief */
    SPAKE2PLUS_BIN2BN_FAILED,
    /*! \brief */
    SPAKE2PLUS_DEC2BN_FAILED,
    /*! \brief */
    SPAKE2PLUS_BN2BIN_FAILED,
    /*! \brief */
    SPAKE2PLUS_BN_RAND_FAILED,
    /*! \brief */
    SPAKE2PLUS_BN_ARITHM_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_GROUP_ORDER_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_GROUP_IDENTITY_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_W0S_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_W1S_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_W0_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_W1_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_L_FAILED,
    /*! \brief */
    SPAKE2PLUS_INSTANCE_IS_NULL,
    /*! \brief */
    SPAKE2PLUS_INSTANCE_FIELD_IS_NULL,
    /*! \brief */
    SPAKE2PLUS_PA_OR_PB_LEN_NULL_POINTER,
    /*! \brief */
    SPAKE2PLUS_FA_OR_FB_LEN_NULL_POINTER,
    /*! \brief */
    SPAKE2PLUS_PA_OR_PB_IS_NULL,
    /*! \brief */
    SPAKE2PLUS_PA_OR_PB_LEN_IS_ZERO,
    /*! \brief */
    SPAKE2PLUS_CLIENT_SERVER_UNEXPECTED,
    /*! \brief */
    SPAKE2PLUS_GET_Z_W0_MUL_NM_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_Z_PAPB_SUB_W0NM_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_Z_WO_COFACTOR_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_Z_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_V_RANDOM_MUL_COFACTOR_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_V_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_V_W0_MUL_N_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_V_Y_SUB_W0_MUL_N_FAILED,
    /*! \brief */
    SPAKE2PLUS_GET_V_WO_COFACTOR,
    /*! \brief */
    SPAKE2PLUS_EVP_MD_CTX_NEW_FAILED,
    /*! \brief */
    SPAKE2PLUS_EVP_DIGESTINIT_EX_FAILED,
    /*! \brief */
    SPAKE2PLUS_EVP_DIGESTUPDATE_FAILED,
    /*! \brief */
    SPAKE2PLUS_EVP_DIGESTFINAL_EX_FAILED,
    /*! \brief */
    SPAKE2PLUS_EVP_PKEY_CTX_NEW_FAILED,
    /*! \brief */
    SPAKE2PLUS_MEMCPY_FAILED,
    /*! \brief */
    SPAKE2PLUS_EVP_PKEY_DERIVE_INIT_FAILED,
    /*! \brief */
    SPAKE2PLUS_EVP_PKEY_CTX_SET_HKDF_MD_FAILED,
    /*! \brief */
    SPAKE2PLUS_EVP_PKEY_CTX_SET_HKDF_SALT_FAILED,
    /*! \brief */
    SPAKE2PLUS_EVP_PKEY_CTX_SET_HKDF_KEY_FAILED,
    /*! \brief */
    SPAKE2PLUS_EVP_PKEY_CTX_SET_HKDF_INFO_FAILED,
    /*! \brief */
    SPAKE2PLUS_EVP_PKEY_DERIVE_FAILED,
    /*! \brief */
    SPAKE2PLUS_KE_LEN_NULL,
    /*! \brief */
    SPAKE2PLUS_FA_FB_KEY_LEN_MISMATCH,
    /*! \brief */
    SPAKE2PLUS_FA_FB_KEY_MISMATCH,
    /*! \brief */
    SPAKE2PLUS_OPENSSL_BN_LSHIFT_FAILED,
    /*! \brief */
    SPAKE2PLUS_OPENSSL_BN_SET_WORD_FAILED,
    /*! \brief */
    SPAKE2PLUS_NID_UNSUPPORTED,
    /*! \brief */
    SPAKE2PLUS_ED25519_SUBTRAHEND_FAILED,
    /*! \brief */
    SPAKE2PLUS_ED448_SUBTRAHEND_FAILED,
    /*! \brief */
    SPAKE2PLUS_NULL_LEN_POINTER,
    /*! \brief */
    SPAKE2PLUS_INCORRECT_LEN,
    /*! \brief */
    SPAKE2PLUS_INCORRECT_W0,
    /*! \brief */
    SPAKE2PLUS_INCORRECT_W1_OR_L,
    /*! \brief */
    SPAKE2PLUS_PA_OR_PB_REQUIRES_TO_POINT_TO_NULL,
    /*! \brief */
    SPAKE2PLUS_PASSWORD_NOT_INITIALIZED,
    /*! \brief */
    SPAKE2PLUS_ZERO_RANDOM_VAL,
    /*! \brief */
    SPAKE2PLUS_INCORRECT_PA_OR_PB,
    /*! \brief */
    SPAKE2PLUS_IS_GROUP_IDENTITY,
    /*! \brief */
    SPAKE2PLUS_FA_OR_FB_IS_NULL,
    /*! \brief */
    SPAKE2PLUS_KCAKCB_IS_NULL,
    /*! \brief */
    SPAKE2PLUS_KE_NOT_AVAILABLE,
    /*! \brief */
    SPAKE2PLUS_EC_POINT_POINT2BN_FAILED,
    /*! \brief */
    SPAKE2PLUS_EC_POINT_POINT2OCT_FAILED,
    /*! \brief */
    SPAKE2PLUS_EC_POINT_SET_COORD_FAILED,
    /*! \brief */
    SPAKE2PLUS_EC_POINT_NEW_FAILED,
    /*! \brief */
    SPAKE2PLUS_EC_POINT_MUL_FAILED,
    /*! \brief */
    SPAKE2PLUS_EC_POINT_ADD_FAILED,
    /*! \brief */
    SPAKE2PLUS_EC_POINT_INVERT_FAILED,
    /*! \brief */
    SPAKE2PLUS_POINT_NOT_ON_EC,
    /*! \brief */
    SPAKE2PLUS_FAILED_TO_CHECK_IF_POINT_ON_EC

};

/*! \brief This enumeration is used to select client or server instance type. */
enum spake2plus_client_server
{
    /*! \brief Client or server role is not specified.*/
    SPAKE2PLUS_CLIENT_SERVER_UNDEFINED = 0,
    /*! \brief Client role */
    SPAKE2PLUS_CLIENT = 1,
    /*! \brief Server role */
    SPAKE2PLUS_SERVER = 2
};

/*! \brief The function prototype for selecting different MAC functions.
 *
 * Not to be used directly, there is a string recognition interface
 * in spake2plus_init.
 * */
typedef int (*Spake2plus_MAC)(
    /*! \brief The returning hash value, max length is EVP_MAX_MD_SIZE. */
    uint8_t *return_hash,
    /*! \brief The actual hash length of the returning hash value. */
    size_t *return_hash_len,
    /*! \brief The key to be used in MAC function MAC(key, message). */
    uint8_t *key,
    /*! \brief The key length. */
    size_t key_len,
    /*! \brief The message to be used in MAC function MAC(key, message). */
    uint8_t *message,
    /*! \brief The message length. */
    size_t message_len,
    /*! \brief The hash function object, to be used with HMAC only. */
    const EVP_MD *evp_md);

struct spake2plus_inst_st
{
    /*! \brief The prime number to be used in conjunction with chosen group. */
    BIGNUM *prime;
    /*! \brief The cofactor or h value for chosen group. */
    BIGNUM *cofactor;
    /*! \brief The w0 value for current protocol setup. */
    BIGNUM *w0;
    /*! \brief The w1 value for current protocol setup. */
    BIGNUM *w1;
    /*! \brief The M EC point for chosen group. */
    EC_POINT *M;
    /*! \brief The N EC point for chosen group. */
    EC_POINT *N;
    /*! \brief The current EC point X to be converted to pA setup protocol value. */
    EC_POINT *pA;
    /*! \brief The current EC point Y to be converted to pB setup protocol value. */
    EC_POINT *pB;
    /*! \brief The current BIGNUM random value x on client or y on server for protocol setup. */
    BIGNUM *random_value;
    /*! \brief The generator EC point for chosen group. */
    const EC_POINT *generator;
    /*! \brief The current EC point L=generator*w1 for current protocol setup. */
    EC_POINT *L;
    /*! \brief The pointer for chosen EC group. */
    EC_GROUP *group;
    /*! \brief The pointer to Additional Authenticated Data shared among client and server. */
    uint8_t *AAD;
    /*! \brief The length of Additional Authenticated Data shared among client and server. */
    size_t AAD_len;
    /*! \brief The pointer to client identity shared among client and server. */
    uint8_t *idA;
    /*! \brief The length of client identity shared among client and server. */
    size_t idA_len;
    /*! \brief The pointer to server identity shared among client and server. */
    uint8_t *idB;
    /*! \brief The length of server identity shared among client and server. */
    size_t idB_len;
    /*! \brief The pointer to chosen MAC function. */
    Spake2plus_MAC MAC_func;
    /*! \brief The pointer to chosen EVP_MD object representing a Hash function. */
    const EVP_MD *evp_md;
    /*! \brief The client or server instance type specifier. */
    int client_server;
    /*! \brief The shared secret key for client and server. */
    uint8_t Ke[EVP_MAX_MD_SIZE];
    /*! \brief The actual length for shared secret key for client and server. */
    size_t Ke_len;
    /*! \brief The pointer to current KcA and KcB values to be used during key verification. */
    uint8_t *KcAKcB;
    /*! \brief The length of current KcA and KcB values to be used during key verification. */
    size_t KcAKcB_len;
};

/* PUBLIC */
typedef struct spake2plus_inst_st SPAKE2PLUS;

/*! \defgroup spake2plus_version spake2plus_version
 *  \ingroup spake2plus_public
 */
 /*! \ingroup spake2plus_version
  *  \brief This function reports the version of the spake2plus library.
  *  \return pointer to the version string.
  * */
const char *spake2plus_version();

/*! \defgroup spake2plus_init spake2plus_init
 *  \ingroup spake2plus_public
 */
/*! \ingroup spake2plus_init
 *  \brief This function initializes SPAKE2+ instance and returns pointer to it in the first parameter.
 *  \param instance a pointer to SPAKE2+ instance to be initialized.
 *  \param client_id a client identity
 *  \param client_id_len a length of the client identity
 *  \param server_id a server identity
 *  \param server_id_len a length of the server identity
 *  \param additional_authenticated_data (AAD), data that is shared between client and server and different from identities
 *  \param additional_authenticated_data_len a length of the AAD
 *  \param group_name a string that should contain one of the supported groups "P-256", "P-384" or "P-521"
 *  \param evp_md_name a string that should contain one of the supported Hash functions "SHA256" or "SHA512"
 *  \param MAC_func_name a string that should contain one of the supported MAC functions "HMAC" or "CMAC"
 *  \param client_or_server an instance type selector, should be SPAKE2PLUS_CLIENT or SPAKE2PLUS_SERVER
 *  \return SPAKE2PLUS_OK (== 0) on success or error code.
 * */
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
    int client_or_server);

/*! \defgroup spake2plus_pwd_init spake2plus_pwd_init
 *  \ingroup spake2plus_public
 * */
/*!
 *  \ingroup spake2plus_pwd_init
 *  \brief This function initializes password data in SPAKE2+ instance.
 *  \param instance a pointer to SPAKE2+ instance to be initialized.
 *  \param pw a password.
 *  \param pw_len a length of the password \a pw.
 *  \return SPAKE2PLUS_OK (== 0) or error code.
 */
int spake2plus_pwd_init(
    SPAKE2PLUS *instance,
    char *pw,
    size_t pw_len);

/*! \defgroup spake2plus_load_L_w0 spake2plus_load_L_w0
 *  \ingroup spake2plus_public
 */
/*! \ingroup spake2plus_load_L_w0
 *  \brief This function initializes password data in SPAKE2+ instance.
 *  \param instance a pointer to SPAKE2+ instance to be initialized.
 *  \param pL an EC point L in uncompressed format
 *  \param pL_len a length of the \a pL.
 *  \param pw0 a BIGNUM L as a byte string
 *  \param pw0_len a length of the \a pw0.
 *  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
int spake2plus_load_L_w0(
    SPAKE2PLUS *instance,
    uint8_t *pL,
    size_t pL_len,
    uint8_t *pw0,
    size_t pw0_len);

/*! \defgroup spake2plus_setup_protocol spake2plus_setup_protocol
 *  \ingroup spake2plus_public
 */
/*! \ingroup spake2plus_setup_protocol
 *  \brief This function initializes SPAKE2+ instance with own pA or pB setup key (EC point).
 *  \param instance a pointer to SPAKE2+ instance to be initialized for new connection
 *  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
int spake2plus_setup_protocol(
    SPAKE2PLUS *instance);

/*! \defgroup spake2plus_get_own_pA_or_pB spake2plus_get_own_pA_or_pB
 *  \ingroup spake2plus_public
 *  */
/*! \ingroup spake2plus_get_own_pA_or_pB
 *  \brief This function obtains own pA or pB setup keys from SPAKE2+ instance.
 *
 *  If not sure how long should be the buffer, send NULL as buffer and obtain the required length.
 *  NULL Ke_len or uninitialized/NULL instance produce errors.
 *  \param pA_or_pB an uncompressed representation of EC point pA for client or pB for server. If NULL, only its length is returned
 *  \param pA_or_pB_len a length of the uncompressed EC point pA or pB representation
 *  \param instance a pointer to an initialized SPAKE2+ instance that stores EC point pA or pB
 *  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
int spake2plus_get_own_pA_or_pB(
    uint8_t *pA_or_pB,
    size_t *pA_or_pB_len,
    SPAKE2PLUS *instance);

/*! \defgroup spake2plus_derive_confirmation_keys spake2plus_derive_confirmation_keys
 *  \ingroup spake2plus_public
 *  */
/*! \ingroup spake2plus_derive_confirmation_keys
 *  \brief This function derives confirmation keys Fa or Fb
 *
 *  It is necessary to provide foreign pA or pB setup keys and a pointer to SPAKE2+ instance that passed through spake2plus_protocol_setup.
 *  \param Fa_or_Fb a confirmation key Fa for client and Fb for server
 *  \param Fa_or_Fb_len a confirmation key length (enough to set it to EVP_MAX_MD_SIZE)
 *  \param instance a pointer to a SPAKE2+ instance that passed through initialization and setup
 *  \param pA_or_pB an uncompressed representation of EC point from the counterpart (pB for client or pA for server)
 *  \param pA_or_pB_len a length of the uncompressed EC point pA or pB representation
 *  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
int spake2plus_derive_confirmation_keys(
    uint8_t *Fa_or_Fb,
    size_t *Fa_or_Fb_len,
    SPAKE2PLUS *instance,
    uint8_t *pA_or_pB,
    size_t pA_or_pB_len);

/*! \defgroup spake2plus_verify spake2plus_verify
 *  \ingroup spake2plus_public
 *  */
/*! \ingroup spake2plus_verify
 *  \brief This function check counterpart's confirmation keys Fa or Fb
 *  \param Fa_or_Fb a confirmation key from the counterpart
 *  \param Fa_or_Fb_len a length of the confirmation key from the counterpart
 *  \param instance a pointer to a fully initialized SPAKE2+ instance after spake2plus_derive_confirmation_keys
 *  \return SPAKE2PLUS_OK (== 0) if the confirmation key is correct or error code.
 */
int spake2plus_verify(
    SPAKE2PLUS *instance,
    uint8_t *Fa_or_Fb,
    size_t Fa_or_Fb_len);

/*! \defgroup spake2plus_get_key_Ke spake2plus_get_key_Ke
 *  \ingroup spake2plus_public
 *  */
/*! \ingroup spake2plus_get_key_Ke
 *  \brief This function obtains shared secret Ke from SPAKE2+ instance.
 *
 *  If not sure how long should be the buffer, send NULL as buffer and obtain the required length.
 *  NULL Ke_len or uninitialized/NULL instance produce errors.
 *  \param Ke a secret shared key derived through the SPAKE2+ protocol
 *  \param Ke_len a length of the secrec shared key Ke
 *  \param instance a pointer to a fully initialized SPAKE2+ instance after spake2plus_derive_confirmation_keys
 *  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
int spake2plus_get_key_Ke(
    uint8_t *Ke,
    size_t *Ke_len,
    SPAKE2PLUS *instance);


/*! \defgroup spake2plus_free spake2plus_free
 *  \ingroup spake2plus_public
 *  */
/*! \ingroup spake2plus_free
 *  \brief This function correctly released previously allocated memory and destroys SPAKE2PLUS instance
 *  \param instance the pointer to instance any SPAKE2+ instance
 */
void spake2plus_free(SPAKE2PLUS *instance);

/*! \defgroup spake2plus_openssl_cleanup spake2plus_openssl_cleanup
 *  \ingroup spake2plus_public
 *  */
/*! \ingroup spake2plus_openssl_cleanup
 *  \brief This function deinitializes OpenSSL and frees all its internally created objects
 */
void spake2plus_openssl_cleanup();

#endif /* INCLUDE_SPAKE2PLUS_H_ */
