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

#ifndef INCLUDE_SPAKE2PLUS_TEST_H_
#define INCLUDE_SPAKE2PLUS_TEST_H_

/*! \file spake2plus_test.h
 * Common SPAKE2+ library declarations.
 * */
/*! \defgroup spake2plus_test SPAKE2+ test functions
 *
 * \brief These functions are intended for tests only.
 *
 * Normally user does not need to call these functions directly.
 */

/*! \struct t_test_vector
 * \brief Structure for storing test vectors from SPAKE2+ standard.
 *
 * This structure stores test vectors byte strings and their lengths.
 */
typedef struct
{
        /*! \brief */
        uint8_t *w0;
        /*! \brief */
        size_t w0_len;
        /*! \brief */
        uint8_t *w1;
        /*! \brief */
        size_t w1_len;
        /*! \brief */
        uint8_t *L;
        /*! \brief */
        size_t L_len;
        /*! \brief */
        uint8_t *X;
        /*! \brief */
        size_t X_len;
        /*! \brief */
        uint8_t *Y;
        /*! \brief */
        size_t Y_len;
        /*! \brief */
        uint8_t *Z;
        /*! \brief */
        size_t Z_len;
        /*! \brief */
        uint8_t *V;
        /*! \brief */
        size_t V_len;
        /*! \brief */
        uint8_t *TT;
        /*! \brief */
        size_t TT_len;
        /*! \brief */
        uint8_t *Ka;
        /*! \brief */
        size_t Ka_len;
        /*! \brief */
        uint8_t *Ke;
        /*! \brief */
        size_t Ke_len;
        /*! \brief */
        uint8_t *KcA;
        /*! \brief */
        size_t KcA_len;
        /*! \brief */
        uint8_t *KcB;
        /*! \brief */
        size_t KcB_len;
        /*! \brief */
        uint8_t *MAC_A;
        /*! \brief */
        size_t MAC_A_len;
        /*! \brief */
        uint8_t *MAC_B;
        /*! \brief */
        size_t MAC_B_len;
} t_test_vector;


/*! \defgroup spake2plus_printf_debug spake2plus_printf_debug
 *  \ingroup spake2plus_test
 *  */
/*! \ingroup spake2plus_printf_debug
 *  \brief This function prints the string \a fmt followed by a BIGNUM \a bn_to_be_printed to \a stream if do_printf is non-zero.
 *  \param do_printf enables printing if non-zero
 *  \param stream specifies where to send data for printing; NULL means stdout
 *  \param bn_to_be_printed is the pointer to a BIGNUM to be printed; if NULL, only \a fmt string is printed
 *  \param fmt is the zero-terminated string of char to be printed
 */
void spake2plus_printf_debug(int do_printf, FILE *stream, const BIGNUM *bn_to_be_printed, const char *fmt);

/*! \defgroup spake2plus_print_ec_point spake2plus_print_ec_point
 *  \ingroup spake2plus_test
 *  */
/*! \ingroup spake2plus_print_ec_point
 *  \brief This function prints a string \a fmt followed by a EC_POINT \a ec_to_be_printed in the selected conversion \a form to \a stream if do_printf is non-zero.
 *  \param do_printf enables printing if non-zero
 *  \param stream specifies where to send data for printing; NULL means stdout
 *  \param instance is the pointer to an initialized SPAKE2+ instance
 *  \param ec_to_be_printed is the pointer to a EC_POINT to be printed; if NULL, only \a fmt string is printed
 *  \param form specifies the EC_POINT conversion form
 *  \param fmt is the zero-terminated string of char to be printed
 *  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
int spake2plus_print_ec_point(int do_printf,
                              FILE *stream,
                              SPAKE2PLUS *instance,
                              const EC_POINT *ec_to_be_printed,
                              point_conversion_form_t form,
                              const char *fmt);

/*! \defgroup spake2plus_print_array spake2plus_print_array
 *  \ingroup spake2plus_test
 *  */
/*! \ingroup spake2plus_print_array
 *  \brief This function prints the \a array of \a bytes as two-digit hex numbers to \a stream if do_printf is non-zero.
 *  \param do_printf enables printing if non-zero
 *  \param stream specifies where to send data for printing; NULL means stdout
 *  \param array is a pointer to a BIGNUM to be printed
 *  \param len specifies the length of the \a array
 */
void spake2plus_print_array(int do_printf, FILE *stream, const uint8_t *array, const size_t len);


/*! \defgroup spake2plus_generate_keys_Z_V spake2plus_generate_keys_Z_V
 *  \ingroup spake2plus_test
 *  */
/*! \ingroup spake2plus_generate_keys_Z_V
 *  \brief This function generates Z and V EC_POINT according to the standard.
 *  \param Z is the pointer to a preallocated EC_POINT, contains value Z=h*x*(Y-w0*N) for client and Z=h*y*(X- w0*M) for server
 *  \param V is the pointer to a preallocated EC_POINT, contains value V=h*w1*(Y-w0*N) for client and V=h*y*L for server
 *  \param instance is the pointer to a SPAKE2+ instance with both provided pA and pB EC points
 *  \param ctx is the pointer to an allocated and preinitialized BN_CTX structure
 *  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
int spake2plus_generate_keys_Z_V(
    EC_POINT *Z,
    EC_POINT *V,
    SPAKE2PLUS *instance,
    BN_CTX *ctx);

/*! \defgroup spake2plus_get_hash spake2plus_get_hash
 *  \ingroup spake2plus_test
 *  */
/*! \ingroup spake2plus_get_hash
 *  \brief This function calculates hash from \a TT with \a instance->evp_md hash function and puts it into \a md_value.
 *  \param md_value is the pointer to a preallocated byte array of length EVP_MAX_MD_SIZE
 *  \param md_len is the pointer actual length of the hash in \a md_value
 *  \param instance is the pointer to a SPAKE2+ instance with evp_md hash function provided
 *  \param TT is the pointer to an input array of bytes to the hash function
 *  \param TT_len is the length of \a TT
 *  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
int spake2plus_get_hash(
    uint8_t *md_value,
    size_t *md_len,
    SPAKE2PLUS *instance,
    uint8_t *TT,
    size_t TT_len);

/*! \defgroup spake2plus_generate_TT spake2plus_generate_TT
 *  \ingroup spake2plus_test
 *  */
/*! \ingroup spake2plus_generate_TT
 *  \brief This function extracts and concatenates values to create \a TT
 *
 *  \a TT is the following concatenation (concatenation is denoted by the symbol ||)
 *   TT = len(A) || A || len(B) || B || len(X) || X
              || len(Y) || Y || len(Z) || Z || len(V) || V
              || len(w0) || w0
 *  \param TT is the pointer to a pointer to an input array of bytes to the hash function
 *  \param TT_len is the pointer to the length of \a TT
 *  \param instance is the pointer to an initialized SPAKE2+ instance
 *  \param Z is the pointer to a preallocated EC_POINT, contains value Z=h*x*(Y-w0*N) for client and Z=h*y*(X- w0*M) for server
 *  \param V is the pointer to a preallocated EC_POINT, contains value V=h*w1*(Y-w0*N) for client and V=h*y*L for server
*  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
int spake2plus_generate_TT(
    uint8_t **TT,
    size_t *TT_len,
    SPAKE2PLUS *instance,
    EC_POINT *Z,
    EC_POINT *V);

/*! \defgroup spake2plus_calculate_HKDF spake2plus_calculate_HKDF
 *  \ingroup spake2plus_test
 *  */
/*! \ingroup spake2plus_calculate_HKDF
 *  \brief This function calculates KcA and KcB values from the shared secret key Ka and AAD.
 *
 *  Empty string as a salt, \a Ka as a key and the following concatenation
 *  (concatenation is denoted by the symbol ||) are profided to HKDF function
 *   KcA || KcB = HKDF(nil, Ka, "ConfirmationKeys" || AAD)
 *  \param KcAKcB is the pointer to the byte string containing both KcA and KcB keys
 *  \param KcAKcB_len is the pointer to the length of \a KcAKcB
 *  \param instance is the pointer to an initialized SPAKE2+ instance
 *  \param Ka is the pointer to the shared secret, derived as the first half of the TT hash: Ka || Ke = Hash(TT)
 *  \param Ka_len is the length of the shared secred Ka
*  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
int spake2plus_calculate_HKDF(
    uint8_t *KcAKcB,
    size_t *KcAKcB_len,
    SPAKE2PLUS *instance,
    uint8_t *Ka,
    size_t Ka_len);

/*! \defgroup spake2plus_select_KcA_KcB spake2plus_select_KcA_KcB
 *  \ingroup spake2plus_test
 *  */
/*! \ingroup spake2plus_select_KcA_KcB
 *  \brief This function chooses own or foreign key from the concatenated array with KcA and KcB.
 *
 *  So if \a choose_own != 0 then KcA is returned for client and KcB is returned for server.
 *  So if \a choose_own == 0 then KcB is returned for client and KcA is returned for server.
 *  \param instance is the pointer to an initialized SPAKE2+ instance
 *  \param choose_own selects if own or foreign key should be returned from the array with KcA and KcB
*  \return -KcA if choose_own !=0 and instance is client or choose_own == 0 and instance is server;
*          -KcB if choose_own !=0 and instance is server or choose_own == 0 and instance is client;
 */
inline uint8_t *spake2plus_select_KcA_KcB(
    SPAKE2PLUS *instance,
    int choose_own);


/*! \defgroup spake2plus_get_own_Fa_or_Fb spake2plus_get_own_Fa_or_Fb
 *  \ingroup spake2plus_test
 *  */
/*! \ingroup spake2plus_get_own_Fa_or_Fb
 *  \brief This function generates own values Fa = MAC(KcA, pB) (for client) or Fb = MAC(KcB, pA) (for server).
 *  \param Fa_or_Fb is the pointer to a preallocated array of minimal size EVP_MAX_MD_SIZE bytes
 *  \param Fa_or_Fb_len is the pointer to actual length of \a Fa_or_Fb
 *  \param instance is the pointer to a SPAKE2+ instance with both provided pA and pB EC points and calculated KcAKcB keys
 *  \param ctx is the pointer to an allocated and preinitialized BN_CTX structure
 *  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
int spake2plus_get_own_Fa_or_Fb(
    uint8_t *Fa_or_Fb,
    size_t *Fa_or_Fb_len,
    SPAKE2PLUS *instance,
    BN_CTX *ctx);

/*! \defgroup spake2plus_set_ec_point_from_uncompressed spake2plus_set_ec_point_from_uncompressed
 *  \ingroup spake2plus_test
 *  */
/*! \ingroup spake2plus_set_ec_point_from_uncompressed
 *  \brief This function sets the EC point from an array of bytes representing EC point in uncompressed form
 *  \param group is the EC group that should contain the target EC point
 *  \param point is the pointer to actual length of \a Fa_or_Fb
 *  \param uncompressed_point is the pointer to byte array containing an uncompressed form of the EC point
 *  \param uncompressed_point_len is the length of the byte array \a uncompressed_point
 *  \return SPAKE2PLUS_OK (== 0) on success or error code.
 */
void spake2plus_set_ec_point_from_uncompressed(
    EC_GROUP *group,
    EC_POINT *point,
    uint8_t *uncompressed_point,
    size_t uncompressed_point_len);

#endif /* INCLUDE_SPAKE2PLUS_TEST_H_ */
