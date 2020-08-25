#pragma once

void test_get_Ke_incorrect_instance(void);
void test_get_Ke_correct_null_Ke_s(void);
void test_get_Ke_correct_null_Ke_c(void);
void test_get_Ke_incorrect_null_Ke_len_s(void);
void test_get_Ke_incorrect_null_Ke_len_c(void);
void test_get_Ke_incorrect_no_derive_c(void);
void test_get_Ke_incorrect_no_derive_s(void);
void test_get_Ke_default_s(void);
void test_get_Ke_default_c(void);
void test_get_Ke_default_p256_sha512_cmac_s(void);
void test_get_Ke_default_p256_sha256_cmac_c(void);
void test_get_Ke_default_p384_sha256_hmac_s(void);
void test_get_Ke_default_p384_sha512_hmac_c(void);
void test_get_Ke_default_p521_sha512_hmac_s(void);
void test_get_Ke_default_p521_sha256_hmac_c(void);

#define DECLARE_TESTS_GET_KE()                             \
    RUN_TEST(test_get_Ke_incorrect_instance);              \
    RUN_TEST(test_get_Ke_correct_null_Ke_s);               \
    RUN_TEST(test_get_Ke_correct_null_Ke_c);               \
    RUN_TEST(test_get_Ke_incorrect_null_Ke_len_s);         \
    RUN_TEST(test_get_Ke_incorrect_null_Ke_len_c);         \
    RUN_TEST(test_get_Ke_incorrect_no_derive_c);           \
    RUN_TEST(test_get_Ke_incorrect_no_derive_s);           \
    RUN_TEST(test_get_Ke_default_s);                       \
    RUN_TEST(test_get_Ke_default_c);                       \
    RUN_TEST(test_get_Ke_default_p256_sha512_cmac_s);      \
    RUN_TEST(test_get_Ke_default_p256_sha256_cmac_c);      \
    RUN_TEST(test_get_Ke_default_p384_sha256_hmac_s);      \
    RUN_TEST(test_get_Ke_default_p384_sha512_hmac_c);      \
    RUN_TEST(test_get_Ke_default_p521_sha512_hmac_s);      \
    RUN_TEST(test_get_Ke_default_p521_sha256_hmac_c);      \
/*                                                         \
//void test_get_Ke_default_ed25519_sha256_hmac_s(void);    \
//void test_get_Ke_default_ed25519_sha512_hmac_c(void);    \
//void test_get_Ke_default_ed448_sha512_hmac_s(void);      \
//void test_get_Ke_default_ed448_sha256_hmac_c(void);      \
//    RUN_TEST(test_get_Ke_default_ed25519_sha256_hmac_s); \
//    RUN_TEST(test_get_Ke_default_ed25519_sha512_hmac_c); \
//    RUN_TEST(test_get_Ke_default_ed448_sha512_hmac_s);   \
//    RUN_TEST(test_get_Ke_default_ed448_sha256_hmac_c);   \
*/
