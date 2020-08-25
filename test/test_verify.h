#pragma once

void test_verify_incorrect_instance(void);
void test_verify_incorrect_Fa_or_Fb_s(void);
void test_verify_incorrect_Fa_or_Fb_c(void);
void test_verify_incorrect_Fa_or_Fb_len_s(void);
void test_verify_incorrect_Fa_or_Fb_len_c(void);
void test_verify_incorrect_no_derive_c(void);
void test_verify_incorrect_no_derive_s(void);
void test_verify_default_s(void);
void test_verify_default_c(void);
void test_verify_default_p256_sha512_cmac_s(void);
void test_verify_default_p256_sha256_cmac_c(void);
void test_verify_default_p384_sha256_hmac_s(void);
void test_verify_default_p384_sha512_hmac_c(void);
void test_verify_default_p521_sha512_hmac_s(void);
void test_verify_default_p521_sha256_hmac_c(void);
void test_verify_incorrect_broken_session_0_c(void);
void test_verify_incorrect_broken_session_0_s(void);
void test_verify_incorrect_broken_session_1_c(void);
void test_verify_incorrect_broken_session_1_s(void);
void test_verify_incorrect_p256sha256hmac_vs_p256sha256cmac_s(void);
void test_verify_incorrect_p256sha256hmac_vs_p256sha512hmac_c(void);

#define DECLARE_TESTS_VERIFY()                                          \
    RUN_TEST(test_verify_incorrect_instance);                           \
    RUN_TEST(test_verify_incorrect_Fa_or_Fb_s);                         \
    RUN_TEST(test_verify_incorrect_Fa_or_Fb_c);                         \
    RUN_TEST(test_verify_incorrect_Fa_or_Fb_len_s);                     \
    RUN_TEST(test_verify_incorrect_Fa_or_Fb_len_c);                     \
    RUN_TEST(test_verify_incorrect_no_derive_c);                        \
    RUN_TEST(test_verify_incorrect_no_derive_s);                        \
    RUN_TEST(test_verify_default_s);                                    \
    RUN_TEST(test_verify_default_c);                                    \
    RUN_TEST(test_verify_default_p256_sha512_cmac_s);                   \
    RUN_TEST(test_verify_default_p256_sha256_cmac_c);                   \
    RUN_TEST(test_verify_default_p384_sha256_hmac_s);                   \
    RUN_TEST(test_verify_default_p384_sha512_hmac_c);                   \
    RUN_TEST(test_verify_default_p521_sha512_hmac_s);                   \
    RUN_TEST(test_verify_default_p521_sha256_hmac_c);                   \
    RUN_TEST(test_verify_incorrect_broken_session_0_s);                 \
    RUN_TEST(test_verify_incorrect_broken_session_0_c);                 \
    RUN_TEST(test_verify_incorrect_broken_session_1_s);                 \
    RUN_TEST(test_verify_incorrect_broken_session_1_c);                 \
    RUN_TEST(test_verify_incorrect_p256sha256hmac_vs_p256sha256cmac_s); \
    RUN_TEST(test_verify_incorrect_p256sha256hmac_vs_p256sha512hmac_c);
/*
//void test_verify_default_ed25519_sha256_hmac_s(void);
//void test_verify_default_ed25519_sha512_hmac_c(void);
//void test_verify_default_ed448_sha512_hmac_s(void);
//void test_verify_default_ed448_sha256_hmac_c(void);
//RUN_TEST(test_verify_default_ed25519_sha256_hmac_s); \
//RUN_TEST(test_verify_default_ed25519_sha512_hmac_c); \
//RUN_TEST(test_verify_default_ed448_sha512_hmac_s); \
//RUN_TEST(test_verify_default_ed448_sha256_hmac_c); \
*/
