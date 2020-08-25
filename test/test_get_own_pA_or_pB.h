#pragma once

void test_get_own_pA_or_pB_incorrect_instance(void);
void test_get_own_pA_or_pB_incorrect_only_init_c(void);
void test_get_own_pA_or_pB_incorrect_only_init_s(void);
void test_get_own_pA_or_pB_incorrect_only_init_pw_c(void);
void test_get_own_pA_or_pB_incorrect_only_init_pw_s(void);
void test_get_own_pA_or_pB_default_s(void);
void test_get_own_pA_or_pB_default_c(void);
void test_get_own_pA_or_pB_back_conversion_c(void);
void test_get_own_pA_or_pB_back_conversion_s(void);
void test_get_own_pA_or_pB_correct_null_pA_or_pB_s(void);
void test_get_own_pA_or_pB_correct_null_pA_or_pB_c(void);
void test_get_own_pA_or_pB_incorrect_null_pA_or_pB_len_s(void);
void test_get_own_pA_or_pB_incorrect_null_pA_or_pB_len_c(void);
void test_get_own_pA_or_pB_default_p256_sha512_cmac_s(void);
void test_get_own_pA_or_pB_default_p256_sha256_cmac_c(void);
void test_get_own_pA_or_pB_default_p384_sha256_hmac_s(void);
void test_get_own_pA_or_pB_default_p384_sha512_hmac_c(void);
void test_get_own_pA_or_pB_default_p521_sha512_hmac_s(void);
void test_get_own_pA_or_pB_default_p521_sha256_hmac_c(void);

#define DECLARE_TESTS_GET_PA_OR_PB()                               \
    RUN_TEST(test_get_own_pA_or_pB_incorrect_instance);            \
    RUN_TEST(test_get_own_pA_or_pB_incorrect_only_init_c);         \
    RUN_TEST(test_get_own_pA_or_pB_incorrect_only_init_s);         \
    RUN_TEST(test_get_own_pA_or_pB_incorrect_only_init_pw_c);      \
    RUN_TEST(test_get_own_pA_or_pB_incorrect_only_init_pw_s);      \
    RUN_TEST(test_get_own_pA_or_pB_default_s);                     \
    RUN_TEST(test_get_own_pA_or_pB_default_c);                     \
    RUN_TEST(test_get_own_pA_or_pB_back_conversion_c);             \
    RUN_TEST(test_get_own_pA_or_pB_back_conversion_s);             \
    RUN_TEST(test_get_own_pA_or_pB_correct_null_pA_or_pB_s);       \
    RUN_TEST(test_get_own_pA_or_pB_correct_null_pA_or_pB_c);       \
    RUN_TEST(test_get_own_pA_or_pB_incorrect_null_pA_or_pB_len_s); \
    RUN_TEST(test_get_own_pA_or_pB_incorrect_null_pA_or_pB_len_c); \
    RUN_TEST(test_get_own_pA_or_pB_default_p256_sha512_cmac_s);    \
    RUN_TEST(test_get_own_pA_or_pB_default_p256_sha256_cmac_c);    \
    RUN_TEST(test_get_own_pA_or_pB_default_p384_sha256_hmac_s);    \
    RUN_TEST(test_get_own_pA_or_pB_default_p384_sha512_hmac_c);    \
    RUN_TEST(test_get_own_pA_or_pB_default_p521_sha512_hmac_s);    \
    RUN_TEST(test_get_own_pA_or_pB_default_p521_sha256_hmac_c);
