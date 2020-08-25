#pragma once

void test_derive_conf_incorrect_instance(void);
void test_derive_conf_incorrect_only_init_c(void);
void test_derive_conf_incorrect_only_init_s(void);
void test_derive_conf_incorrect_only_init_pw_c(void);
void test_derive_conf_incorrect_only_init_pw_s(void);
void test_derive_conf_incorrect_Fa_or_Fb_s(void);
void test_derive_conf_incorrect_Fa_or_Fb_c(void);
void test_derive_conf_incorrect_Fa_or_Fb_len_s(void);
void test_derive_conf_incorrect_Fa_or_Fb_len_c(void);
void test_derive_conf_incorrect_pA_or_pB_null_s(void);
void test_derive_conf_incorrect_pA_or_pB_null_c(void);
void test_derive_conf_incorrect_pA_or_pB_short_s(void);
void test_derive_conf_incorrect_pA_or_pB_short_c(void);
void test_derive_conf_incorrect_pA_or_pB_long_s(void);
void test_derive_conf_incorrect_pA_or_pB_long_c(void);
void test_derive_conf_incorrect_pA_or_pB_len_0_s(void);
void test_derive_conf_incorrect_pA_or_pB_len_0_c(void);
void test_derive_conf_default_s(void);
void test_derive_conf_default_c(void);
void test_derive_conf_p256_sha512_cmac_s(void);
void test_derive_conf_p256_sha256_cmac_c(void);
void test_derive_conf_p384_sha256_hmac_s(void);
void test_derive_conf_p384_sha512_hmac_c(void);
void test_derive_conf_p521_sha512_hmac_s(void);
void test_derive_conf_p521_sha256_hmac_c(void);
void test_derive_conf_incorrect_p256_sha512_cmac_group_identity_s(void);
void test_derive_conf_incorrect_p384_sha256_hmac_group_identity_c(void);
void test_derive_conf_incorrect_p521_sha256_hmac_group_identity_s(void);

#define DECLARE_TESTS_DERIVE_CONF()                                           \
    RUN_TEST(test_derive_conf_incorrect_instance);                            \
    RUN_TEST(test_derive_conf_incorrect_only_init_c);                         \
    RUN_TEST(test_derive_conf_incorrect_only_init_s);                         \
    RUN_TEST(test_derive_conf_incorrect_only_init_pw_c);                      \
    RUN_TEST(test_derive_conf_incorrect_only_init_pw_s);                      \
    RUN_TEST(test_derive_conf_incorrect_Fa_or_Fb_s);                          \
    RUN_TEST(test_derive_conf_incorrect_Fa_or_Fb_c);                          \
    RUN_TEST(test_derive_conf_incorrect_Fa_or_Fb_len_s);                      \
    RUN_TEST(test_derive_conf_incorrect_Fa_or_Fb_len_c);                      \
    RUN_TEST(test_derive_conf_incorrect_pA_or_pB_null_s);                     \
    RUN_TEST(test_derive_conf_incorrect_pA_or_pB_null_c);                     \
    RUN_TEST(test_derive_conf_incorrect_pA_or_pB_short_s);                    \
    RUN_TEST(test_derive_conf_incorrect_pA_or_pB_short_c);                    \
    RUN_TEST(test_derive_conf_incorrect_pA_or_pB_long_s);                     \
    RUN_TEST(test_derive_conf_incorrect_pA_or_pB_long_c);                     \
    RUN_TEST(test_derive_conf_incorrect_pA_or_pB_len_0_s);                    \
    RUN_TEST(test_derive_conf_incorrect_pA_or_pB_len_0_c);                    \
    RUN_TEST(test_derive_conf_default_s);                                     \
    RUN_TEST(test_derive_conf_default_c);                                     \
    RUN_TEST(test_derive_conf_p256_sha512_cmac_s);                            \
    RUN_TEST(test_derive_conf_p256_sha256_cmac_c);                            \
    RUN_TEST(test_derive_conf_p384_sha256_hmac_s);                            \
    RUN_TEST(test_derive_conf_p384_sha512_hmac_c);                            \
    RUN_TEST(test_derive_conf_p521_sha512_hmac_s);                            \
    RUN_TEST(test_derive_conf_p521_sha256_hmac_c);                            \
    RUN_TEST(test_derive_conf_incorrect_p256_sha512_cmac_group_identity_s);   \
    RUN_TEST(test_derive_conf_incorrect_p384_sha256_hmac_group_identity_c);   \
    RUN_TEST(test_derive_conf_incorrect_p521_sha256_hmac_group_identity_s);   \
/*                                                                            \
//void test_derive_conf_ed25519_sha256_hmac_s(void);                          \
//void test_derive_conf_ed25519_sha512_hmac_c(void);                          \
//void test_derive_conf_ed448_sha512_hmac_s(void);                            \
//void test_derive_conf_ed448_sha256_hmac_c(void);                            \
//void test_derive_conf_incorrect_ed25519_sha512_hmac_group_identity_c(void); \
//void test_derive_conf_incorrect_ed448_sha256_hmac_group_identity_s(void);   \
//RUN_TEST(test_derive_conf_ed25519_sha256_hmac_s);                           \
//RUN_TEST(test_derive_conf_ed25519_sha512_hmac_c);                           \
//RUN_TEST(test_derive_conf_ed448_sha512_hmac_s);                             \
//RUN_TEST(test_derive_conf_ed448_sha256_hmac_c);                             \
//RUN_TEST(test_derive_conf_incorrect_ed25519_sha512_hmac_group_identity_c);  \
//RUN_TEST(test_derive_conf_incorrect_ed448_sha256_hmac_group_identity_s);    \
*/
