#pragma once

void test_init_pw_client_normal_0(void);
void test_init_pw_server_normal_0(void);
void test_init_pw_client_normal_1(void);
void test_init_pw_server_normal_1(void);
void test_init_pw_client_incorrect_init_1(void);
void test_init_pw_server_incorrect_init_1(void);
void test_init_pw_client_incorrect_pw_0(void);
void test_init_pw_server_incorrect_pw_0(void);
void test_init_pw_client_incorrect_pw_1(void);
void test_init_pw_server_incorrect_pw_1(void);
void test_init_pw_client_incorrect_pw_2(void);
void test_init_pw_server_incorrect_pw_2(void);
void test_init_pw_server_normal_p256_sha512_cmac(void);
void test_init_pw_client_normal_p256_sha256_cmac(void);
void test_init_pw_client_normal_p384_sha256_hmac(void);
void test_init_pw_server_normal_p384_sha512_hmac(void);
void test_init_pw_client_normal_p521_sha512_hmac(void);
void test_init_pw_server_normal_p521_sha256_hmac(void);

#define DECLARE_TESTS_INIT_PW()                              \
    RUN_TEST(test_init_pw_client_normal_0);                  \
    RUN_TEST(test_init_pw_server_normal_0);                  \
    RUN_TEST(test_init_pw_client_normal_1);                  \
    RUN_TEST(test_init_pw_server_normal_1);                  \
    RUN_TEST(test_init_pw_server_normal_p256_sha512_cmac);   \
    RUN_TEST(test_init_pw_client_normal_p256_sha256_cmac);   \
    RUN_TEST(test_init_pw_client_normal_p384_sha256_hmac);   \
    RUN_TEST(test_init_pw_server_normal_p384_sha512_hmac);   \
    RUN_TEST(test_init_pw_client_normal_p521_sha512_hmac);   \
    RUN_TEST(test_init_pw_server_normal_p521_sha256_hmac);   \
    RUN_TEST(test_init_pw_client_incorrect_init_1);          \
    RUN_TEST(test_init_pw_server_incorrect_init_1);          \
    RUN_TEST(test_init_pw_client_incorrect_pw_0);            \
    RUN_TEST(test_init_pw_server_incorrect_pw_0);            \
    RUN_TEST(test_init_pw_client_incorrect_pw_1);            \
    RUN_TEST(test_init_pw_server_incorrect_pw_1);            \
    RUN_TEST(test_init_pw_client_incorrect_pw_2);            \
    RUN_TEST(test_init_pw_server_incorrect_pw_2);            \
/*                                                           \
//void test_init_pw_server_normal_ed25519_sha256_hmac(void); \
//void test_init_pw_client_normal_ed25519_sha512_hmac(void); \
//void test_init_pw_server_normal_ed448_sha512_hmac(void);   \
//void test_init_pw_client_normal_ed448_sha256_hmac(void);   \
//RUN_TEST(test_init_pw_server_normal_ed25519_sha256_hmac);  \
//RUN_TEST(test_init_pw_client_normal_ed25519_sha512_hmac);  \
//RUN_TEST(test_init_pw_server_normal_ed448_sha512_hmac);    \
//RUN_TEST(test_init_pw_client_normal_ed448_sha256_hmac);    \
*/
