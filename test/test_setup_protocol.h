#pragma once

void test_setup_protocol_after_pw(void);
void test_setup_protocol_after_load_s(void);
void test_setup_protocol_after_load_c(void);
void test_setup_protocol_no_pw(void);
void test_setup_protocol_incorrect_instance(void);
void test_setup_protocol_p256_c(void);
void test_setup_protocol_p384_c(void);
void test_setup_protocol_p384_s(void);
void test_setup_protocol_p521_c(void);
void test_setup_protocol_p521_s(void);

#define DECLARE_TESTS_SETUP_PROTOCOL()                \
    RUN_TEST(test_setup_protocol_after_pw);           \
    RUN_TEST(test_setup_protocol_after_load_s);       \
    RUN_TEST(test_setup_protocol_after_load_c);       \
    RUN_TEST(test_setup_protocol_no_pw);              \
    RUN_TEST(test_setup_protocol_incorrect_instance); \
    RUN_TEST(test_setup_protocol_p256_c);             \
    RUN_TEST(test_setup_protocol_p384_c);             \
    RUN_TEST(test_setup_protocol_p384_s);             \
    RUN_TEST(test_setup_protocol_p521_c);             \
    RUN_TEST(test_setup_protocol_p521_s);             \
/*                                                    \
//void test_setup_protocol_ed25519_c(void);           \
//void test_setup_protocol_ed25519_s(void);           \
//void test_setup_protocol_ed448_c(void);             \
//void test_setup_protocol_ed448_s(void);             \
//    RUN_TEST(test_setup_protocol_ed25519_c);        \
//    RUN_TEST(test_setup_protocol_ed25519_s);        \
//    RUN_TEST(test_setup_protocol_ed448_c);          \
//    RUN_TEST(test_setup_protocol_ed448_s);          \
*/
