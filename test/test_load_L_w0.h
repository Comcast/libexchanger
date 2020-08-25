#pragma once

void test_load_L_w0_after_pw(void);
void test_load_L_w0_no_pw(void);
void test_load_L_w0_back_conversion_w0(void);
void test_load_L_w0_back_conversion_L(void);
void test_load_L_w0_data_w0_too_short(void);
void test_load_L_w0_data_L_too_short(void);
void test_load_L_w0_wrong_group(void);
void test_load_L_w0_data_w0_zero(void);
void test_load_L_w0_data_L_too_long(void);
void test_load_L_w0_data_w0_too_long(void);
void test_load_L_w0_incorrect_instance_0(void);
void test_load_L_w0_incorrect_pL_0(void);
void test_load_L_w0_incorrect_pL_1(void);
void test_load_L_w0_incorrect_pL_2(void);
void test_load_L_w0_incorrect_buf_pw0_0(void);
void test_load_L_w0_incorrect_buf_pw0_1(void);
void test_load_L_w0_incorrect_buf_pw0_2(void);

#define DECLARE_TESTS_LOAD_L_W0()                  \
    RUN_TEST(test_load_L_w0_after_pw);             \
    RUN_TEST(test_load_L_w0_no_pw);                \
    RUN_TEST(test_load_L_w0_back_conversion_w0);   \
    RUN_TEST(test_load_L_w0_back_conversion_L);    \
    RUN_TEST(test_load_L_w0_data_w0_too_short);    \
    RUN_TEST(test_load_L_w0_data_L_too_short);     \
    RUN_TEST(test_load_L_w0_wrong_group);          \
    RUN_TEST(test_load_L_w0_data_w0_zero);         \
    RUN_TEST(test_load_L_w0_data_L_too_long);      \
    RUN_TEST(test_load_L_w0_data_w0_too_long);     \
    RUN_TEST(test_load_L_w0_incorrect_instance_0); \
    RUN_TEST(test_load_L_w0_incorrect_pL_0);       \
    RUN_TEST(test_load_L_w0_incorrect_pL_1);       \
    RUN_TEST(test_load_L_w0_incorrect_pL_2);       \
    RUN_TEST(test_load_L_w0_incorrect_buf_pw0_0);  \
    RUN_TEST(test_load_L_w0_incorrect_buf_pw0_1);  \
    RUN_TEST(test_load_L_w0_incorrect_buf_pw0_2);
