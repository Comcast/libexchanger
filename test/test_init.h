#pragma once

void test_init_server_normal_0();
void test_init_client_normal_0();
void test_init_server_normal_1();
void test_init_client_normal_1();
void test_init_server_normal_3();
void test_init_client_normal_3();
void test_init_server_normal_4();
void test_init_client_normal_4();
void test_init_server_normal_5();
void test_init_client_normal_5();
void test_init_server_normal_8();
void test_init_client_normal_8();
void test_init_client_wrong_hash();
void test_incorrect_client_server_0();
void test_incorrect_client_server_1();
void test_incorrect_client_server_2();
void test_init_null_instance_link_0();
void test_init_null_instance_link_1();
void test_init_client_wrong_mac_0();
void test_init_server_wrong_mac_0();
void test_init_client_wrong_mac_1();
void test_init_server_wrong_mac_1();
void test_init_client_wrong_mac_2();
void test_init_server_wrong_mac_2();
void test_init_client_wrong_mac_3();
void test_init_server_wrong_mac_3();
void test_init_client_wrong_hash_0();
void test_init_server_wrong_hash_0();
void test_init_client_wrong_hash_1();
void test_init_server_wrong_hash_2();
void test_init_client_unsupported_hash();
void test_init_server_wrong_hash_4();
void test_init_client_wrong_group_0();
void test_init_server_wrong_group_0();
void test_init_client_wrong_group_1();
void test_init_server_wrong_group_2();
void test_init_client_wrong_group_3();
void test_init_server_wrong_group_4();
void test_init_server_wrong_client_id_0();
void test_init_client_wrong_server_id_0();
void test_init_server_wrong_aad_id_0();
void test_init_client_wrong_client_id_1();
void test_init_server_wrong_server_id_1();
void test_init_client_wrong_aad_id_1();
void test_init_client_memory_shortage_c();
void test_init_client_memory_shortage_s();
void test_init_free_prime();
void test_init_free_cofactor();
void test_init_free_w0();
void test_init_free_w1_or_L();
void test_init_free_M();
void test_init_free_N();
void test_init_free_pA();
void test_init_free_pB();
void test_init_free_random_value();
void test_init_free_AAD();
void test_init_free_idA();
void test_init_free_idB();
void test_init_free_KcAKcB();

#define DECLARE_TESTS_INIT()                      \
    RUN_TEST(test_init_server_normal_0);          \
    RUN_TEST(test_init_client_normal_0);          \
    RUN_TEST(test_init_server_normal_1);          \
    RUN_TEST(test_init_client_normal_1);          \
    RUN_TEST(test_init_server_normal_3);          \
    RUN_TEST(test_init_client_normal_3);          \
    RUN_TEST(test_init_server_normal_4);          \
    RUN_TEST(test_init_client_normal_4);          \
    RUN_TEST(test_init_server_normal_5);          \
    RUN_TEST(test_init_client_normal_5);          \
    RUN_TEST(test_init_server_normal_8);          \
    RUN_TEST(test_init_client_normal_8);          \
    RUN_TEST(test_init_client_wrong_hash);        \
    RUN_TEST(test_incorrect_client_server_0);     \
    RUN_TEST(test_incorrect_client_server_1);     \
    RUN_TEST(test_incorrect_client_server_2);     \
    RUN_TEST(test_init_null_instance_link_0);     \
    RUN_TEST(test_init_null_instance_link_1);     \
    RUN_TEST(test_init_client_wrong_mac_0);       \
    RUN_TEST(test_init_server_wrong_mac_0);       \
    RUN_TEST(test_init_client_wrong_mac_1);       \
    RUN_TEST(test_init_server_wrong_mac_1);       \
    RUN_TEST(test_init_client_wrong_mac_2);       \
    RUN_TEST(test_init_server_wrong_mac_2);       \
    RUN_TEST(test_init_client_wrong_mac_3);       \
    RUN_TEST(test_init_server_wrong_mac_3);       \
    RUN_TEST(test_init_client_wrong_hash_0);      \
    RUN_TEST(test_init_server_wrong_hash_0);      \
    RUN_TEST(test_init_client_wrong_hash_1);      \
    RUN_TEST(test_init_server_wrong_hash_2);      \
    RUN_TEST(test_init_client_unsupported_hash);  \
    RUN_TEST(test_init_server_wrong_hash_4);      \
    RUN_TEST(test_init_client_wrong_group_0);     \
    RUN_TEST(test_init_server_wrong_group_0);     \
    RUN_TEST(test_init_client_wrong_group_1);     \
    RUN_TEST(test_init_server_wrong_group_2);     \
    RUN_TEST(test_init_client_wrong_group_3);     \
    RUN_TEST(test_init_server_wrong_group_4);     \
    RUN_TEST(test_init_server_wrong_client_id_0); \
    RUN_TEST(test_init_client_wrong_server_id_0); \
    RUN_TEST(test_init_server_wrong_aad_id_0);    \
    RUN_TEST(test_init_client_wrong_client_id_1); \
    RUN_TEST(test_init_server_wrong_server_id_1); \
    RUN_TEST(test_init_client_wrong_aad_id_1);    \
    RUN_TEST(test_init_client_memory_shortage_c); \
    RUN_TEST(test_init_client_memory_shortage_s); \
    RUN_TEST(test_init_free_prime);               \
    RUN_TEST(test_init_free_cofactor);            \
    RUN_TEST(test_init_free_w0);                  \
    RUN_TEST(test_init_free_w1_or_L);             \
    RUN_TEST(test_init_free_M);                   \
    RUN_TEST(test_init_free_N);                   \
    RUN_TEST(test_init_free_pA);                  \
    RUN_TEST(test_init_free_pB);                  \
    RUN_TEST(test_init_free_random_value);        \
    RUN_TEST(test_init_free_AAD);                 \
    RUN_TEST(test_init_free_idA);                 \
    RUN_TEST(test_init_free_idB);                 \
    RUN_TEST(test_init_free_KcAKcB);
/*
//void test_init_server_normal_6();
//void test_init_client_normal_6();
//void test_init_server_normal_7();
//void test_init_client_normal_7();
//RUN_TEST(test_init_server_normal_2); \
//RUN_TEST(test_init_client_normal_2); \
//RUN_TEST(test_init_server_normal_6); \
//RUN_TEST(test_init_client_normal_6); \
//RUN_TEST(test_init_server_normal_7); \
//RUN_TEST(test_init_client_normal_7); \
*/