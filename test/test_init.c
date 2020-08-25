#include "unity.h"
#include "spake2plus.h"
#include <string.h>
#include "test_globals.h"

#define GROUP_DEFAULT SPAKE2PLUS_GROUP_P256_SEARCH_NAME
#define MAC_DEFAULT SPAKE2PLUS_HMAC_SEARCH_NAME
#define HASH_DEFAULT SPAKE2PLUS_HASH_SHA256_SEARCH_NAME
#define VERY_LONG_AAD_LEN ((1 << 16) - 1)

static char *g_srv_id_ptr = "test server id";
static char *g_client_id_ptr = "test client id";
static char *g_aad_ptr = "test additional info";
static char *empty_string = "";
static char g_aad_very_long[VERY_LONG_AAD_LEN] = {0};
static char g_srv_very_long[VERY_LONG_AAD_LEN] = {0};
static char g_clt_very_long[VERY_LONG_AAD_LEN] = {0};

void test_init_client_normal_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_server_normal_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_SERVER);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_client_normal_1(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0,
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_server_normal_1(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0,
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_client_normal_2(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_server_normal_2(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_client_normal_3(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_server_normal_3(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_client_normal_4(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_server_normal_4(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_client_normal_5(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_server_normal_5(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_client_normal_6(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_server_normal_6(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_client_normal_7(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_server_normal_7(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_client_normal_8(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_server_normal_8(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_incorrect_client_server_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT_SERVER_UNDEFINED);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_CLIENT_SERVER_UNEXPECTED, res, "Incorrect client/server choice initialization failed!");
}

void test_incorrect_client_server_1(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        55);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_CLIENT_SERVER_UNEXPECTED, res, "Incorrect client/server choice initialization failed!");
}

void test_incorrect_client_server_2(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        -1);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_CLIENT_SERVER_UNEXPECTED, res, "Incorrect client/server choice initialization failed!");
}

void test_init_null_instance_link_0(void)
{
    int res = spake2plus_init(
        NULL,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INSTANCE_IS_NULL, res, "NULL instance pointer initialization failed!");
}

void test_init_null_instance_link_1(void)
{
    int res = spake2plus_init(
        NULL,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INSTANCE_IS_NULL, res, "NULL instance pointer initialization failed!");
}

void test_init_client_wrong_mac_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        NULL,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_MAC_NULL_NAME, res, "Wrong MAC function client initialization failed!");
}

void test_init_server_wrong_mac_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        NULL,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_MAC_NULL_NAME, res, "Wrong MAC function server initialization failed!");
}

void test_init_client_wrong_mac_1(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        empty_string,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_MAC_FUNC_NOT_FOUND, res, "Wrong MAC function client initialization failed!");
}

void test_init_server_wrong_mac_1(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        empty_string,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_MAC_FUNC_NOT_FOUND, res, "Wrong MAC function server initialization failed!");
}

void test_init_client_wrong_mac_2(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        "mac_error",
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_MAC_FUNC_NOT_FOUND, res, "Wrong MAC function client initialization failed!");
}

void test_init_server_wrong_mac_2(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        "mac_error",
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_MAC_FUNC_NOT_FOUND, res, "Wrong MAC function server initialization failed!");
}

void test_init_client_wrong_mac_3(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        "incredibly_long_stringggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_MAC_FUNC_NOT_FOUND, res, "Wrong MAC function client initialization failed!");
}

void test_init_server_wrong_mac_3(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        "incredibly_long_stringggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_MAC_FUNC_NOT_FOUND, res, "Wrong MAC function server initialization failed!");
}

void test_init_client_wrong_hash_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        NULL,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_HASH_NAME_IS_NULL, res, "Wrong Hash function client initialization failed!");
}

void test_init_server_wrong_hash_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        NULL,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_HASH_NAME_IS_NULL, res, "Wrong Hash function server initialization failed!");
}

void test_init_client_wrong_hash_1(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        empty_string,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_HASH_NOT_SET, res, "Wrong Hash function client initialization failed!");
}

void test_init_server_wrong_hash_2(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        "hash_error",
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_HASH_NOT_SET, res, "Wrong Hash function server initialization failed!");
}

void test_init_client_unsupported_hash(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        "sha1",
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Wrong Hash function client initialization failed!");
}

void test_init_server_wrong_hash_4(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        "incredibly_long_stringggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_HASH_NOT_SET, res, "Wrong Hash function server initialization failed!");
}

void test_init_client_wrong_group_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        NULL,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_EC_NULL_NAME, res, "Wrong Group name client initialization failed!");
}

void test_init_server_wrong_group_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        NULL,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_EC_NULL_NAME, res, "Wrong Group name server initialization failed!");
}

void test_init_client_wrong_group_1(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        empty_string,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_EC_NOT_FOUND, res, "Wrong Group name client initialization failed!");
}

void test_init_server_wrong_group_2(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        "group_error",
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_EC_NOT_FOUND, res, "Wrong Group name server initialization failed!");
}

void test_init_client_wrong_group_3(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        "brainpoolP512r1",
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Wrong Group name client initialization failed!");
}

void test_init_server_wrong_group_4(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        "incredibly_long_stringggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_EC_NOT_FOUND, res, "Wrong Group name server initialization failed!");
}

void test_init_server_wrong_client_id_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        NULL,
        1,
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_CLIENT_ID_DATA_ERROR, res, "Wrong client ID server initialization failed!");
}

void test_init_client_wrong_server_id_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        NULL,
        1,
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_SERVER_ID_DATA_ERROR, res, "Wrong server ID client initialization failed!");
}

void test_init_server_wrong_aad_id_0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        NULL,
        1,
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_AAD_DATA_ERROR, res, "Wrong AAD server initialization failed!");
}

void test_init_client_wrong_client_id_1(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        empty_string,
        (size_t)(-1),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED, res, "Wrong client ID client initialization failed!");
}

void test_init_server_wrong_server_id_1(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        empty_string,
        (size_t)(-1),
        g_aad_ptr,
        strlen(g_aad_ptr),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED, res, "Wrong server ID server initialization failed!");
}

void test_init_client_wrong_aad_id_1(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        empty_string,
        (size_t)(-1),
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OPENSSL_SECURE_MALLOC_FAILED, res, "Wrong AAD client initialization failed!");
}

void test_init_client_wrong_hash(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        "HASH-unun",
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_HASH_NOT_SET, res, "Normal client initialization failed!");
}

void test_init_client_memory_shortage_c(void)
{
    int i = 0;
    for (i = 0; i < VERY_LONG_AAD_LEN; ++i)
    {
        g_aad_very_long[i] = i;
        g_srv_very_long[i] = (i << 1);
        g_clt_very_long[i] = (i << 2);
    }
    int res = spake2plus_init(
        &spake2_instance,
        g_clt_very_long,
        VERY_LONG_AAD_LEN,
        g_srv_very_long,
        VERY_LONG_AAD_LEN,
        g_aad_very_long,
        VERY_LONG_AAD_LEN,
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_client_memory_shortage_s(void)
{
    int i = 0;
    for (i = 0; i < VERY_LONG_AAD_LEN; ++i)
    {
        g_aad_very_long[i] = i;
        g_srv_very_long[i] = (i << 1);
        g_clt_very_long[i] = (i << 2);
    }
    int res = spake2plus_init(
        &spake2_instance,
        g_clt_very_long,
        VERY_LONG_AAD_LEN,
        g_srv_very_long,
        VERY_LONG_AAD_LEN,
        g_aad_very_long,
        VERY_LONG_AAD_LEN,
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_free_prime(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    BN_clear_free(spake2_instance->prime);
    spake2_instance->prime = NULL;

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_cofactor(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    BN_clear_free(spake2_instance->cofactor);
    spake2_instance->cofactor = NULL;

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_w0(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    BN_clear_free(spake2_instance->w0);
    spake2_instance->w0 = NULL;

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_w1_or_L(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    BN_clear_free(spake2_instance->w1);
    spake2_instance->w1 = NULL;

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_M(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    EC_POINT_clear_free(spake2_instance->M);
    spake2_instance->M = NULL;

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_N(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    EC_POINT_clear_free(spake2_instance->N);
    spake2_instance->N = NULL;

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_pA(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    EC_POINT_CHECK_NULL_AND_FREE(spake2_instance->pA);
    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_pB(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    EC_POINT_CHECK_NULL_AND_FREE(spake2_instance->pB);
    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_random_value(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    BN_clear_free(spake2_instance->random_value);
    spake2_instance->random_value = NULL;

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_AAD(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    OPENSSL_secure_free(spake2_instance->AAD);
    spake2_instance->AAD = NULL;

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_idA(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    OPENSSL_secure_free(spake2_instance->idA);
    spake2_instance->idA = NULL;

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_idB(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    OPENSSL_secure_free(spake2_instance->idB);
    spake2_instance->idB = NULL;

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

void test_init_free_KcAKcB(void)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        GROUP_DEFAULT,
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_CLIENT);

    OPENSSL_secure_free(spake2_instance->KcAKcB);
    spake2_instance->KcAKcB = NULL;

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal free failed!");
}

// not needed when using generate_test_runner.rb
