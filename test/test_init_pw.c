#include "unity.h"
#include "spake2plus.h"
#include <string.h>
#include "test_globals.h"
#include <stdbool.h>

static char *g_pw_ptr = "test password";
static char *g_srv_id_ptr = "test server id";
static char *g_client_id_ptr = "test client id";
static char *g_aad_ptr = "test additional info";
static char *empty_string = "";

#define GROUP_DEFAULT SPAKE2PLUS_GROUP_P256_SEARCH_NAME
#define MAC_DEFAULT SPAKE2PLUS_HMAC_SEARCH_NAME
#define HASH_DEFAULT SPAKE2PLUS_HASH_SHA256_SEARCH_NAME

static void default_init(bool server)
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
        server ? SPAKE2PLUS_SERVER : SPAKE2PLUS_CLIENT);
    TEST_ASSERT_MESSAGE(res == SPAKE2PLUS_OK, "Default initialization failed!");
}

static void default_server_init_group_hash_mac(char *group, char *hash, char *mac)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        group,
        hash,
        mac,
        SPAKE2PLUS_SERVER);
    TEST_ASSERT_MESSAGE(res == SPAKE2PLUS_OK, "Default initialization failed!");
}

static void default_client_init_group_hash_mac(char *group, char *hash, char *mac)
{
    int res = spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        g_srv_id_ptr,
        strlen(g_srv_id_ptr),
        g_aad_ptr,
        strlen(g_aad_ptr),
        group,
        hash,
        mac,
        SPAKE2PLUS_CLIENT);
    TEST_ASSERT_MESSAGE(res == SPAKE2PLUS_OK, "Default initialization failed!");
}

void test_init_pw_client_normal_0(void)
{
    default_init(false);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_pw_server_normal_0(void)
{
    default_init(true);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_pw_client_normal_1(void)
{
    spake2plus_init(
        &spake2_instance,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0,
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_pw_server_normal_1(void)
{
    spake2plus_init(
        &spake2_instance,
        g_client_id_ptr,
        strlen(g_client_id_ptr),
        NULL,
        0,
        NULL,
        0,
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);

    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_pw_server_normal_p256_sha512_cmac(void)
{
    default_server_init_group_hash_mac(
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_pw_client_normal_p256_sha256_cmac(void)
{
    default_client_init_group_hash_mac(
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_pw_client_normal_p384_sha256_hmac(void)
{
    default_client_init_group_hash_mac(
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_pw_server_normal_p384_sha512_hmac(void)
{
    default_server_init_group_hash_mac(
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_pw_client_normal_p521_sha512_hmac(void)
{
    default_client_init_group_hash_mac(
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_pw_server_normal_p521_sha256_hmac(void)
{
    default_server_init_group_hash_mac(
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_pw_server_normal_ed25519_sha256_hmac(void)
{
    default_server_init_group_hash_mac(
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_pw_client_normal_ed25519_sha512_hmac(void)
{
    default_client_init_group_hash_mac(
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_pw_server_normal_ed448_sha512_hmac(void)
{
    default_server_init_group_hash_mac(
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server initialization failed!");
}

void test_init_pw_client_normal_ed448_sha256_hmac(void)
{
    default_client_init_group_hash_mac(
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client initialization failed!");
}

void test_init_pw_client_incorrect_init_1(void)
{
    int res = spake2plus_pwd_init(
        NULL,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INSTANCE_IS_NULL, res, "Incorrect NULL instance client initialization failed!");
}

void test_init_pw_server_incorrect_init_1(void)
{
    int res = spake2plus_pwd_init(
        NULL,
        g_pw_ptr,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INSTANCE_IS_NULL, res, "Incorrect NULL instance server initialization failed!");
}

void test_init_pw_client_incorrect_pw_0(void)
{
    default_init(false);
    int res = spake2plus_pwd_init(
        spake2_instance,
        NULL,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PW_IS_NULL, res, "Incorrect client initialization failed!");
}

void test_init_pw_server_incorrect_pw_0(void)
{
    default_init(true);
    int res = spake2plus_pwd_init(
        spake2_instance,
        NULL,
        strlen(g_pw_ptr));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PW_IS_NULL, res, "Incorrect server initialization failed!");
}

void test_init_pw_client_incorrect_pw_1(void)
{
    default_init(false);
    int res = spake2plus_pwd_init(
        spake2_instance,
        NULL,
        0);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PW_WRONG_LEN, res, "Incorrect client initialization failed!");
}

void test_init_pw_server_incorrect_pw_1(void)
{
    default_init(true);
    int res = spake2plus_pwd_init(
        spake2_instance,
        NULL,
        0);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PW_WRONG_LEN, res, "Incorrect server initialization failed!");
}

void test_init_pw_client_incorrect_pw_2(void)
{
    default_init(false);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        0);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PW_WRONG_LEN, res, "Incorrect client initialization failed!");
}

void test_init_pw_server_incorrect_pw_2(void)
{
    default_init(true);
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        0);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PW_WRONG_LEN, res, "Incorrect server initialization failed!");
}

void test_init_pw_client_incorrect_pw_3(void)
{
    default_init(false);
    int res = spake2plus_pwd_init(
        spake2_instance,
        empty_string,
        /**Incorrect sizeof usage below is part of the test.*/
        sizeof(empty_string));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PW_WRONG_LEN, res, "Incorrect client initialization failed!");
}

void test_init_pw_server_incorrect_pw_3(void)
{
    default_init(true);
    int res = spake2plus_pwd_init(
        spake2_instance,
        empty_string,
        /**Incorrect sizeof usage below is part of the test.*/
        sizeof(empty_string));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PW_WRONG_LEN, res, "Incorrect server initialization failed!");
}
