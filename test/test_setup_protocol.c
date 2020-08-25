#include "unity.h"
#include "spake2plus.h"
#include "test_globals.h"
#include <string.h>
#include <stdbool.h>

static char *g_pw_ptr = "test password";
static char *g_srv_id_ptr = "test server id";
static char *g_client_id_ptr = "test client id";
static char *g_aad_ptr = "test additional info";

static uint8_t buf_pL[] = {
    0x04, 0x91, 0xbb, 0x1e, 0x66, 0x72, 0xe7, 0x1a, 0xd8, 0x0b,
    0x17, 0xd1, 0x3f, 0x7a, 0x72, 0xca, 0x2f, 0xe7, 0xf8, 0x82,
    0xd4, 0xbd, 0x73, 0x4e, 0x2d, 0x14, 0x0f, 0x67, 0xab, 0x49,
    0xd2, 0xc3, 0xe7, 0x6d, 0xbc, 0xf7, 0x06, 0x95, 0x4b, 0xd9,
    0xad, 0xa4, 0xe3, 0xa7, 0xfc, 0x50, 0xcf, 0x92, 0x94, 0x72,
    0x9f, 0x93, 0xb1, 0x30, 0xad, 0xa3, 0xd3, 0xa4, 0xae, 0x98,
    0xcc, 0x7e, 0x7b, 0x69, 0x71};
static uint8_t buf_pw0[] = {
    0x4f, 0x9e, 0x28, 0x32, 0x2a, 0x64, 0xf9, 0xdc, 0x7a, 0x01,
    0xb2, 0x82, 0xcc, 0x51, 0xe2, 0xab, 0xc4, 0xf9, 0xed, 0x56,
    0x88, 0x05, 0xca, 0x84, 0xf4, 0xed, 0x3e, 0xf8, 0x06, 0x51,
    0x6c, 0xf8};

#define GROUP_DEFAULT SPAKE2PLUS_GROUP_P256_SEARCH_NAME
#define MAC_DEFAULT SPAKE2PLUS_HMAC_SEARCH_NAME
#define HASH_DEFAULT SPAKE2PLUS_HASH_SHA256_SEARCH_NAME

static void default_init()
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
    TEST_ASSERT_MESSAGE(res == SPAKE2PLUS_OK, "Default initialization failed!");
}

static void default_init_group_client_server(char *group, int c_or_s)
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
        HASH_DEFAULT,
        MAC_DEFAULT,
        c_or_s);
    TEST_ASSERT_MESSAGE(res == SPAKE2PLUS_OK, "Default initialization failed!");
}

static void default_init_pw()
{
    int res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));
    TEST_ASSERT_MESSAGE(res == SPAKE2PLUS_OK, "Default password initialization failed!");
}

static void default_load()
{
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL,
        sizeof(buf_pL),
        buf_pw0,
        sizeof(buf_pw0));
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Default L, w0 load failed!");
}

void test_setup_protocol_after_pw(void)
{
    default_init();
    default_init_pw();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal protocol setup after pw init failed!");
}

void test_setup_protocol_after_load_s(void)
{
    default_init();
    default_load();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal protocol setup after w0 and L load failed!");
}

void test_setup_protocol_after_load_c(void)
{
    default_init_group_client_server(SPAKE2PLUS_GROUP_P256_SEARCH_NAME, SPAKE2PLUS_CLIENT);
    default_load();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect load values for client protocol setup failed!");
}

void test_setup_protocol_no_pw(void)
{
    default_init();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect protocol setup w/o pw init failed!");
}

void test_setup_protocol_incorrect_instance(void)
{
    int res = spake2plus_setup_protocol(
        NULL);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INSTANCE_IS_NULL, res, "Incorrect NULL instance initialization failed!");
}

void test_setup_protocol_p256_c(void)
{
    default_init_group_client_server(SPAKE2PLUS_GROUP_P256_SEARCH_NAME, SPAKE2PLUS_CLIENT);
    default_init_pw();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal protocol setup for client, P-256 failed!");
}

void test_setup_protocol_p384_c(void)
{
    default_init_group_client_server(SPAKE2PLUS_GROUP_P384_SEARCH_NAME, SPAKE2PLUS_CLIENT);
    default_init_pw();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal protocol setup for client, P-384 failed!");
}

void test_setup_protocol_p384_s(void)
{
    default_init_group_client_server(SPAKE2PLUS_GROUP_P384_SEARCH_NAME, SPAKE2PLUS_SERVER);
    default_init_pw();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal protocol setup for server, P-384 failed!");
}

void test_setup_protocol_p521_c(void)
{
    default_init_group_client_server(SPAKE2PLUS_GROUP_P521_SEARCH_NAME, SPAKE2PLUS_CLIENT);
    default_init_pw();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal protocol setup for client, P-521 failed!");
}

void test_setup_protocol_p521_s(void)
{
    default_init_group_client_server(SPAKE2PLUS_GROUP_P521_SEARCH_NAME, SPAKE2PLUS_SERVER);
    default_init_pw();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal protocol setup for server, P-521 failed!");
}

void test_setup_protocol_ed25519_c(void)
{
    default_init_group_client_server(SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME, SPAKE2PLUS_CLIENT);
    default_init_pw();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal protocol setup for client, ed25519 failed!");
}

void test_setup_protocol_ed25519_s(void)
{
    default_init_group_client_server(SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME, SPAKE2PLUS_SERVER);
    default_init_pw();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal protocol setup for server, ed25519 failed!");
}

void test_setup_protocol_ed448_c(void)
{
    default_init_group_client_server(SPAKE2PLUS_GROUP_ED448_SEARCH_NAME, SPAKE2PLUS_CLIENT);
    default_init_pw();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal protocol setup for client, ed448 failed!");
}

void test_setup_protocol_ed448_s(void)
{
    default_init_group_client_server(SPAKE2PLUS_GROUP_ED448_SEARCH_NAME, SPAKE2PLUS_SERVER);
    default_init_pw();
    int res = spake2plus_setup_protocol(
        spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal protocol setup for server, ed448 failed!");
}
