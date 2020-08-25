#include "unity.h"
#include "spake2plus.h"
#include "test_globals.h"
#include <string.h>
#include <stdbool.h>

static char *g_pw_ptr = "test password";
static char *g_srv_id_ptr = "test server id";
static char *g_client_id_ptr = "test client id";
static char *g_aad_ptr = "test additional info";
static uint8_t g_Fa_or_Fb[EVP_MAX_MD_SIZE] = {0};
static size_t g_Fa_or_Fb_len;

static uint8_t g_pA_or_pB_example_p256[] =
    {
        0x04, 0x87, 0x95, 0x67, 0xd0, 0x95, 0x60, 0xc0, 0x2b, 0xe5,
        0x65, 0x42, 0x90, 0x36, 0xed, 0x1d, 0x2f, 0xc3, 0xca, 0x53,
        0xf2, 0xeb, 0x6f, 0xad, 0xda, 0x4d, 0xba, 0x09, 0xef, 0xf3,
        0xa0, 0x09, 0x6f, 0x03, 0x2f, 0x0e, 0x22, 0x72, 0x07, 0xeb,
        0xeb, 0xe0, 0x5e, 0x1e, 0x95, 0xde, 0x32, 0x5d, 0xff, 0xfe,
        0x57, 0x9c, 0x8a, 0xae, 0x76, 0x05, 0x40, 0x30, 0xe5, 0x43,
        0x5f, 0xd5, 0x29, 0x8c, 0x75};

static uint8_t g_pA_or_pB_example_p384[] =
    {
        0x04, 0x84, 0xAE, 0x09, 0x16, 0x43, 0x70, 0xD6, 0xC9, 0xA5,
        0x74, 0x59, 0xC6, 0x27, 0x3B, 0xFB, 0x8C, 0xE7, 0x6E, 0x23,
        0xAE, 0x9F, 0xE3, 0x39, 0x1D, 0xF5, 0x7A, 0x68, 0x5C, 0x69,
        0x06, 0xE2, 0x9E, 0x60, 0x31, 0x98, 0xEF, 0xAF, 0x13, 0x84,
        0xF2, 0x88, 0xDF, 0x70, 0xFE, 0x7D, 0x85, 0x50, 0xC4, 0x19,
        0x1A, 0x6F, 0x42, 0x98, 0xEB, 0xC5, 0xD2, 0x33, 0x42, 0xC6,
        0xD3, 0x75, 0xC3, 0x7B, 0x03, 0x24, 0xFD, 0x4F, 0x9C, 0xAF,
        0x53, 0x95, 0xF9, 0xF5, 0x7E, 0x24, 0x02, 0x4A, 0x67, 0x3A,
        0xC2, 0x6A, 0x12, 0x72, 0xA4, 0x79, 0x7C, 0x0E, 0x6A, 0x28,
        0xEC, 0xE0, 0x2D, 0xBB, 0x8A, 0x69, 0x66};

static uint8_t g_pA_or_pB_example_p521[] =
    {
        0x04, 0x01, 0x6E, 0xB3, 0xAD, 0xB9, 0xA5, 0xE1, 0x00, 0xEE,
        0x6B, 0xD1, 0xA7, 0xA9, 0x92, 0x40, 0xA2, 0x67, 0xDD, 0x91,
        0x24, 0x41, 0x16, 0x5C, 0xE8, 0x8A, 0x17, 0x45, 0xD8, 0x69,
        0xFD, 0x3C, 0xC8, 0x8C, 0xAF, 0x5C, 0x9C, 0xA6, 0xFE, 0x8E,
        0x78, 0xA7, 0xFD, 0x2B, 0xF5, 0x90, 0x6B, 0x0E, 0xAB, 0x56,
        0xA9, 0x0C, 0x0D, 0x66, 0x58, 0x93, 0xB5, 0x22, 0x16, 0x45,
        0x81, 0x7A, 0x2E, 0x6C, 0x7A, 0x2F, 0x6F, 0x00, 0x10, 0x3D,
        0x83, 0xD2, 0xE6, 0xC7, 0x02, 0x2B, 0x5B, 0x20, 0x0D, 0xE7,
        0xF6, 0xB7, 0x54, 0x0C, 0xC4, 0xAD, 0xAF, 0x0B, 0x50, 0x3C,
        0xFA, 0x24, 0x35, 0xD1, 0xEE, 0x6C, 0x1B, 0xEC, 0x4E, 0x34,
        0x12, 0x84, 0x4B, 0xA3, 0xB7, 0xDA, 0xD0, 0x0C, 0xCA, 0xB6,
        0x36, 0x23, 0xA0, 0x34, 0xC6, 0x39, 0x0C, 0xDB, 0xD6, 0xDE,
        0x9B, 0x7D, 0xC7, 0x21, 0x04, 0x3F, 0xC5, 0x87, 0xA1, 0xE3,
        0x7A, 0xF0, 0x48};

static uint8_t g_pA_or_pB_example_ed448[] =
    {
        0x4A, 0x9B, 0x66, 0x1F, 0x52, 0x30, 0xB5, 0xF4, 0x4D, 0xB7,
        0x65, 0x9A, 0xE4, 0xA4, 0x16, 0x9A, 0x53, 0xB7, 0xC7, 0x3C,
        0xA7, 0x00, 0xC9, 0x51, 0x3C, 0x1A, 0xD3, 0x58, 0xAF, 0x68,
        0x32, 0x08, 0x06, 0xD4, 0x48, 0xFD, 0x9D, 0x68, 0x6F, 0x8C,
        0xBA, 0x21, 0xC0, 0x4E, 0x41, 0xC8, 0x52, 0x7D, 0xB3, 0xFF,
        0x46, 0x9C, 0x22, 0x76, 0x69, 0x02, 0x4F, 0xA9, 0x66, 0x1E,
        0xDA, 0xDB, 0xB5, 0xCD, 0x40, 0xC0, 0x7C, 0xDB, 0x25, 0x84,
        0x0B, 0x08, 0x91, 0xEB, 0xAA, 0xEE, 0x2E, 0xDD, 0x5E, 0x3A,
        0x62, 0xF3, 0xB0, 0xA2, 0x13, 0x42, 0xB6, 0xBF, 0x8E, 0xB8,
        0x6B, 0xCA, 0x3C, 0xD2, 0x37, 0xB6, 0x50, 0xFD, 0x69, 0x1C,
        0xE1, 0xF7, 0xBB, 0x2C, 0x80, 0xD1, 0x77, 0x32, 0xED, 0x33,
        0x88, 0x21, 0xC2, 0xFA, 0xDD, 0x3E, 0x2E, 0x9E, 0x9C, 0xD2,
        0x83, 0xC8, 0xF1, 0x6A, 0x9A, 0xF9, 0x04, 0xF6, 0x54, 0x1A,
        0xA8, 0xB1, 0xD7, 0x68, 0x59, 0x97, 0x84, 0xE9, 0x18, 0x94};

static uint8_t g_pA_or_pB_incorrect_long_example[] =
    {
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x6c,
        0x69, 0x65, 0x6e, 0x74, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x41, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x87, 0x95, 0x67,
        0xd0, 0x95, 0x60, 0xc0, 0x2b, 0xe5, 0x65, 0x42, 0x90, 0x36,
        0xed, 0x1d, 0x2f, 0xc3, 0xca, 0x53, 0xf2, 0xeb, 0x6f, 0xad,
        0xda, 0x4d, 0xba, 0x09, 0xef, 0xf3, 0xa0, 0x09, 0x6f, 0x03,
        0x2f, 0x0e, 0x22, 0x72, 0x07, 0xeb, 0xeb, 0xe0, 0x5e, 0x1e,
        0x95, 0xde, 0x32, 0x5d, 0xff, 0xfe, 0x57, 0x9c, 0x8a, 0xae,
        0x76, 0x05, 0x40, 0x30, 0xe5, 0x43, 0x5f, 0xd5, 0x29, 0x8c,
        0x75, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0xb5, 0x95, 0xa2, 0x55, 0x88, 0xa2, 0xfb, 0xa7, 0x57, 0x19,
        0x5a, 0x75, 0x6d, 0x28, 0x9c, 0x19, 0x12, 0x40, 0x29, 0x66,
        0x99, 0xf6, 0x1f, 0xee, 0x8f, 0x15, 0xa7, 0xa7, 0x41, 0xa4,
        0x23, 0xd4, 0x8b, 0xd4, 0x4c, 0xf5, 0x44, 0xb4, 0x09, 0xbb,
        0xe4, 0x26, 0x2a, 0x80, 0x45, 0x05, 0x1e, 0x73, 0x45, 0x67,
        0x54, 0x8b, 0xa4, 0x3b, 0x31, 0x17, 0xef, 0xd6, 0xfb, 0x03,
        0xac, 0xf4, 0x1a, 0xff, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x7b, 0xb4, 0x66, 0x1d, 0xb7, 0x08, 0x5d,
        0x01, 0x9c, 0xff, 0xa8, 0x49, 0x5a, 0xba, 0x73, 0xd2, 0x2f,
        0x87, 0xab, 0x8b, 0xa2, 0x2e, 0x78, 0x94, 0x77, 0xef, 0x93,
        0x3b, 0x91, 0x6f, 0x41, 0x28, 0x63, 0xae, 0xb2, 0xdb, 0xc8,
        0x00, 0x3e, 0x4f, 0x1c, 0x21, 0x93, 0x29, 0x03, 0x38, 0xea,
        0x0c, 0x7d, 0x78, 0x6d, 0x30, 0xca, 0x47, 0xa4, 0x8e, 0xea,
        0x27, 0x33, 0x75, 0xa0, 0xc7, 0x2c, 0xa1, 0x41, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x17, 0x65, 0x8e, 0x1e,
        0x97, 0x07, 0xa2, 0x9d, 0x42, 0x9a, 0x47, 0x33, 0xd3, 0xbe,
        0xe7, 0x03, 0x57, 0x4a, 0xec, 0x22, 0x2e, 0x78, 0x1a, 0x6e,
        0x7e, 0x5f, 0x5e, 0x50, 0x49, 0x08, 0x11, 0xaa, 0xbf, 0x28,
        0xe1, 0x12, 0xfe, 0xe3, 0x2a, 0x37, 0xc2, 0x28, 0xdf, 0x9b,
        0x53, 0xe6, 0x22, 0x04, 0x68, 0xa2, 0xf6, 0xf0, 0x74, 0x27,
        0x60, 0x4d, 0x89, 0x17, 0x87, 0x0a, 0xc9, 0x65, 0xee, 0xc7,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x9e,
        0x28, 0x32, 0x2a, 0x64, 0xf9, 0xdc, 0x7a, 0x01, 0xb2, 0x82,
        0xcc, 0x51, 0xe2, 0xab, 0xc4, 0xf9, 0xed, 0x56, 0x88, 0x05,
        0xca, 0x84, 0xf4, 0xed, 0x3e, 0xf8, 0x06, 0x51, 0x6c, 0xf8};
static uint8_t *group_identity = NULL;
size_t group_identity_len = 0;

#define GROUP_DEFAULT SPAKE2PLUS_GROUP_P256_SEARCH_NAME
#define MAC_DEFAULT SPAKE2PLUS_HMAC_SEARCH_NAME
#define HASH_DEFAULT SPAKE2PLUS_HASH_SHA256_SEARCH_NAME

static void default_init(int c_or_s)
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
        c_or_s);
    TEST_ASSERT_MESSAGE(res == SPAKE2PLUS_OK, "Default initialization failed!");
}

static void default_init_group_hash_mac_cs(char *group, char *hash, char *mac, int c_or_s)
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

static void default_setup_protocol()
{
    int res = spake2plus_setup_protocol(spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Default protocol setup failed!");
}

static void default_setup_party_params(char *group, char *hash, char *mac, int c_or_s)
{
    default_init_group_hash_mac_cs(group, hash, mac, c_or_s);
    default_init_pw();
    default_setup_protocol();
}

static void default_setup_party(int c_or_s)
{
    default_init(c_or_s);
    default_init_pw();
    default_setup_protocol();
}

static void default_setup_party_identity(char *group, char *hash, char *mac, int c_or_s)
{
    default_setup_party_params(
        group,
        hash,
        mac,
        c_or_s);
    EC_POINT *infinity = NULL;
    BN_CTX *ctx = NULL;
    TEST_ASSERT(NULL != (infinity = EC_POINT_new(spake2_instance->group)));
    TEST_ASSERT(NULL != (ctx = BN_CTX_new()));
    BN_CTX_start(ctx);
    TEST_ASSERT(1 == EC_POINT_set_to_infinity(spake2_instance->group, infinity));
    TEST_ASSERT(0 < (group_identity_len = EC_POINT_point2oct(spake2_instance->group,
                                                             infinity,
                                                             POINT_CONVERSION_UNCOMPRESSED,
                                                             (unsigned char *)group_identity,
                                                             0,
                                                             ctx)));
    TEST_ASSERT(NULL != (group_identity = malloc(group_identity_len)));
    TEST_ASSERT(group_identity_len == EC_POINT_point2oct(spake2_instance->group,
                                                         infinity,
                                                         POINT_CONVERSION_UNCOMPRESSED,
                                                         (unsigned char *)group_identity,
                                                         group_identity_len,
                                                         ctx));
    BN_CTX_CHECK_NULL_AND_FREE(ctx);
    EC_POINT_CHECK_NULL_AND_FREE(infinity);
}

void test_derive_conf_incorrect_instance(void)
{
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        NULL,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INSTANCE_IS_NULL, res, "Incorrect instance confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_only_init_c(void)
{
    default_init(SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect only init client confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_only_init_s(void)
{
    default_init(SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect only init server confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_only_init_pw_c(void)
{
    default_init(SPAKE2PLUS_CLIENT);
    default_init_pw();
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_ZERO_RANDOM_VAL, res, "Incorrect only init pw client confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_only_init_pw_s(void)
{
    default_init(SPAKE2PLUS_SERVER);
    default_init_pw();
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_ZERO_RANDOM_VAL, res, "Incorrect only init pw server confirmation keys derivation failed!");
}

void test_derive_conf_default_s(void)
{
    default_setup_party(SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server confirmation keys derivation failed!");
}

void test_derive_conf_default_c(void)
{
    default_setup_party(SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_Fa_or_Fb_s(void)
{
    default_setup_party(SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        NULL,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_MAC_NULL_RETURN, res, "Incorrect server confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_Fa_or_Fb_c(void)
{
    default_setup_party(SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        NULL,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_MAC_NULL_RETURN, res, "Incorrect client confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_Fa_or_Fb_len_s(void)
{
    default_setup_party(SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        NULL,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_OR_FB_LEN_NULL_POINTER, res, "Incorrect server confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_Fa_or_Fb_len_c(void)
{
    default_setup_party(SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        NULL,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_OR_FB_LEN_NULL_POINTER, res, "Incorrect client confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_pA_or_pB_null_s(void)
{
    default_setup_party(SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        NULL,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PA_OR_PB_IS_NULL, res, "Incorrect server confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_pA_or_pB_null_c(void)
{
    default_setup_party(SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        NULL,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PA_OR_PB_IS_NULL, res, "Incorrect client confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_pA_or_pB_short_s(void)
{
    uint8_t short_string[] = {-0x73, 0x54, -0x0f};
    default_setup_party(SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        short_string,
        sizeof(short_string));

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect server confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_pA_or_pB_short_c(void)
{
    uint8_t short_string[] = {0xd3, 0x54, 0x8f};
    default_setup_party(SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        short_string,
        sizeof(short_string));

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect client confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_pA_or_pB_long_s(void)
{
    default_setup_party(SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_incorrect_long_example,
        sizeof(g_pA_or_pB_incorrect_long_example));

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect server confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_pA_or_pB_long_c(void)
{
    default_setup_party(SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_incorrect_long_example,
        sizeof(g_pA_or_pB_incorrect_long_example));

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect client confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_pA_or_pB_len_0_s(void)
{
    default_setup_party(SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        0);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PA_OR_PB_LEN_IS_ZERO, res, "Incorrect server confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_pA_or_pB_len_0_c(void)
{
    default_setup_party(SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        0);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PA_OR_PB_LEN_IS_ZERO, res, "Incorrect client confirmation keys derivation failed!");
}

void test_derive_conf_p256_sha512_cmac_s(void)
{
    default_setup_party_params(
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server confirmation keys derivation failed!");
}

void test_derive_conf_p256_sha256_cmac_c(void)
{
    default_setup_party_params(
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client confirmation keys derivation failed!");
}

void test_derive_conf_p384_sha256_hmac_s(void)
{
    default_setup_party_params(
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p384,
        sizeof(g_pA_or_pB_example_p384));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server confirmation keys derivation failed!");
}

void test_derive_conf_p384_sha512_hmac_c(void)
{
    default_setup_party_params(
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p384,
        sizeof(g_pA_or_pB_example_p384));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client confirmation keys derivation failed!");
}

void test_derive_conf_p521_sha512_hmac_s(void)
{
    default_setup_party_params(
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p521,
        sizeof(g_pA_or_pB_example_p521));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server confirmation keys derivation failed!");
}

void test_derive_conf_p521_sha256_hmac_c(void)
{
    default_setup_party_params(
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p521,
        sizeof(g_pA_or_pB_example_p521));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client confirmation keys derivation failed!");
}

void test_derive_conf_ed25519_sha256_hmac_s(void)
{
    default_setup_party_params(
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server confirmation keys derivation failed!");
}

void test_derive_conf_ed25519_sha512_hmac_c(void)
{
    default_setup_party_params(
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_p256,
        sizeof(g_pA_or_pB_example_p256));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client confirmation keys derivation failed!");
}

void test_derive_conf_ed448_sha512_hmac_s(void)
{
    default_setup_party_params(
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_ed448,
        sizeof(g_pA_or_pB_example_ed448));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server confirmation keys derivation failed!");
}

void test_derive_conf_ed448_sha256_hmac_c(void)
{
    default_setup_party_params(
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_example_ed448,
        sizeof(g_pA_or_pB_example_ed448));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_p256_sha512_cmac_group_identity_s(void)
{
    default_setup_party_identity(
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        group_identity,
        group_identity_len);

    free(group_identity);
    group_identity = NULL;

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect server confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_p384_sha256_hmac_group_identity_c(void)
{
    default_setup_party_identity(
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_CLIENT);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        group_identity,
        group_identity_len);

    free(group_identity);
    group_identity = NULL;

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect client confirmation keys derivation failed!");
}

void test_derive_conf_incorrect_p521_sha256_hmac_group_identity_s(void)
{
    default_setup_party_identity(
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        group_identity,
        group_identity_len);

    free(group_identity);
    group_identity = NULL;

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect server confirmation keys derivation failed!");
}
