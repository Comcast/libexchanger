#include "unity.h"
#include "spake2plus.h"
#include "test_globals.h"
#include <string.h>
#include <stdbool.h>

static char *g_pw_ptr = "test password";
static char *g_srv_id_ptr = "test server id";
static char *g_client_id_ptr = "test client id";
static char *g_aad_ptr = "test additional info";

static uint8_t buf_pL_long[] = {
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
static uint8_t buf_pw0_long[] = {
    0x02, 0x00, 0xc7, 0x92, 0x4b, 0x9e, 0xc0, 0x17, 0xf3, 0x09,
    0x45, 0x62, 0x89, 0x43, 0x36, 0xa5, 0x3c, 0x50, 0x16, 0x7b,
    0xa8, 0xc5, 0x96, 0x38, 0x76, 0x88, 0x05, 0x42, 0xbc, 0x66,
    0x9e, 0x49, 0x4b, 0x25, 0x32, 0xd7, 0x6c, 0x5b, 0x53, 0xdf,
    0xb3, 0x49, 0xfd, 0xf6, 0x91, 0x54, 0xb9, 0xe0, 0x04, 0x8c,
    0x58, 0xa4, 0x2e, 0x8e, 0xd0, 0x4c, 0xef, 0x05, 0x2a, 0x3b,
    0xc3, 0x49, 0xd9, 0x55, 0x75, 0xcd, 0x25, 0x02, 0x00, 0x3f,
    0x06, 0xf3, 0x81, 0x31, 0xb2, 0xba, 0x26, 0x00, 0x79, 0x1e,
    0x82, 0x48, 0x8e, 0x8d, 0x20, 0xab, 0x88, 0x9a, 0xf7, 0x53,
    0xa4, 0x18, 0x06, 0xc5, 0xdb, 0x18, 0xd3, 0x7d, 0x85, 0x60,
    0x8c, 0xfa, 0xe0, 0x6b, 0x82, 0xe4, 0xa7, 0x2c, 0xd7, 0x44,
    0xc7, 0x19, 0x19, 0x35, 0x62, 0xa6, 0x53, 0xea, 0x1f, 0x11,
    0x9e, 0xef, 0x93, 0x56, 0x90, 0x7e, 0xdc, 0x9b, 0x56, 0x97,
    0x99, 0x62, 0xd7, 0xaa};

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

static void default_init_p521()
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
        HASH_DEFAULT,
        MAC_DEFAULT,
        SPAKE2PLUS_SERVER);
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
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal reverse conversion L, w0 load failed!");
}

void test_load_L_w0_after_pw(void)
{
    default_init();
    default_init_pw();
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL,
        sizeof(buf_pL),
        buf_pw0,
        sizeof(buf_pw0));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal L, w0 load failed!");
}

void test_load_L_w0_no_pw(void)
{
    default_init();
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL,
        sizeof(buf_pL),
        buf_pw0,
        sizeof(buf_pw0));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal L, w0 load failed!");
}

void test_load_L_w0_back_conversion_w0(void)
{
    default_init();
    default_load();
    unsigned char *pback_conversion = malloc(BN_num_bytes(spake2_instance->w0));
    TEST_ASSERT_NOT_EQUAL_MESSAGE(pback_conversion, NULL, "Memory allocation failed!");

    BN_bn2bin(spake2_instance->w0, pback_conversion);

    int res = memcmp(pback_conversion, buf_pw0, sizeof(buf_pw0));

    free(pback_conversion);
    pback_conversion = NULL;

    TEST_ASSERT_EQUAL_MESSAGE(0, res, "Normal reverse conversion w0 load failed!");
}

void test_load_L_w0_back_conversion_L(void)
{
    default_init();
    default_load();
    BN_CTX *ctx = NULL;
    TEST_ASSERT(NULL != (ctx = BN_CTX_secure_new()));
    BN_CTX_start(ctx);
    size_t size = EC_POINT_point2oct(spake2_instance->group,
                                     spake2_instance->L,
                                     EC_GROUP_get_point_conversion_form(spake2_instance->group),
                                     NULL,
                                     0,
                                     ctx);
    unsigned char *pback_conversion = malloc(size);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(pback_conversion, NULL, "Memory allocation failed!");

    EC_POINT_point2oct(spake2_instance->group,
                       spake2_instance->L,
                       EC_GROUP_get_point_conversion_form(spake2_instance->group),
                       pback_conversion,
                       size,
                       ctx);

    int res = memcmp(pback_conversion, buf_pL, sizeof(buf_pL));

    free(pback_conversion);
    pback_conversion = NULL;
    BN_CTX_CHECK_NULL_AND_FREE(ctx);

    TEST_ASSERT_EQUAL_MESSAGE(0, res, "Normal reverse conversion L load failed!");
}

void test_load_L_w0_data_w0_too_short(void)
{
    static uint8_t short_number[] = {0xaa, 0xbb, 0xcc};
    default_init();
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL,
        sizeof(buf_pL),
        short_number,
        sizeof(short_number));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal L, w0 load failed!");
}

void test_load_L_w0_data_L_too_short(void)
{
    static uint8_t short_number[] = {0xaa, 0xbb, 0xcc};
    default_init();
    int res = spake2plus_load_L_w0(
        spake2_instance,
        short_number,
        sizeof(short_number),
        buf_pw0,
        sizeof(buf_pw0));

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect short L, L and w0 load failed!");
}

void test_load_L_w0_wrong_group(void)
{
    default_init_p521();
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL,
        sizeof(buf_pL),
        buf_pw0,
        sizeof(buf_pw0));

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect short L, L and w0 load failed!");
}

void test_load_L_w0_data_w0_zero(void)
{
    static uint8_t zero_number[] = {0};
    default_init();
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL,
        sizeof(buf_pL),
        zero_number,
        sizeof(zero_number));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INCORRECT_W0, res, "Incorrect zero w0, L and w0 load failed!");
}

void test_load_L_w0_data_L_too_long(void)
{
    default_init();
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL_long,
        sizeof(buf_pL_long),
        buf_pw0,
        sizeof(buf_pw0));

    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect long L > generator * prime, L and w0 load failed!");
}

void test_load_L_w0_data_w0_too_long(void)
{
    default_init();
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL,
        sizeof(buf_pL),
        buf_pw0_long,
        sizeof(buf_pw0_long));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INCORRECT_W0, res, "Incorrect long w0 > prime, L and w0 load failed!");
}

void test_load_L_w0_incorrect_instance_0(void)
{
    int res = spake2plus_load_L_w0(
        NULL,
        buf_pL,
        sizeof(buf_pL),
        buf_pw0,
        sizeof(buf_pw0));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INSTANCE_IS_NULL, res, "Incorrect NULL instance initialization failed!");
}

void test_load_L_w0_incorrect_pL_0(void)
{
    int res = spake2plus_load_L_w0(
        spake2_instance,
        NULL,
        sizeof(buf_pL),
        buf_pw0,
        sizeof(buf_pw0));

    TEST_ASSERT_MESSAGE(SPAKE2PLUS_OK != res, "Incorrect buf_pL for spake2plus_load_L_w0 failed!");
}

void test_load_L_w0_incorrect_pL_1(void)
{
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL,
        0,
        buf_pw0,
        sizeof(buf_pw0));

    TEST_ASSERT_MESSAGE(SPAKE2PLUS_OK != res, "Incorrect buf_pL for spake2plus_load_L_w0 failed!");
}

void test_load_L_w0_incorrect_pL_2(void)
{
    int res = spake2plus_load_L_w0(
        spake2_instance,
        NULL,
        0,
        buf_pw0,
        sizeof(buf_pw0));

    TEST_ASSERT_MESSAGE(SPAKE2PLUS_OK != res, "Incorrect buf_pL for spake2plus_load_L_w0 failed!");
}

void test_load_L_w0_incorrect_buf_pw0_0(void)
{
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL,
        sizeof(buf_pL),
        NULL,
        sizeof(buf_pw0));

    TEST_ASSERT_MESSAGE(SPAKE2PLUS_OK != res, "Incorrect buf_pw0 for spake2plus_load_L_w0 failed!");
}

void test_load_L_w0_incorrect_buf_pw0_1(void)
{
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL,
        sizeof(buf_pL),
        buf_pw0,
        0);

    TEST_ASSERT_MESSAGE(SPAKE2PLUS_OK != res, "Incorrect buf_pw0 for spake2plus_load_L_w0 failed!");
}

void test_load_L_w0_incorrect_buf_pw0_2(void)
{
    int res = spake2plus_load_L_w0(
        spake2_instance,
        buf_pL,
        sizeof(buf_pL),
        NULL,
        0);

    TEST_ASSERT_MESSAGE(SPAKE2PLUS_OK != res, "Incorrect buf_pw0 for spake2plus_load_L_w0 failed!");
}
