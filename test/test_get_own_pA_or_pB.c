#include "unity.h"
#include "spake2plus.h"
#include "test_globals.h"
#include <string.h>
#include <stdbool.h>

static char *g_pw_ptr = "test password";
static char *g_srv_id_ptr = "test server id";
static char *g_client_id_ptr = "test client id";
static char *g_aad_ptr = "test additional info";
static size_t g_pA_or_pB_len = 0;
static uint8_t *g_pA_or_pB = NULL;
static uint8_t g_pA_or_pB_fixed[2000];

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
static void default_get_pA_or_pB()
{
    TEST_ASSERT(SPAKE2PLUS_OK == spake2plus_get_own_pA_or_pB(NULL, &g_pA_or_pB_len, spake2_instance));
    TEST_ASSERT(NULL != (g_pA_or_pB = malloc(g_pA_or_pB_len)));
    TEST_ASSERT(SPAKE2PLUS_OK == spake2plus_get_own_pA_or_pB(g_pA_or_pB, &g_pA_or_pB_len, spake2_instance));
}
static void default_setup_params(char *group, char *hash, char *mac, int c_or_s)
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

    res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));
    TEST_ASSERT_MESSAGE(res == SPAKE2PLUS_OK, "Default password initialization failed!");

    res = spake2plus_setup_protocol(spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Default protocol setup failed!");
}
static void default_setup(int c_or_s)
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

    res = spake2plus_pwd_init(
        spake2_instance,
        g_pw_ptr,
        strlen(g_pw_ptr));
    TEST_ASSERT_MESSAGE(res == SPAKE2PLUS_OK, "Default password initialization failed!");

    res = spake2plus_setup_protocol(spake2_instance);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Default protocol setup failed!");
}

static void cleanup(void)
{
    OPENSSL_CHECK_NULL_AND_FREE(g_pA_or_pB);
}

void test_get_own_pA_or_pB_incorrect_instance(void)
{
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        NULL);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INSTANCE_IS_NULL, res, "Incorrect instance get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_incorrect_only_init_c(void)
{
    default_init(SPAKE2PLUS_CLIENT);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect only init client confirmation keys derivation failed!");
}

void test_get_own_pA_or_pB_incorrect_only_init_s(void)
{
    default_init(SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect only init server confirmation keys derivation failed!");
}

void test_get_own_pA_or_pB_incorrect_only_init_pw_c(void)
{
    default_init(SPAKE2PLUS_CLIENT);
    default_init_pw();
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_IS_GROUP_IDENTITY, res, "Incorrect only init pw client confirmation keys derivation failed!");
}

void test_get_own_pA_or_pB_incorrect_only_init_pw_s(void)
{
    default_init(SPAKE2PLUS_SERVER);
    default_init_pw();
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_IS_GROUP_IDENTITY, res, "Incorrect only init pw server confirmation keys derivation failed!");
}

void test_get_own_pA_or_pB_default_s(void)
{
    default_setup(SPAKE2PLUS_SERVER);

    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_default_c(void)
{
    default_setup(SPAKE2PLUS_CLIENT);

    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_back_conversion_c(void)
{
    default_init(SPAKE2PLUS_CLIENT);
    default_init_pw();
    default_setup_protocol();
    default_get_pA_or_pB();
    EC_POINT *pback_conversion = NULL;
    BN_CTX *ctx = NULL;
    TEST_ASSERT(NULL != (ctx = BN_CTX_secure_new()));
    BN_CTX_start(ctx);
    TEST_ASSERT(NULL != (pback_conversion = EC_POINT_new(spake2_instance->group)));
    TEST_ASSERT(1 == EC_POINT_oct2point(
                         spake2_instance->group,
                         pback_conversion,
                         (unsigned char *)g_pA_or_pB,
                         g_pA_or_pB_len,
                         ctx));

    int res = EC_POINT_cmp(spake2_instance->group, pback_conversion, spake2_instance->pA, ctx);

    BN_CTX_CHECK_NULL_AND_FREE(ctx);
    EC_POINT_CHECK_NULL_AND_FREE(pback_conversion);
    pback_conversion = NULL;

    OPENSSL_CHECK_NULL_AND_FREE(g_pA_or_pB);

    TEST_ASSERT_EQUAL_MESSAGE(0, res, "Normal reverse conversion of pA failed!");
}

void test_get_own_pA_or_pB_back_conversion_s(void)
{
    default_init(SPAKE2PLUS_SERVER);
    default_init_pw();
    default_setup_protocol();
    default_get_pA_or_pB();
    EC_POINT *pback_conversion = NULL;
    BN_CTX *ctx = NULL;
    TEST_ASSERT(NULL != (ctx = BN_CTX_secure_new()));
    BN_CTX_start(ctx);
    TEST_ASSERT(NULL != (pback_conversion = EC_POINT_new(spake2_instance->group)));
    TEST_ASSERT(1 == EC_POINT_oct2point(
                         spake2_instance->group,
                         pback_conversion,
                         (unsigned char *)g_pA_or_pB,
                         g_pA_or_pB_len,
                         ctx));

    int res = EC_POINT_cmp(spake2_instance->group, pback_conversion, spake2_instance->pB, ctx);

    BN_CTX_CHECK_NULL_AND_FREE(ctx);
    EC_POINT_CHECK_NULL_AND_FREE(pback_conversion);
    pback_conversion = NULL;

    OPENSSL_CHECK_NULL_AND_FREE(g_pA_or_pB);

    TEST_ASSERT_EQUAL_MESSAGE(0, res, "Normal reverse conversion of pB failed!");
}

void test_get_own_pA_or_pB_correct_null_pA_or_pB_s(void)
{
    default_setup(SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        NULL,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get pA_or_pB_len failed!");
}

void test_get_own_pA_or_pB_correct_null_pA_or_pB_c(void)
{
    default_setup(SPAKE2PLUS_CLIENT);
    int res = spake2plus_get_own_pA_or_pB(
        NULL,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get pA_or_pB_len failed!");
}

void test_get_own_pA_or_pB_incorrect_null_pA_or_pB_len_s(void)
{
    default_setup(SPAKE2PLUS_SERVER);

    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        NULL,
        spake2_instance);

    cleanup();

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PA_OR_PB_LEN_NULL_POINTER, res, "Incorrect server get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_incorrect_null_pA_or_pB_len_c(void)
{
    default_setup(SPAKE2PLUS_CLIENT);

    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        NULL,
        spake2_instance);

    cleanup();

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_PA_OR_PB_LEN_NULL_POINTER, res, "Incorrect client get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_default_p256_sha512_cmac_s(void)
{
    default_setup_params(
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_default_p256_sha256_cmac_c(void)
{
    default_setup_params(
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_default_p384_sha256_hmac_s(void)
{
    default_setup_params(
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_default_p384_sha512_hmac_c(void)
{
    default_setup_params(
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_default_p521_sha512_hmac_s(void)
{
    default_setup_params(
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_default_p521_sha256_hmac_c(void)
{
    default_setup_params(
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_default_ed25519_sha256_hmac_s(void)
{
    default_setup_params(
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_default_ed25519_sha512_hmac_c(void)
{
    default_setup_params(
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_default_ed448_sha512_hmac_s(void)
{
    default_setup_params(
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get pA_or_pB failed!");
}

void test_get_own_pA_or_pB_default_ed448_sha256_hmac_c(void)
{
    default_setup_params(
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_own_pA_or_pB(
        g_pA_or_pB_fixed,
        &g_pA_or_pB_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get pA_or_pB failed!");
}
