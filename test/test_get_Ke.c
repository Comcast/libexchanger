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
static size_t g_pA_or_pB_buddy_len = 0;
static uint8_t *g_pA_or_pB_buddy = NULL;
static size_t g_Fa_or_Fb_len = 0;
static uint8_t g_Fa_or_Fb[EVP_MAX_MD_SIZE] = {0};
static size_t g_Fa_or_Fb_buddy_len = 0;
static uint8_t g_Fa_or_Fb_buddy[EVP_MAX_MD_SIZE] = {0};
static uint8_t g_Ke[EVP_MAX_MD_SIZE] = {0};
static size_t g_Ke_len = sizeof(g_Ke);

static SPAKE2PLUS *spake2_buddy_inst = NULL;

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
static void default_get_pA_or_pB_party()
{
    TEST_ASSERT(SPAKE2PLUS_OK == spake2plus_get_own_pA_or_pB(NULL, &g_pA_or_pB_len, spake2_instance));
    TEST_ASSERT(NULL != (g_pA_or_pB = malloc(g_pA_or_pB_len)));
    TEST_ASSERT(SPAKE2PLUS_OK == spake2plus_get_own_pA_or_pB(g_pA_or_pB, &g_pA_or_pB_len, spake2_instance));
}
static void default_setup_party_params(char *group, char *hash, char *mac, int c_or_s)
{
    default_init_group_hash_mac_cs(group, hash, mac, c_or_s);
    default_init_pw();
    default_setup_protocol();
    default_get_pA_or_pB_party();
}
static void default_setup_party(int c_or_s)
{
    default_init(c_or_s);
    default_init_pw();
    default_setup_protocol();
    default_get_pA_or_pB_party();
}
static void default_derive_conf_party()
{
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb,
        &g_Fa_or_Fb_len,
        spake2_instance,
        g_pA_or_pB_buddy,
        g_pA_or_pB_buddy_len);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Default server confirmation keys derivation failed!");
}

////////////////////////////

static void default_init_buddy(int c_or_s)
{
    int res = spake2plus_init(
        &spake2_buddy_inst,
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
static void default_init_group_hash_mac_cs_buddy(char *group, char *hash, char *mac, int c_or_s)
{
    int res = spake2plus_init(
        &spake2_buddy_inst,
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
static void default_init_pw_buddy()
{
    int res = spake2plus_pwd_init(
        spake2_buddy_inst,
        g_pw_ptr,
        strlen(g_pw_ptr));
    TEST_ASSERT_MESSAGE(res == SPAKE2PLUS_OK, "Default password initialization failed!");
}
static void default_setup_protocol_buddy()
{
    int res = spake2plus_setup_protocol(spake2_buddy_inst);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Default protocol setup failed!");
}
static void default_get_pA_or_pB_buddy()
{
    TEST_ASSERT(SPAKE2PLUS_OK == spake2plus_get_own_pA_or_pB(NULL, &g_pA_or_pB_buddy_len, spake2_buddy_inst));
    TEST_ASSERT(NULL != (g_pA_or_pB_buddy = malloc(g_pA_or_pB_buddy_len)));
    TEST_ASSERT(SPAKE2PLUS_OK == spake2plus_get_own_pA_or_pB(g_pA_or_pB_buddy, &g_pA_or_pB_buddy_len, spake2_buddy_inst));
}

static void default_setup_buddy_params(char *group, char *hash, char *mac, int c_or_s)
{
    default_init_group_hash_mac_cs_buddy(group, hash, mac, c_or_s);
    default_init_pw_buddy();
    default_setup_protocol_buddy();
    default_get_pA_or_pB_buddy();
}
static void default_setup_buddy(int c_or_s)
{
    default_init_buddy(c_or_s);
    default_init_pw_buddy();
    default_setup_protocol_buddy();
    default_get_pA_or_pB_buddy();
}
static void default_derive_conf_buddy()
{
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb_buddy,
        &g_Fa_or_Fb_buddy_len,
        spake2_buddy_inst,
        g_pA_or_pB,
        g_pA_or_pB_len);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Default server get Ke failed!");
}

////////////////////////////

static void default_setup_params(char *group, char *hash, char *mac, int c_or_s)
{
    default_setup_party_params(group, hash, mac, c_or_s);
    default_setup_buddy_params(group, hash, mac,
                               ((SPAKE2PLUS_CLIENT == c_or_s) ? SPAKE2PLUS_SERVER : SPAKE2PLUS_CLIENT));
}
static void default_setup(int c_or_s)
{
    default_setup_party(c_or_s);
    default_setup_buddy(((SPAKE2PLUS_CLIENT == c_or_s) ? SPAKE2PLUS_SERVER : SPAKE2PLUS_CLIENT));
}
static void default_derive_params(char *group, char *hash, char *mac, int c_or_s)
{
    default_setup_params(group, hash, mac, c_or_s);
    default_derive_conf_buddy();
    default_derive_conf_party();
}
static void default_derive(int c_or_s)
{
    default_setup(c_or_s);
    default_derive_conf_buddy();
    default_derive_conf_party();
}

static void cleanup(void)
{
    OPENSSL_CHECK_NULL_AND_FREE(g_pA_or_pB);
    OPENSSL_CHECK_NULL_AND_FREE(g_pA_or_pB_buddy);
    spake2plus_free(spake2_buddy_inst);
    spake2_buddy_inst = NULL;
}

void test_get_Ke_incorrect_instance(void)
{
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        NULL);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INSTANCE_IS_NULL, res, "Incorrect instance get Ke failed!");
}

void test_get_Ke_incorrect_no_derive_s(void)
{
    default_setup(SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_KE_NOT_AVAILABLE, res, "Incorrect server get Ke w/o derivation failed!");
}

void test_get_Ke_incorrect_no_derive_c(void)
{
    default_setup(SPAKE2PLUS_CLIENT);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_KE_NOT_AVAILABLE, res, "Incorrect client get Ke w/o derivation failed!");
}

void test_get_Ke_default_s(void)
{
    default_derive(SPAKE2PLUS_SERVER);

    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get Ke failed!");
}

void test_get_Ke_default_c(void)
{
    default_derive(SPAKE2PLUS_CLIENT);

    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get Ke failed!");
}

void test_get_Ke_correct_null_Ke_s(void)
{
    default_derive(SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        NULL,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get Ke_len failed!");
}

void test_get_Ke_correct_null_Ke_c(void)
{
    default_derive(SPAKE2PLUS_CLIENT);
    int res = spake2plus_get_key_Ke(
        NULL,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get Ke_len failed!");
}

void test_get_Ke_incorrect_null_Ke_len_s(void)
{
    default_derive(SPAKE2PLUS_SERVER);

    int res = spake2plus_get_key_Ke(
        g_Ke,
        NULL,
        spake2_instance);

    cleanup();

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_KE_LEN_NULL, res, "Incorrect server get Ke failed!");
}

void test_get_Ke_incorrect_null_Ke_len_c(void)
{
    default_derive(SPAKE2PLUS_CLIENT);

    int res = spake2plus_get_key_Ke(
        g_Ke,
        NULL,
        spake2_instance);

    cleanup();

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_KE_LEN_NULL, res, "Incorrect client get Ke failed!");
}

void test_get_Ke_default_p256_sha512_cmac_s(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get Ke failed!");
}

void test_get_Ke_default_p256_sha256_cmac_c(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get Ke failed!");
}

void test_get_Ke_default_p384_sha256_hmac_s(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get Ke failed!");
}

void test_get_Ke_default_p384_sha512_hmac_c(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get Ke failed!");
}

void test_get_Ke_default_p521_sha512_hmac_s(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get Ke failed!");
}

void test_get_Ke_default_p521_sha256_hmac_c(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get Ke failed!");
}

void test_get_Ke_default_ed25519_sha256_hmac_s(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get Ke failed!");
}

void test_get_Ke_default_ed25519_sha512_hmac_c(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get Ke failed!");
}

void test_get_Ke_default_ed448_sha512_hmac_s(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server get Ke failed!");
}

void test_get_Ke_default_ed448_sha256_hmac_c(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_get_key_Ke(
        g_Ke,
        &g_Ke_len,
        spake2_instance);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client get Ke failed!");
}
