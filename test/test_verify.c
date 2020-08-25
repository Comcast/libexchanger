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
static size_t g_pA_or_pB_third_len = 0;
static uint8_t *g_pA_or_pB_third = NULL;
static size_t g_Fa_or_Fb_len = 0;
static uint8_t g_Fa_or_Fb[EVP_MAX_MD_SIZE] = {0};
static size_t g_Fa_or_Fb_buddy_len = 0;
static uint8_t g_Fa_or_Fb_buddy[EVP_MAX_MD_SIZE] = {0};
static size_t g_Fa_or_Fb_third_len = 0;
static uint8_t g_Fa_or_Fb_third[EVP_MAX_MD_SIZE] = {0};

static SPAKE2PLUS *spake2_buddy_inst = NULL;
static SPAKE2PLUS *spake2_third_inst = NULL;

static uint8_t g_Fa_or_Fb_example[] =
    {
        0x04, 0x87, 0x95, 0x67, 0xd0, 0x95, 0x60, 0xc0, 0x2b, 0xe5,
        0x65, 0x42, 0x90, 0x36, 0xed, 0x1d, 0x2f, 0xc3, 0xca, 0x53,
        0xf2, 0xeb, 0x6f, 0xad, 0xda, 0x4d, 0xba, 0x09, 0xef, 0xf3,
        0xa0, 0x09, 0x6f, 0x03, 0x2f, 0x0e, 0x22, 0x72, 0x07, 0xeb,
        0xeb, 0xe0, 0x5e, 0x1e, 0x95, 0xde, 0x32, 0x5d, 0xff, 0xfe,
        0x57, 0x9c, 0x8a, 0xae, 0x76, 0x05, 0x40, 0x30, 0xe5, 0x43,
        0x5f, 0xd5, 0x29, 0x8c};

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
    int res = spake2plus_setup_protocol(
        spake2_instance);

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
    int res = spake2plus_setup_protocol(
        spake2_buddy_inst);

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
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Default server confirmation keys derivation failed!");
}

////////////////////////////

static void default_init_third(int c_or_s)
{
    int res = spake2plus_init(
        &spake2_third_inst,
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
static void default_init_pw_third()
{
    int res = spake2plus_pwd_init(
        spake2_third_inst,
        g_pw_ptr,
        strlen(g_pw_ptr));
    TEST_ASSERT_MESSAGE(res == SPAKE2PLUS_OK, "Default password initialization failed!");
}
static void default_setup_protocol_third()
{
    int res = spake2plus_setup_protocol(
        spake2_third_inst);

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Default protocol setup failed!");
}
static void default_get_pA_or_pB_third()
{
    TEST_ASSERT(SPAKE2PLUS_OK == spake2plus_get_own_pA_or_pB(NULL, &g_pA_or_pB_third_len, spake2_third_inst));
    TEST_ASSERT(NULL != (g_pA_or_pB_third = malloc(g_pA_or_pB_third_len)));
    TEST_ASSERT(SPAKE2PLUS_OK == spake2plus_get_own_pA_or_pB(g_pA_or_pB_third, &g_pA_or_pB_third_len, spake2_third_inst));
}
static void default_derive_conf_third()
{
    int res = spake2plus_derive_confirmation_keys(
        g_Fa_or_Fb_third,
        &g_Fa_or_Fb_third_len,
        spake2_third_inst,
        g_pA_or_pB,
        g_pA_or_pB_len);
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Default server confirmation keys derivation failed!");
}
static void default_setup_third(int c_or_s)
{
    default_init_third(c_or_s);
    default_init_pw_third();
    default_setup_protocol_third();
    default_get_pA_or_pB_third();
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
static void default_broken_session(int c_or_s)
{
    default_derive(c_or_s);

    spake2plus_free(spake2_instance);
    spake2_instance = NULL;
    OPENSSL_CHECK_NULL_AND_FREE(g_pA_or_pB);

    default_setup_party(c_or_s);
    default_setup_third(((SPAKE2PLUS_CLIENT == c_or_s) ? SPAKE2PLUS_SERVER : SPAKE2PLUS_CLIENT));
    default_derive_conf_third();
    default_derive_conf_party();
}
static void default_derive_diff_params(int c_or_s,
                                       char *group0, char *hash0, char *mac0,
                                       char *group1, char *hash1, char *mac1)
{
    default_setup_party_params(group0, hash0, mac0, c_or_s);
    default_setup_buddy_params(group1, hash1, mac1,
                               ((SPAKE2PLUS_CLIENT == c_or_s) ? SPAKE2PLUS_SERVER : SPAKE2PLUS_CLIENT));
    default_derive_conf_buddy();
    default_derive_conf_party();
}

static void cleanup(void)
{
    OPENSSL_CHECK_NULL_AND_FREE(g_pA_or_pB);
    OPENSSL_CHECK_NULL_AND_FREE(g_pA_or_pB_buddy);
    OPENSSL_CHECK_NULL_AND_FREE(g_pA_or_pB_third);
    spake2plus_free(spake2_buddy_inst);
    spake2_buddy_inst = NULL;
    spake2plus_free(spake2_third_inst);
    spake2_third_inst = NULL;
}

void test_verify_incorrect_instance(void)
{
    int res = spake2plus_verify(
        NULL,
        g_Fa_or_Fb_example,
        sizeof(g_Fa_or_Fb_example));

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_INSTANCE_IS_NULL, res, "Incorrect instance verification failed!");
}

void test_verify_incorrect_no_derive_s(void)
{
    default_setup(SPAKE2PLUS_SERVER);
    default_derive_conf_buddy();
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect server verification w/o derivation failed!");
}

void test_verify_incorrect_no_derive_c(void)
{
    default_setup(SPAKE2PLUS_CLIENT);
    default_derive_conf_buddy();
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_NOT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Incorrect client verification w/o derivation failed!");
}

void test_verify_default_s(void)
{
    default_derive(SPAKE2PLUS_SERVER);

    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server verification failed!");
}

void test_verify_default_c(void)
{
    default_derive(SPAKE2PLUS_CLIENT);

    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server verification failed!");
}

void test_verify_incorrect_Fa_or_Fb_s(void)
{
    default_derive(SPAKE2PLUS_SERVER);
    int res = spake2plus_verify(
        spake2_instance,
        NULL,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_OR_FB_IS_NULL, res, "Incorrect server verification failed!");
}

void test_verify_incorrect_Fa_or_Fb_c(void)
{
    default_derive(SPAKE2PLUS_CLIENT);
    int res = spake2plus_verify(
        spake2_instance,
        NULL,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_OR_FB_IS_NULL, res, "Incorrect client verification failed!");
}

void test_verify_incorrect_Fa_or_Fb_len_s(void)
{
    default_derive(SPAKE2PLUS_SERVER);

    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len + 1);

    cleanup();

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_FB_KEY_LEN_MISMATCH, res, "Incorrect server verification failed!");
}

void test_verify_incorrect_Fa_or_Fb_len_c(void)
{
    default_derive(SPAKE2PLUS_CLIENT);

    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len - 1);

    cleanup();

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_FB_KEY_LEN_MISMATCH, res, "Incorrect client verification incorrect length failed!");
}

void test_verify_default_p256_sha512_cmac_s(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();

    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server verification failed!");
}

void test_verify_default_p256_sha256_cmac_c(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_CMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client verification failed!");
}

void test_verify_default_p384_sha256_hmac_s(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server verification failed!");
}

void test_verify_default_p384_sha512_hmac_c(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P384_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client verification failed!");
}

void test_verify_default_p521_sha512_hmac_s(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server verification failed!");
}

void test_verify_default_p521_sha256_hmac_c(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_P521_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client verification failed!");
}

void test_verify_default_ed25519_sha256_hmac_s(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server verification failed!");
}

void test_verify_default_ed25519_sha512_hmac_c(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_ED25519_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client verification failed!");
}

void test_verify_default_ed448_sha512_hmac_s(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal server verification failed!");
}

void test_verify_default_ed448_sha256_hmac_c(void)
{
    default_derive_params(
        SPAKE2PLUS_GROUP_ED448_SEARCH_NAME,
        SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
        SPAKE2PLUS_HMAC_SEARCH_NAME,
        SPAKE2PLUS_SERVER);
    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_OK, res, "Normal client verification failed!");
}

void test_verify_incorrect_broken_session_0_s(void)
{
    default_broken_session(SPAKE2PLUS_SERVER);

    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_FB_KEY_MISMATCH, res, "Incorrect server verification broken session failed!");
}

void test_verify_incorrect_broken_session_0_c(void)
{
    default_broken_session(SPAKE2PLUS_CLIENT);

    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_FB_KEY_MISMATCH, res, "Incorrect server verification broken session failed!");
}

void test_verify_incorrect_broken_session_1_s(void)
{
    default_broken_session(SPAKE2PLUS_SERVER);

    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_third,
        g_Fa_or_Fb_third_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_FB_KEY_MISMATCH, res, "Incorrect server verification broken session failed!");
}

void test_verify_incorrect_broken_session_1_c(void)
{
    default_broken_session(SPAKE2PLUS_CLIENT);

    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_third,
        g_Fa_or_Fb_third_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_FB_KEY_MISMATCH, res, "Incorrect server verification broken session failed!");
}

void test_verify_incorrect_p256sha256hmac_vs_p256sha256cmac_s(void)
{
    default_derive_diff_params(SPAKE2PLUS_SERVER,
                               SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
                               SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
                               SPAKE2PLUS_HMAC_SEARCH_NAME,
                               SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
                               SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
                               SPAKE2PLUS_CMAC_SEARCH_NAME);

    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_FB_KEY_LEN_MISMATCH, res, "Incorrect server verification incorrect settings failed!");
}

void test_verify_incorrect_p256sha256hmac_vs_p256sha512hmac_c(void)
{
    default_derive_diff_params(SPAKE2PLUS_CLIENT,
                               SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
                               SPAKE2PLUS_HASH_SHA256_SEARCH_NAME,
                               SPAKE2PLUS_HMAC_SEARCH_NAME,
                               SPAKE2PLUS_GROUP_P256_SEARCH_NAME,
                               SPAKE2PLUS_HASH_SHA512_SEARCH_NAME,
                               SPAKE2PLUS_HMAC_SEARCH_NAME);

    int res = spake2plus_verify(
        spake2_instance,
        g_Fa_or_Fb_buddy,
        g_Fa_or_Fb_buddy_len);

    cleanup();
    TEST_ASSERT_EQUAL_MESSAGE(SPAKE2PLUS_FA_FB_KEY_LEN_MISMATCH, res, "Incorrect server verification incorrect settings failed!");
}
