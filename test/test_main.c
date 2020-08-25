#include "unity.h"
#include "spake2plus.h"
#include "test_init.h"
#include "test_init_pw.h"
#include "test_load_L_w0.h"
#include "test_setup_protocol.h"
#include "test_get_own_pA_or_pB.h"
#include "test_derive_conf_keys.h"
#include "test_verify.h"
#include "test_get_Ke.h"
#include "test_vectors.h"

SPAKE2PLUS *spake2_instance = NULL;

void setUp(void)
{
    spake2_instance = NULL;
}

void tearDown(void)
{
    // clean stuff up here
    spake2plus_free(spake2_instance);
    spake2_instance = NULL;
}

int main(void)
{
    UNITY_BEGIN();
    DECLARE_TESTS_INIT();
    DECLARE_TESTS_INIT_PW();
    DECLARE_TESTS_LOAD_L_W0();
    DECLARE_TESTS_SETUP_PROTOCOL();
    DECLARE_TESTS_GET_PA_OR_PB();
    DECLARE_TESTS_DERIVE_CONF();
    DECLARE_TESTS_VERIFY();
    DECLARE_TESTS_GET_KE();
    DECLARE_TESTS_WITH_VECTORS();
    spake2plus_openssl_cleanup();
    return UNITY_END();
}
