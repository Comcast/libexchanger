#pragma once

void test_vectors_cs(void);
void test_vectors_c0(void);
void test_vectors_0s(void);
void test_vectors_00(void);

#if __x86_64__
#define DECLARE_TESTS_WITH_VECTORS() \
    RUN_TEST(test_vectors_cs);       \
    RUN_TEST(test_vectors_c0);       \
    RUN_TEST(test_vectors_0s);       \
    RUN_TEST(test_vectors_00);
#else
#define DECLARE_TESTS_WITH_VECTORS()
#endif
