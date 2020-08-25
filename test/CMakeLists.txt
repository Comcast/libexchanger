# set the project name

project(unity_tests)
# add the executable
add_executable("${PROJECT_NAME}" test_main.c 
    test_init.c 
    test_init_pw.c 
    test_load_L_w0.c 
    test_setup_protocol.c
    test_get_own_pA_or_pB.c
    test_derive_conf_keys.c
    test_verify.c
    test_get_Ke.c
    test_vectors.c)

add_subdirectory(Unity)

target_link_libraries("${PROJECT_NAME}" PUBLIC spake2plus)
target_link_libraries("${PROJECT_NAME}" PUBLIC unity)

target_include_directories("${PROJECT_NAME}" PUBLIC "${spake2plus_SOURCE_DIR}" "${unity_SOURCE_DIR}/src")

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND cp "${PROJECT_BINARY_DIR}/${PROJECT_NAME}" "${CMAKE_BINARY_DIR}/${PROJECT_NAME}"
    COMMAND cp "${CMAKE_CURRENT_SOURCE_DIR}/test_server_client_exhausting.sh" "${CMAKE_BINARY_DIR}"
)

add_test(libtest ${PROJECT_NAME})
