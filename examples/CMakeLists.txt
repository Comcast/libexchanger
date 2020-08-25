project(client)
add_executable(${PROJECT_NAME} client.c common.c)
target_link_libraries(${PROJECT_NAME} PUBLIC spake2plus)

target_include_directories(${PROJECT_NAME} PUBLIC "${spake2_plus_SOURCE_DIR}")

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND cp "${PROJECT_BINARY_DIR}/${PROJECT_NAME}" "${CMAKE_BINARY_DIR}/${PROJECT_NAME}"
)

project(server)
add_executable(${PROJECT_NAME} server.c common.c)
target_link_libraries(${PROJECT_NAME} PUBLIC spake2plus)

target_include_directories(${PROJECT_NAME} PUBLIC "${spake2_plus_SOURCE_DIR}")

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND cp "${PROJECT_BINARY_DIR}/${PROJECT_NAME}" "${CMAKE_BINARY_DIR}/${PROJECT_NAME}"
)
