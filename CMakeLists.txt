cmake_minimum_required(VERSION 3.12)
set(CMAKE_XCODE_GENERATE_SCHEME ON)
set(CMAKE_XCODE_SCHEME_ADDRESS_SANITIZER ON)
set(CMAKE_XCODE_SCHEME_ADDRESS_SANITIZER_USE_AFTER_RETURN ON)

project(SPAKE2plus_lib VERSION 1.0)
SET(CMAKE_C_OUTPUT_EXTENSION .o)
SET(CMAKE_C_OUTPUT_EXTENSION_REPLACE 1)

# Requirement: use ANSI C
# According to GCC docs it is equivalent to C90 
# (https://gcc.gnu.org/onlinedocs/gcc/C-Dialect-Options.html#C-Dialect-Options)                           
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED True)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(Spake2PlusDoxygenDoc)

add_compile_options(-Wall -Wextra -Werror -Wstrict-aliasing=2)

include(CTest)

# Build Types
# - Debug
# - Release
# - asan
# - lsan
# - ubsan
set(build_types_list Release Debug asan lsan ubsan)
IF( NOT CMAKE_BUILD_TYPE )
   SET( CMAKE_BUILD_TYPE Debug )
ENDIF()

set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
    CACHE STRING "Choose the type of build, options are: Debug Release asan lsan ubsan"
    FORCE)

if(NOT (${CMAKE_BUILD_TYPE} IN_LIST build_types_list))
  message(FATAL_ERROR "Unsupported CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}." )
endif()

IF( NOT COMMON_DEBUG )
   SET(COMMON_DEBUG 0)
else()
   SET(COMMON_DEBUG "${COMMON_DEBUG}")
ENDIF()

IF( NOT FATAL_DEBUG )
   SET(FATAL_DEBUG 0)
else()
   SET(FATAL_DEBUG "${FATAL_DEBUG}")
ENDIF()

IF( NOT CONCATENATE_ARRAYS_DEBUG )
   SET(CONCATENATE_ARRAYS_DEBUG 0)
else()
   SET(CONCATENATE_ARRAYS_DEBUG "${CONCATENATE_ARRAYS_DEBUG}")
ENDIF()
add_definitions(-DCOMMON_DEBUG=${COMMON_DEBUG} -DFATAL_DEBUG=${FATAL_DEBUG} -DCONCATENATE_ARRAYS_DEBUG=${CONCATENATE_ARRAYS_DEBUG})

add_subdirectory(src)
add_subdirectory(examples)
add_subdirectory(test)

# AddressSanitize
# Sanitizer usage: cmake -DCMAKE_BUILD_TYPE=asan
set(CMAKE_C_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C++ compiler during AddressSanitizer builds."
    FORCE)

# LeakSanitizer
set(CMAKE_C_FLAGS_LSAN
    "-fsanitize=leak -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during LeakSanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_LSAN
    "-fsanitize=leak -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C++ compiler during LeakSanitizer builds."
    FORCE)

# MemorySanitizer
set(CMAKE_C_FLAGS_MSAN
    "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O2"
    CACHE STRING "Flags used by the C compiler during MemorySanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_MSAN
    "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O2"
    CACHE STRING "Flags used by the C++ compiler during MemorySanitizer builds."
    FORCE)

# UndefinedBehaviour
set(CMAKE_C_FLAGS_UBSAN
    "-fsanitize=undefined"
    CACHE STRING "Flags used by the C compiler during UndefinedBehaviourSanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_UBSAN
    "-fsanitize=undefined"
    CACHE STRING "Flags used by the C++ compiler during UndefinedBehaviourSanitizer builds."
    FORCE)

# Valgrind usage: ctest -T memcheck
find_program(MEMORYCHECK_COMMAND NAMES valgrind)
if(MEMORYCHECK_COMMAND STREQUAL "MEMORYCHECK_COMMAND-NOTFOUND")
	message(WARNING "Valgrind not found, corresponding checks won't be available.")
endif()
set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full  --show-leak-kinds=all -v")


add_doxygen_doc(
  BUILD_DIR
    ${CMAKE_CURRENT_BINARY_DIR}/_build
  DOXY_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in
  TARGET_NAME
    docs
  COMMENT
    "HTML documentation"
  )
