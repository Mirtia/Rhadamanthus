cmake_minimum_required(VERSION 3.10)
project(introspector C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Note: There is a log.c issue with exposing only on Release
set(CMAKE_BUILD_TYPE Release)

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)
find_package(cJSON REQUIRED)
find_package(log.c REQUIRED)
find_package(yaml REQUIRED)
find_package(CMocka REQUIRED)
find_package(OpenSSL REQUIRED)

file(GLOB STATE_CALLBACKS "src/state_callbacks/*.c")
file(GLOB EVENT_CALLBACKS "src/event_callbacks/*.c")

add_library(vmi_event_handler STATIC
    src/event_handler.c
    src/config_parser.c
    src/serializer.c
    src/callback_handler.c
    src/state_task_map.c
    src/event_task_map.c
    src/utils.c
    ${STATE_CALLBACKS}
    ${EVENT_CALLBACKS}
)

target_include_directories(vmi_event_handler PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${GLIB2_INCLUDE_DIRS}
)

target_link_libraries(vmi_event_handler
    ${GLIB2_LIBRARIES}
    yaml
    cjson::cjson
    log.c::log.c
    vmi
    OpenSSL::Crypto
)

target_compile_options(vmi_event_handler PRIVATE ${GLIB2_CFLAGS_OTHER})

add_executable(introspector src/main.c)

target_link_libraries(introspector OpenSSL::Crypto
    vmi_event_handler
)

# Tests

enable_testing()

add_executable(test_event_handler
    tests/test_event_handler.c
)

target_link_libraries(test_event_handler
    vmi_event_handler
    ${GLIB2_LIBRARIES}
    log.c::log.c
    cmocka::cmocka
)

add_executable(test_config_parser
    tests/test_config_parser.c
)

target_link_libraries(test_config_parser
    vmi_event_handler
    ${GLIB2_LIBRARIES}
    log.c::log.c
    cmocka::cmocka
)

add_executable(test_state_callbacks_syscall_table
    tests/test_state_callbacks_syscall_table.c
)

target_link_libraries(test_state_callbacks_syscall_table
    vmi_event_handler
    ${GLIB2_LIBRARIES}
    log.c::log.c
    cmocka::cmocka
)

add_executable(test_state_callbacks_kernel_module_list
    tests/test_state_callbacks_kernel_module_list.c
)

target_link_libraries(test_state_callbacks_kernel_module_list
    vmi_event_handler
    ${GLIB2_LIBRARIES}
    log.c::log.c
    cmocka::cmocka
)


add_executable(test_state_callbacks_idt_table
    tests/test_state_callbacks_idt_table.c
)

target_link_libraries(test_state_callbacks_idt_table
    vmi_event_handler
    ${GLIB2_LIBRARIES}
    log.c::log.c
    cmocka::cmocka
)

add_test(NAME ConfigParserTest COMMAND test_config_parser)
add_test(NAME EventHandlerTest COMMAND test_event_handler)
add_test(NAME StateCallbacksSyscallTableTest COMMAND test_state_callbacks_syscall_table)
add_test(NAME StateCallbacksKernelModuleListTest COMMAND test_state_callbacks_kernel_module_list)
add_test(NAME StateCallbacksIdtTableTest COMMAND test_state_callbacks_idt_table)

add_compile_definitions(TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
# TODO: Check that the syscall index is appropriate (matches the linux kernel version).
add_compile_definitions(SYSCALL_INDEX_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/syscall_index.linux")
add_compile_definitions(INTERRUPT_INDEX_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/interrupt_index.linux")
add_compile_definitions(BASELINE_HASH_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/ubuntu-20-04-new-kernel-clean.bin")

install(TARGETS introspector DESTINATION bin)
