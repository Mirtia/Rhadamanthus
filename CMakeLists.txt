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

add_library(vmi_dispatcher STATIC
    src/dispatcher.c
    src/config_parser.c
    src/serializer.c
    src/state_callbacks/module_list.c
    src/event_callbacks/cr0_write.c
)

target_include_directories(vmi_dispatcher PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${GLIB2_INCLUDE_DIRS}
)

target_link_libraries(vmi_dispatcher
    ${GLIB2_LIBRARIES}
    yaml
    cjson::cjson
    log.c::log.c
    vmi
)

target_compile_options(vmi_dispatcher PRIVATE ${GLIB2_CFLAGS_OTHER})

add_executable(introspector src/main.c)

target_link_libraries(introspector
    vmi_dispatcher
)

# Tests
enable_testing()

add_executable(test_dispatcher tests/test_dispatcher.c)

target_link_libraries(test_dispatcher
    vmi_dispatcher
    ${GLIB2_LIBRARIES}
    log.c::log.c
    cmocka::cmocka
)

add_test(NAME DispatcherTest COMMAND test_dispatcher)

install(TARGETS introspector DESTINATION bin)
