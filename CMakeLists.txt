cmake_minimum_required(VERSION 3.15)
project(vmi_examples C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Release)
# log.c issue with exposing only on Release

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)

find_package(cJSON REQUIRED)
find_package(log.c REQUIRED)
find_package(yaml REQUIRED)

# Dispatcher library
add_library(vmi_dispatcher STATIC
    src/dispatcher.c
)

target_include_directories(vmi_dispatcher PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${GLIB2_INCLUDE_DIRS}
)
    
target_link_libraries(vmi_dispatcher PUBLIC vmi log.c::log.c)

# Example builder
function(add_vmi_example exe source)
    add_executable(${exe} src/${source})
    target_include_directories(${exe} PRIVATE
        ${GLIB2_INCLUDE_DIRS}
    )
    target_compile_options(${exe} PRIVATE ${GLIB2_CFLAGS_OTHER})
    target_link_libraries(${exe} PRIVATE
        cjson::cjson
        yaml
        vmi_dispatcher
        ${GLIB2_LIBRARIES}
    )
endfunction()

# Main executables
add_vmi_example(map-addr map-addr.c)
add_vmi_example(cr3-event-example cr3-event-example.c)
add_vmi_example(descriptor-event-example descriptor-event-example.c)
add_vmi_example(mem-event-example mem-event-example.c)
add_vmi_example(map-symbol map-symbol.c)
add_vmi_example(va-pages va-pages.c)
add_vmi_example(event-example event-example.c)
add_vmi_example(fool-patchguard fool-patchguard.c)
add_vmi_example(interrupt-event-example interrupt-event-example.c)
add_vmi_example(breakpoint-emulate-example breakpoint-emulate-example.c)
add_vmi_example(breakpoint-recoil-example breakpoint-recoil-example.c)
add_vmi_example(wait-for-domain-example wait-for-domain-example.c)
add_vmi_example(msr-event-example msr-event-example.c)
add_vmi_example(new-physical-page-example new-physical-page-example.c)
add_vmi_example(singlestep-event-example singlestep-event-example.c)
add_vmi_example(step-event-example step-event-example.c)
add_vmi_example(xen-emulate-reponse xen-emulate-response.c)
add_vmi_example(read-disk-example read-disk-example.c)
add_vmi_example(io-event-example io-event-example.c)
add_vmi_example(vmi-process-list process-list.c)
add_vmi_example(vmi-dump-memory dump-memory.c)
add_vmi_example(vmi-module-list module-list.c)
add_vmi_example(switch-view-example switch-view-example.c)
add_vmi_example(vmi-rwmem rwmem.c)

if(ENABLE_LINUX)
    add_vmi_example(vmi-dmesg dmesg.c)
    add_vmi_example(vmi-linux-offsets linux-offsets.c)
endif()

# Install only selected executables
install(TARGETS
    vmi-process-list
    vmi-module-list
    vmi-dump-memory
    DESTINATION bin)

if(ENABLE_LINUX)
    install(TARGETS
        vmi-dmesg
        DESTINATION bin)
endif()
