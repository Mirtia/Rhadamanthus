cmake_minimum_required(VERSION 3.15)
project(vmi_examples C)

set(CMAKE_C_STANDARD 99)

find_package(cJSON REQUIRED)
find_package(glib REQUIRED)
find_package(log.c REQUIRED)
find_package(yaml REQUIRED)
# # Enable building using cmake-conan   
# list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
# set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "cmake/external/conan.cmake")

# Conan integration
# include(${CMAKE_BINARY_DIR}/conan_toolchain.cmake OPTIONAL RESULT_VARIABLE _toolchain_included)
# Always include dependencies before using targets
# include(${CMAKE_BINARY_DIR}/conan_deps.cmake OPTIONAL RESULT_VARIABLE _conan_deps_included)

function(add_vmi_example exe source)
    add_executable(${exe} src/${source})
    target_link_libraries(${exe} PRIVATE cjson::cjson yaml log.c::log.c vmi m glib::glib)
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

# Platform-specific
if(ENABLE_WINDOWS)
    add_vmi_example(vmi-win-guid win-guid.c)
    add_vmi_example(vmi-win-offsets win-offsets.c)
endif()

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

if(ENABLE_WINDOWS)
    install(TARGETS
        vmi-win-guid
        vmi-win-offsets
        DESTINATION bin)
endif()

if(ENABLE_LINUX)
    install(TARGETS
        vmi-dmesg
        DESTINATION bin)
endif()
