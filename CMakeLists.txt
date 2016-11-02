project(sysrepo-plugin-ietf-system C)
cmake_minimum_required(VERSION 3.0)

include(GNUInstallDirs)

find_package(PkgConfig)
pkg_check_modules(SYSREPO REQUIRED libsysrepo)

set(CMAKE_CFLAGS "-Wall -pedantic -O2 ${CMAKE_CFLAGS}")

add_definitions(${SYSREPO_CFLAGS})
include_directories(${SYSREPO_INCLUDE_DIRS})
link_directories(${SYSREPO_LIBRARY_DIRS})

set(YANG_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/iana-crypt-hash.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/ietf-netconf-acm.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/ietf-system.yang
)
add_custom_target(YANG_files ${YANG_SRCS})

add_library(sysrepo-plugin-ietf-system SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/system-plugin.c
)
target_link_libraries(sysrepo-plugin-ietf-system ${SYSREPO_LIBRARIES})

set(PLUGINS_DIR "${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}/sysrepo/plugins/" CACHE PATH "Sysrepo plugins directory.")
set(YANG_DIR ${CMAKE_INSTALL_PREFIX}/share/sysrepo/yang)

    install(FILES ${YANG_SRCS} DESTINATION ${YANG_DIR})
install(TARGETS sysrepo-plugin-ietf-system DESTINATION ${PLUGINS_DIR})
install(CODE "MESSAGE(STATUS
\"To enable this plugin, run:

 - sysrepoctl --install -s ${YANG_DIR} --module ietf-system
 - systemctl restart sysrepo-plugind
\")")
