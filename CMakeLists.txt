cmake_minimum_required(VERSION 3.26)
project(Check-SNMP-plugins C)

set(CMAKE_C_STANDARD 99)
SET(CMAKE_C_COMPILER /usr/bin/gcc)

find_library(NETSNMP "netsnmp")

add_executable(check_snmp_disk src/check_snmp_disk.c src/snmp-common.c src/snmp-common.h)
add_executable(check_snmp_process src/check_snmp_process.c src/snmp-common.c src/snmp-common.h)
add_executable(check_snmp_load src/check_snmp_process.c src/snmp-common.c src/snmp-common.h)

target_link_libraries(check_snmp_disk ${NETSNMP})
target_link_libraries(check_snmp_process ${NETSNMP})
target_link_libraries(check_snmp_load ${NETSNMP})


