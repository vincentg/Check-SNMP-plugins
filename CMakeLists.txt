cmake_minimum_required(VERSION 3.26)
project(Check-SNMP-plugins C)

find_library(NETSNMP "netsnmp")

add_executable(check_snmp_disk src/check_snmp_disk.c src/snmp-common.c src/snmp-common.h)
add_executable(check_snmp_process src/check_snmp_process.c src/snmp-common.c src/snmp-common.h)
add_executable(check_snmp_load src/check_snmp_load.c src/snmp-common.c src/snmp-common.h)

target_link_libraries(check_snmp_disk ${NETSNMP})
target_link_libraries(check_snmp_process ${NETSNMP})
target_link_libraries(check_snmp_load ${NETSNMP})


