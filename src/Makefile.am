
bin_PROGRAMS = check_snmp_disk check_snmp_process check_snmp_load
SNMP_OBJ = snmp-common.o

check_snmp_disk_LDADD = $(SNMP_OBJ)
check_snmp_process_LDADD = $(SNMP_OBJ)
check_snmp_load_LDADD = $(SNMP_OBJ)

check_snmp_disk_DEPENDENCIES = $(SNMP_OBJ)
check_snmp_process_DEPENDENCIES = $(SNMP_OBJ)
check_snmp_load_DEPENDENCIES = $(SNMP_OBJ)


snmp_common.o: snmp-common.c snmp-common.h

check_snmp_disk.o: check_snmp_disk.c
check_snmp_process.o: check_snmp_process.c
check_snmp_load.o: check_snmp_load.c
