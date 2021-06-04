/*
*    check_snmp_disk . A Nagios plugin to monitor storage via SNMP	    
*
*    Copyright (C) 2006  Vincent GERARD v.ge@wanadoo.fr
*
*    This program is free software; you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation; either version 2 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program; see the file COPYING. If not, write to the
*    Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <sys/types.h>

#define TYPE_MEM 0
#define TYPE_VMEM 1
#define TYPE_FIXED 2
#define TYPE_NET 3

#define OK 0
#define WARNING 1
#define CRITICAL 2
#define UNKNOWN 3


int verbose = 0;
int perfdata = 0;

typedef struct store
{
  int index;
  unsigned char descr[50];
  int allocunit;
  int totalsize;
  int used;
  int type;

} t_storage;


oid FIXED_DISK[] = { 1, 3, 6, 1, 2, 1, 25, 2, 1, 4 };
oid VIRTUAL_MEM[] = { 1, 3, 6, 1, 2, 1, 25, 2, 1, 3 };
oid RAM[] = { 1, 3, 6, 1, 2, 1, 25, 2, 1, 2 };
oid NETWORK_DISK[] = { 1, 3, 6, 1, 2, 1, 25, 2, 1, 10 };
oid objid_mib[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 2 };

int warningmin = -1;
int criticalmin = -1;
int check_ram = 0;
int check_disk = 0;
int check_net = 0;
int check_vmem = 0;
int filteron = 0;
char filter[20];


void usage (void);
int checkDisk (netsnmp_session * ss);

int check_and_print (t_storage * storage, int index_storage);

t_storage *newStorageEntry (int index_storage, t_storage * storage,
			    unsigned char * descr, size_t descr_length,
			    int allocunit, int totalsize,
			    int used, int index_oid, int type);

