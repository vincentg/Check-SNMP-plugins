/*
    check_snmp_load . A Nagios plugin to monitor load via SNMP	    

    Copyright (C) 2006  Vincent GERARD v.ge@wanadoo.fr

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; see the file COPYING. If not, write to the
    Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


#define OK 0
#define WARNING 1
#define CRITICAL 2
#define UNKNOWN 3

#define WINDOWS 0
#define LINUX 1

int verbose = 0;
int style = 3;
int perfdata =0;

int *load;
double linload[3];


const oid linux_mib[] = { 1, 3, 6, 1, 4, 1, 2021, 10, 1, 3 };
const oid win_mib[] = { 1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2 };

int warningmin[3] = { -1, -1, -1 };
int criticalmin[3] = { -1, -1, -1 };



void usage (void);
int checkLoad (netsnmp_session * ss);

int check_and_print (int cpunbr);
