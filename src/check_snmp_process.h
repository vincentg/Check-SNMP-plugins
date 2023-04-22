/*
    check_snmp_process . A Nagios plugin to monitor process via SNMP

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

int perfdata = 0;
int verbose = 0;
int warnzero = 0;
int critmem = 0;
int rammin = 9999;

typedef struct process
{
  int *index;
  unsigned char procstr[20];
  int nbr;
  int ram;
  int cpu;

} t_process;

t_process *process;

const oid objid_mib[] = {1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 2};

int warningmin = -1;
int criticalmin = -1;

int procnbr = 0;

void usage(void);
int checkProc(netsnmp_session *ss);
t_process *newProcessEntry(int index_process, t_process *process,
                           u_char *descr, size_t descr_length,
                           int ram, int cpu);

int check_and_print(netsnmp_session *ss, int procnbr);
