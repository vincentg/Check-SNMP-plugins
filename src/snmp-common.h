/*
    snmp-common . Common file for Nagios snmp plugins

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


struct snmpv3_args
{
#define AUTH_ALGO_MAX_SIZE 8 // SHA-512 + 0
#define PRIV_ALGO_MAX_SIZE 4 // AES + 0
    char *username;
    char *password;
    char *priv_password;
    char auth_algo[AUTH_ALGO_MAX_SIZE];
    char priv_algo[PRIV_ALGO_MAX_SIZE];    
};
typedef struct snmpv3_args snmpv3_args_t;

void init_v3_args(snmpv3_args_t *v3_args); 
void free_v3_args(snmpv3_args_t *v3_args);

void snmpv3_parseargs(int verbose, int opt, char *optarg, snmpv3_args_t *v3args);
void snmpv3_set_session(netsnmp_session *session, const snmpv3_args_t *v3args);


netsnmp_pdu *getResponse(oid *nameoid, size_t nameoid_length,
                         netsnmp_session *pss, int type);
void snmp_get_uchar(netsnmp_session *ss, oid *theoid, size_t theoid_len,
                    unsigned char *result, size_t length);
int snmp_get_int(netsnmp_session *ss, oid *theoid, size_t theoid_len);

int is_integer(char *number);

void print_version(void);
