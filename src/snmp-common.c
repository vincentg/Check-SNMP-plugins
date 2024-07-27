/*
 *    snmp-common . Common file for Nagios snmp plugins
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

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <errno.h>
#include <limits.h>
#include "snmp-common.h"

#define VERSION "1.3"

void print_version(void)
{
    printf
        ("SNMP Plugins version %s by Vincent Gerard <vincent@xenbox.fr>\nDistributed under the terms of the GNU General Public License\n",
         VERSION);
}

void init_v3_args(snmpv3_args_t *v3_args)
{
    memset(v3_args, 0, sizeof(snmpv3_args_t));
}

void free_v3_args(snmpv3_args_t *v3_args)
{
    if (v3_args->password)
        free(v3_args->password);
    if (v3_args->username)
        free(v3_args->username);
    if (v3_args->priv_password)
        free(v3_args->priv_password);

    memset(v3_args, 0, sizeof(snmpv3_args_t));
}

void snmpv3_parseargs(int verbose, int opt, char *optarg, snmpv3_args_t *v3args)
{
    switch (opt) {
    case 'u':
        /* SNMPv3 Username */
        v3args->username = strdup(optarg);

        if (verbose)
            printf("Username set to %s\n", v3args->username);

        break;

    case 'p':
        /* SNMP passwd */
        v3args->password = strdup(optarg);

        if (verbose)
            printf("Password set\n");

        break;

    case 'k':
        /* SNMP algo */
        strncpy(v3args->auth_algo, optarg, AUTH_ALGO_MAX_SIZE - 1);

        if (verbose)
            printf("Authentication algo set to %s\n", v3args->auth_algo);

        break;

    case 'x':
        /* SNMP Priv algo */
        strncpy(v3args->priv_algo, optarg, PRIV_ALGO_MAX_SIZE - 1);

        if (verbose)
            printf("Privacy algo set to %s\n", v3args->priv_algo);

        break;

    case 'X':
        /* SNMP Priv passwd */
        v3args->priv_password = strdup(optarg);

        if (verbose)
            printf("Privacy Password set\n");

        break;
    }
}

void snmpv3_set_session(netsnmp_session *session, const snmpv3_args_t *v3args)
{
    int auth_type, priv_type, kuret;

    session->securityName = v3args->username;
    session->securityNameLen = strlen(v3args->username);

    // Basic validity check (3 = len of DES/AES)
    if (strlen(v3args->priv_algo) == 3 && v3args->priv_password)
        session->securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
    else
        session->securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;

    auth_type = usm_lookup_auth_type(v3args->auth_algo);
    if (auth_type) {
        session->securityAuthProto = sc_get_auth_oid(auth_type, &(session->securityAuthProtoLen));
    } else {
        printf("Invalid auth algo option: %s\n", v3args->auth_algo);
        exit(UNKNOWN);
    }

    session->securityAuthKeyLen = USM_AUTH_KU_LEN;
    kuret = generate_Ku(session->securityAuthProto, session->securityAuthProtoLen, (unsigned char *)v3args->password,
                        strlen(v3args->password), session->securityAuthKey, &(session->securityAuthKeyLen));

    if (kuret != SNMPERR_SUCCESS) {
        printf("Error generating SNMP Authentication Key from the passphrase\n");
        exit(UNKNOWN);
    }

    if (session->securityLevel == SNMP_SEC_LEVEL_AUTHPRIV) {
        priv_type = usm_lookup_priv_type(v3args->priv_algo);

        if (priv_type) {
            session->securityPrivProto = sc_get_priv_oid(priv_type, &(session->securityPrivProtoLen));
        } else {
            printf("Invalid privacy algo option: %s\n", v3args->priv_algo);
            exit(UNKNOWN);
        }
        session->securityPrivKeyLen = USM_PRIV_KU_LEN;
        kuret =
            generate_Ku(session->securityAuthProto, session->securityAuthProtoLen,
                        (unsigned char *)v3args->priv_password, strlen(v3args->priv_password), session->securityPrivKey,
                        &(session->securityPrivKeyLen));

        if (kuret != SNMPERR_SUCCESS) {
            printf("Error generating SNMP Privacy Key from the passphrase\n");
            exit(UNKNOWN);
        }

    }
}

/*
 *   Returns 1 if the supplied number is an integer, 0 if not
 */

int is_integer(char *number)
{
    long int n;

    if (strspn(number, "-0123456789 ") != strlen(number))
        return (0);
    n = strtol(number, NULL, 10);
    if ((errno != ERANGE) && (n >= INT_MIN) && (n <= INT_MAX))
        return (1);
    return (0);
}

/* getResponse
 * args :  *nameoid = oid to go
 * 	    nemeoid_length = oid length
 *	    *pss =  SNMP session pointer
 *	    type = reponse type :
 *	      - SNMP_MSG_GET : go to the oid nameoid
 *	      - SNMP_MSG_GETNEXT : on the Next OID useful to walk SNMP tree
 *
 * return :	*response : pdu pointer or NULL if error
 */
netsnmp_pdu *getResponse(oid *nameoid, size_t nameoid_length, netsnmp_session *pss, int type)
{

    netsnmp_pdu *pdu, *response;
    int status;
    /*
     * create PDU for GETNEXT request and add object name to request
     */

    pdu = snmp_pdu_create(type);
    snmp_add_null_var(pdu, nameoid, nameoid_length);

    /*
     * do the request
     */
    status = snmp_synch_response(pss, pdu, &response);
    if (status == STAT_SUCCESS) {

        return response;
    } else {
        return NULL;
    }
}

/*
 * snmp_get_uchar : return the u_char of the given OID
 *	arguments : ... (like getResponse)
 *		    - *result : where the response should be written
 *		    - length : size of the strncpy
 */

void snmp_get_uchar(netsnmp_session *ss, oid *theoid, size_t theoid_len, unsigned char *result, size_t length)
{
    netsnmp_pdu *response;
    netsnmp_variable_list *vars;
    /* ASK the given OID to getResponse */
    if ((response = getResponse(theoid, theoid_len, ss, SNMP_MSG_GET)) != NULL) {
        /* If no error */
        if (response->errstat == SNMP_ERR_NOERROR) {
            vars = response->variables;
            /* If string */
            if (vars->type == ASN_OCTET_STR) {
                /* If string too long */
                if (vars->val_len >= length) {
                    strncpy(result, (vars->val).string, length - 1);
                    result[length - 1] = '\0';
                } else {
                    strncpy(result, (vars->val).string, vars->val_len);
                    result[vars->val_len] = '\0';
                }
            }
        }
    }
    /* Free memory */
    if (response) {
        snmp_free_pdu(response);
    }
}

/*
 * snmp_get_int : return the integer value of the given OID
 *	args : session, oid, oid_length (like getResponse)
 *
 */

int snmp_get_int(netsnmp_session *ss, oid *theoid, size_t theoid_len)
{
    netsnmp_pdu *response;
    netsnmp_variable_list *vars;
    int retvalue = 0;

    if ((response = getResponse(theoid, theoid_len, ss, SNMP_MSG_GET)) != NULL) {
        if (response->errstat == SNMP_ERR_NOERROR) {
            vars = response->variables;
            /* If INTEGER */
            if (vars->type == ASN_INTEGER) {

                retvalue = (*(vars->val).integer);
            }
        }
    }
    if (response) {
        snmp_free_pdu(response);
    }
    return retvalue;
}
