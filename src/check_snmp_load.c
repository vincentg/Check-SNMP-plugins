/*
 *  check_snmp_load . A Nagios plugin to monitor load via SNMP
 *
 *  Copyright (C) 2006  Vincent GERARD v.ge@wanadoo.fr
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING. If not, write to the
 *  Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "snmp-common.h"
#include "check_snmp_load.h"

/*
 * usage function : print the help
 *
 */

void usage(void)
{
    fprintf(stderr, "USAGE: check_snmp_load ");
    fprintf(stderr, " -H HOST -C COMMUNITY -w xx -c xx -m STRING\n\n");
    fprintf(stderr,
            "  -H HOST\tHostname/IP to query\n"
            "  SNMP v1/2c:\n"
            "     -C COMMUNITY\tSNMP community name\n"
            "  SNMP v3:\n"
            "     -u Username\n"
            "     -p Password\n"
            "     -k Authentication Protocol [MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512]\n"
            "     -x Protocol   Privacy protocol [DES|AES]\n"
            "     -X Passphrase Privacy protocol pass phrase\n"
            "  -s VERSION\tVERSION=[1|2c|3]\n"
            "  -V \t\tPrint Version\n"
            "  -d \t\tProvide Performance data output\n"
            "  -m [W,L]\t\tDefine if windows or linux\n"
            "\t\t\t\t W = Monitor Windows machines (result in %%)\n"
            "\t\t\t\t L = Monitor Linux Load Average\n"
            "\t\t\t\t Example : -m W for windows load\n"
            "  -w INTEGER\t\tWarning limit in percent for Windows\n"
            "  -w INT,INT,INT\t\tWarning limits in load average for Linux\n"
            "  -c INTEGER\t\tCritical limit in percent for Windows\n"
            "  -c INT,INT,INT\t\tCritical limits in load average for Linux\n");
}

/*
 * main function : -> parse command line args
 * 		   -> open SNMP session
 */
int main(int argc, char *argv[])
{
    netsnmp_session session, *ss = NULL;
    int opt;
    int exitcode = UNKNOWN;
    char *community = NULL;
    char *hostname = NULL;
    char *bn = argv[0];
    int timeout = 0;
    int version = SNMP_VERSION_1;
    char *token;
    snmpv3_args_t v3_args;

    init_v3_args(&v3_args);

    /* Print the help if not arguments provided */
    if (argc == 1) {
        usage();
        return (UNKNOWN);
    }
    /*
     * get the common command line arguments
     */

    while ((opt = getopt(argc, argv, "?hVdvt:w:c:m:C:H:s:u:p:k:x:X:")) != -1) {
        switch (opt) {
        case '?':
        case 'h':
            /* print help */
            usage();
            exit(UNKNOWN);

        case 'V':
            print_version();
            exit(UNKNOWN);

        case 'd':
            perfdata = 1;
            break;

        case 't':
            /* Timeout */
            if (!is_integer(optarg)) {
                printf("Timeout interval (%s)must be integer!\n", optarg);
                exit(UNKNOWN);
            }

            timeout = atoi(optarg);
            if (verbose)
                printf("%s: Timeout set to %d\n", bn, timeout);
            break;

        case 'C':
            /* SNMP Community */
            community = strdup(optarg);

            if (verbose)
                printf("%s: Community set to %s\n", bn, community);

            break;

        case 'H':
            /* SNMP Hostname */
            hostname = strdup(optarg);

            if (verbose)
                printf("%s: Hostname set to %s\n", bn, hostname);

            break;

        case 'v':
            /* Verbose mode */
            verbose = 1;
            printf("%s: Verbose mode\n", bn);
            break;

        case 'u':
        case 'p':
        case 'k':
        case 'x':
        case 'X':
            snmpv3_parseargs(verbose, opt, optarg, &v3_args);
            break;

        case 'm':
            /* WINDOWS / LINUX Check style */
            if (strcmp(optarg, "W") == 0) {
                style = WINDOWS;
            } else if (strcmp(optarg, "L") == 0) {
                style = LINUX;
            } else {
                printf("Format : -m [W|L]  : -m W for windows\t -m L for Linux\n");
            }

            break;

        case 's':
            /* SNMP Version */
            if (strcmp(optarg, "2c") == 0) {
                version = SNMP_VERSION_2c;
            } else if (strcmp(optarg, "1") == 0) {
                version = SNMP_VERSION_1;
            } else if (strcmp(optarg, "3") == 0) {
                version = SNMP_VERSION_3;
            } else {
                printf("Sorry, only SNMP vers. 1, 2c, 3 are supported at this time\n");
                exit(1);
            }
            break;

        case 'w':
            /* ARGS for warning min */
            if (strlen(optarg) <= 3) {  /* Percent limit */
                warningmin[0] = atoi(optarg);
                /* In order to check the type of limit entered */
                warningmin[1] = 9999;
                break;
            } else if (strlen(optarg) <= 8) {   /* Load averages limits */
                token = strtok(optarg, ",");
                warningmin[0] = atoi(token);
                if ((token = strtok(NULL, ",")) != NULL) {
                    warningmin[1] = atoi(token);
                }

                if ((token = strtok(NULL, ",")) != NULL) {
                    warningmin[2] = atoi(token);
                    break;
                }
            }

            printf("Format : -w xx or -w xx,xx,xx\n");
            exit(UNKNOWN);

            break;

        case 'c':
            /* CRITICAL min */
            if (strlen(optarg) <= 3) {  /* Percent limit */
                criticalmin[0] = atoi(optarg);
                /* In order to check the type of limit entered */
                criticalmin[1] = 9999;
                break;
            } else if (strlen(optarg) <= 8) {   /* Load averages limits */
                /* Separate with delimiter , */
                token = strtok(optarg, ",");
                criticalmin[0] = atoi(token);
                if ((token = strtok(NULL, ",")) != NULL) {
                    criticalmin[1] = atoi(token);
                }

                if ((token = strtok(NULL, ",")) != NULL) {
                    criticalmin[2] = atoi(token);
                    break;
                }
            }

            printf("Format : -c xx or -c xx,xx,xx\n");
            exit(UNKNOWN);

            break;
        }
    }
    /* If no style set */
    if (style == 3) {
        printf("You must choose between linux / windows monitoring ( -m L or -m W)\n");
        exit(UNKNOWN);
    } else if ((style == WINDOWS) && ((warningmin[1] != 9999) || (criticalmin[1] != 9999))) {
        printf("If you choose -m W, you must set -w xx and -c xx (xx = limit in percent\n");
        exit(UNKNOWN);
    } else if ((style == LINUX) && ((warningmin[1] == 9999) || (criticalmin[1] == 9999))) {
        printf
            ("If you choose -m L, you must set -w xx,xx,xx and -c xx,xx,xx\n (xx,xx,xx = limits for load average 1,5,15 minutes\n");
        exit(UNKNOWN);
    }

    if ((warningmin[0] == -1) || (criticalmin[0] == -1)) {
        printf("Must set the warning and critical values (-w and -c)\n");
        exit(UNKNOWN);
    }

    if (warningmin[0] > criticalmin[0]) {
        printf("warning minimum must be lower than critical minimum\n");
        exit(UNKNOWN);
    }

    if (version != SNMP_VERSION_3 && (!hostname || !community)) {
        printf("Both Community and Hostname must be set for SNMP v2\n");
        exit(UNKNOWN);
    }

    snmp_sess_init(&session);

    init_snmp("check_load");

    session.version = version;

    session.peername = hostname;

    if (version != SNMP_VERSION_3) {
        session.community = (unsigned char *)community;
        session.community_len = strlen(community);
    } else {
        snmpv3_set_session(&session, &v3_args);
    }

    if (timeout)
        session.timeout = timeout * 1000000L;

    SOCK_STARTUP;

    /*
     * open an SNMP session
     */
    ss = snmp_open(&session);
    if (ss == NULL) {
        /*
         * diagnose snmp_open errors with the input netsnmp_session pointer
         */
        snmp_sess_perror("snmp_check_process", &session);
        SOCK_CLEANUP;
        exit(UNKNOWN);
    }

    exitcode = checkLoad(ss);

    snmp_close(ss);

    SOCK_CLEANUP;

    free(community);
    free(hostname);

    free_v3_args(&v3_args);

    return exitcode;
}

int checkLoad(netsnmp_session *ss)
{

    netsnmp_pdu *response;
    netsnmp_variable_list *vars;
    oid name[MAX_OID_LEN];
    size_t name_length;
    oid root[MAX_OID_LEN];
    size_t rootlen;
    int running;
    int exitval = 0;
    int cpunbr = 0;

    if (style == WINDOWS) {
        memmove(root, win_mib, sizeof(win_mib));
        rootlen = sizeof(win_mib) / sizeof(oid);
        /* Style == LINUX */
    } else {
        memmove(root, linux_mib, sizeof(linux_mib));
        rootlen = sizeof(linux_mib) / sizeof(oid);
    }
    /*
     * get first object to start walk
     */
    memmove(name, root, rootlen * sizeof(oid));
    name_length = rootlen;

    running = 1;

    while (running) {

        if ((response = getResponse(name, name_length, ss, SNMP_MSG_GETNEXT)) == NULL) {
            printf("SNMP Error: timeout\n");
            return UNKNOWN;
        }

        if (response->errstat == SNMP_ERR_NOERROR) {

            /*
             * check variables
             */
            for (vars = response->variables; vars; vars = vars->next_variable) {
                if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0)) {
                    /*
                     * not part of this subtree
                     */
                    running = 0;
                    continue;
                }

                if (verbose) {
                    print_variable(vars->name, vars->name_length, vars);
                }

                if (style == WINDOWS) {
                    if (vars->type == ASN_INTEGER) {
                        /* Allocation de 10 en 10 */
                        if (cpunbr == 0) {
                            load = malloc(10 * sizeof(int));
                        } else if ((cpunbr % 10) == 0) {
                            load = realloc(load, (cpunbr + 10) * sizeof(int));
                        }

                        load[cpunbr++] = (*(vars->val).integer);
                    }
                }

                if (style == LINUX) {
                    if (vars->type == ASN_OCTET_STR) {
                        char *temp = (char *)malloc(1 + vars->val_len);
                        memcpy(temp, vars->val.string, vars->val_len);
                        temp[vars->val_len] = '\0';
                        if (strlen(temp) <= 5) {
                            linload[cpunbr++] = strtod(temp, (char **)NULL);
                        }
                        free(temp);
                    }
                }

                /* Test si ce n'est pas une exception */

                if ((vars->type != SNMP_ENDOFMIBVIEW) &&
                    (vars->type != SNMP_NOSUCHOBJECT) && (vars->type != SNMP_NOSUCHINSTANCE)) {

                    /* Et l'on avance dans la MIB :) */

                    memmove((char *)name, (char *)vars->name, vars->name_length * sizeof(oid));
                    name_length = vars->name_length;
                }

                else
                    /*
                     * une exception , donc stop
                     */
                    running = 0;
            }
        }

        else {
            /*
             * error in response, print it
             */
            running = 0;
            printf("Error in response");
            return UNKNOWN;
        }

        if (response)
            snmp_free_pdu(response);
    }

    exitval = check_and_print(cpunbr);

    return exitval;
}

/*
 * check_and_print : utilise la structure process, cherche l'occupation memoire
 * 		     et affiche
 *
 *	arguments :  *storage : structure t_storage
 *		     storage_length : taille de la structure (nb d'elements)
 */

int check_and_print(int cpunbr)
{

    int count;
    double average = 0;
    int exitstatus = OK;
    int w = 0;

    if (style == WINDOWS) {

        for (count = 0; count < cpunbr; count++) {
            /* Average of cpu use */
            average += load[count];
            if (verbose) {
                printf("Cpu no %d load=%d%% \n", count, load[count]);
            }
        }
        average /= cpunbr;

        free(load);

        if (average > warningmin[0]) {
            if (average > criticalmin[0]) {
                printf("CRITICAL : ");
                exitstatus = CRITICAL;
            } else {
                exitstatus = WARNING;
                printf("WARNING : ");
            }
        } else {
            printf("OK : ");
        }
        if (perfdata) {
            printf("%d CPU :  %.2f%% | cpu_used_percent=%.2f%%;%d;%d", cpunbr, average, average, warningmin[0],
                   criticalmin[0]);
        } else {
            printf("%d CPU :  %.2f%%", cpunbr, average);
        }
    }

    /* Style == LINUX */
    else {

        for (count = 0; count < 3; count++) {
            if (linload[count] > warningmin[count]) {
                if (linload[count] > criticalmin[count]) {
                    exitstatus = CRITICAL;
                    printf("CRITICAL ");
                    break;
                } else {
                    w = 1;
                }
            }
        }
        if ((exitstatus == OK) && (w == 1)) {
            exitstatus = WARNING;
            printf("WARNING ");
        }

        if (perfdata) {
            printf("LOAD: %.2f, %.2f, %.2f | load_1_min=%.2f;%d;%d,load_5_min=%.2f;%d;%d,load_15_min=%.2f;%d;%d",
                   linload[0], linload[1], linload[2], linload[0], warningmin[0], criticalmin[0], linload[1],
                   warningmin[1], criticalmin[1], linload[2], warningmin[2], criticalmin[2]);
        } else {

            printf("LOAD: %.2f, %.2f, %.2f", linload[0], linload[1], linload[2]);
        }
    }

    printf("\n");

    return exitstatus;
}
