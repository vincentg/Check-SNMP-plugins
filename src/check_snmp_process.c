/*
    check_snmp_process . A Nagios plugin to monitor process Via SNMP	    

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

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "snmp-common.h"
#include "check_snmp_process.h"

/*
 * usage function : print the help
 *
 */

void
usage (void)
{
  fprintf (stderr, "USAGE: check_snmp_process ");
  fprintf (stderr, " -H HOST -C COMMUNITY -w xx -c xx -m STRING\n\n");
  fprintf (stderr,
	   " Required options :\n"
	   "  -H HOST\tHostname/IP to query\n"
	   "  -C COMMUNITY\tSNMP community name\n"
	   "  -m STRING\tSTRING define what process to check (m=monitor)\n"
	   "\t\t\t STRING = proc1,proc2,proc3\n"
	   "\t\t\t Example : -m spoolsv.exe,svchost.exe\n"
	   "  -w INTEGER\tMax number of process before WARNING (Warn if >=)\n"
	   "  -c INTEGER\tMax number of process before CRITICAL\n\n"
	   " Additionals options :\n"
	   "  -h -?\t\tPrint this help\n"
	   "  -d \t\tProvide Performance data output(doesn't support multiple process check)\n"
	   "  -s VERSION\tSNMP VERSION=[1|2c], 3 not supported right now (1 by default)\n"
	   "  -V \t\tPrint Version\n"
	   "  -r INTEGER\tMax value of ram in MB(sum of all the instances of a process)(throw a WARNING)\n"
	   "  -R \t\tIf the memory check should throw a CRITICAL instead of a WARNING\n"
	   "  -A \t\tThrow a WARNING instead of a CRITICAL when no process detected\n ");
}

/*
 * main function : -> parse command line args
 * 		   -> open SNMP session
 */
int
main (int argc, char *argv[])
{
  netsnmp_session session, *ss;
  int opt;
  int exitcode = UNKNOWN;
  char *community = NULL;
  char *hostname = NULL;
  char *bn = argv[0];
  int timeout = 0;
  int version = SNMP_VERSION_1;
  char *token;
  
  /* Print the help if not arguments provided */ 
  if(argc==1) {
	usage();
	return(UNKNOWN);
  }

  /*
   * get the common command line arguments 
   */

  while ((opt = getopt (argc, argv, "?hVdvRAt:w:c:r:m:C:H:s:")) != -1)
    {
      switch (opt)
	{
	case '?':
	case 'h':
	  /* Help */
	  usage ();
	  exit (UNKNOWN);

	case 'V':
	  /* Version */
	  print_version ();
	  exit (UNKNOWN);
	case 'd':
	  perfdata = 1;
	  break;

	case 'A':
	  /* WARN instead of CRITICAL when 0 process found */
	  warnzero = 1;
	  break;

	case 'R':
	  /* CRITICAL instead of WARN when ram exceed limit */
	  critmem = 1;
	  break;



	case 't':
	  /* Timeout */
	  if (!is_integer (optarg))
	    {
	      printf ("Timeout interval (%s)must be integer!\n", optarg);
	      exit (UNKNOWN);
	    }

	  timeout = atoi (optarg);
	  if (verbose)
	    printf ("%s: Timeout set to %d\n", bn, timeout);
	  break;

	case 'C':
	  /* SNMP community */
	  community = strdup (optarg);

	  if (verbose)
	    printf ("%s: Community set to %s\n", bn, community);

	  break;

	case 'H':
	  /* SNMP Hostname */
	  hostname = strdup (optarg);

	  if (verbose)
	    printf ("%s: Hostname set to %s\n", bn, hostname);

	  break;

	case 'v':
	  /* Verbose */
	  verbose = 1;
	  printf ("%s: Verbose mode activated\n", bn);
	  break;

	case 'm':
	  /* STRING of process */
	  /* Delimiter = , */

	  token = strtok (optarg, ",");
	  /* First process */
	  /* limit to 20 char */
	  if (strlen (token) < 20)
	    {
	      /* Malloc of the *process table */
	      process = malloc (sizeof (t_process));
	      strcpy ((process[procnbr]).procstr, token);
	      process[procnbr].nbr = 0;
	      procnbr++;
	    }
	  /* Following process */
	  while ((token = strtok (NULL, ",")) != NULL)
	    {
	      if (strlen (token) < 20)
		{
		  /* Realloc to contain one more structure */
		  process =
		    realloc (process, (procnbr + 1) * sizeof (t_process));
		  strcpy ((process[procnbr]).procstr, token);
		  process[procnbr].nbr = 0;
		  procnbr++;
		}
	    }
	  break;

	case 's':
	  /* SNMP Version */
	  if (strcmp (optarg, "2c") == 0)
	    {
	      version = SNMP_VERSION_2c;
	    }
	  else if (strcmp (optarg, "1") == 0)
	    {
	      version = SNMP_VERSION_1;
	    }
	  else
	    {
	      printf
		("Sorry, only SNMP vers. 1 and 2c are supported at this time\n");
	      exit (1);
	    }
	  break;

	case 'w':
	  /* Warning min */
	  if (strlen (optarg) <= 4)
	    {
	      warningmin = atoi (optarg);
	    }
	  else
	    {
	      printf ("Format : -w INTEGER\n");
	      exit (UNKNOWN);
	    }
	  break;

	case 'c':
	  /* Critical min */
	  if (strlen (optarg) <= 4)
	    {
	      criticalmin = atoi (optarg);
	    }
	  else
	    {
	      printf ("Format : -c INTEGER\n");
	      exit (UNKNOWN);
	    }
	  break;

	case 'r':
	  /* Ram min */
	  if (strlen (optarg) <= 4)
	    {
	      rammin = atoi (optarg);
	    }
	  else
	    {
	      printf ("Format : -r INTEGER\n");
	      exit (UNKNOWN);
	    }
	  break;

	}
    }

  if ((warningmin == -1) || (criticalmin == -1))
    {
      printf ("Warning limit or/and Critical limit not set (-w /-c)\n");
      exit (UNKNOWN);
    }

  if (!hostname || !community)
    {
      printf ("Both Community and Hostname must be set\n");
      exit (UNKNOWN);

    }

  if (warningmin > criticalmin)
    {
      printf ("Critical limit must be higher than Warning limit\n");
      exit (UNKNOWN);
    }

  if (procnbr == 0)
    {
      printf ("You must specify process to search with -m <processlist>\n");
      exit (UNKNOWN);

    }

  if ((perfdata) && procnbr > 1)
    {
      printf ("Performance data output doesn't support multiples process\nPlease check one process only : -m process\n");
      exit (UNKNOWN);      
    }	    

  snmp_sess_init (&session);

  init_snmp ("check_process");

  session.version = version;

  session.peername = hostname;
  session.community = (unsigned char *) community;
  session.community_len = strlen (community);

  if (timeout)
    session.timeout = timeout * 1000000L;



  SOCK_STARTUP;

  /*
   * open an SNMP session 
   */
  ss = snmp_open (&session);
  if (ss == NULL)
    {
      /*
       * diagnose snmp_open errors with the input netsnmp_session pointer 
       */
      snmp_sess_perror ("snmp_check_process", &session);
      SOCK_CLEANUP;
      exit (UNKNOWN);
    }

  /* go to the principal function */

  exitcode = checkProc (ss);

  snmp_close (ss);

  SOCK_CLEANUP;

  free (community);
  free (hostname);

  return exitcode;
}

/*
 * checkProc : the principal function 
 * 
 * 	args : an opened SNMP session pointer
 *
 * 	return : Nagios code
 * 
 */



int
checkProc (netsnmp_session * ss)
{

  netsnmp_pdu *response;
  netsnmp_variable_list *vars;
  oid name[MAX_OID_LEN];
  size_t name_length;
  oid root[MAX_OID_LEN];
  size_t rootlen;
  int count;
  int running;
  int exitval = 0;
  int nbr;
  int processid = 0;

  t_process *procactuel;



  memmove (root, objid_mib, sizeof (objid_mib));
  rootlen = sizeof (objid_mib) / sizeof (oid);
  /*
   * get first object to start 
   */
  memmove (name, root, rootlen * sizeof (oid));
  name_length = rootlen;

  running = 1;


  while (running)
    {
      if ((response =
	   getResponse (name, name_length, ss, SNMP_MSG_GETNEXT)) == NULL)
	{
	  printf ("SNMP Error: timeout\n");
	  return UNKNOWN;
	}
      if (response->errstat == SNMP_ERR_NOERROR)
	{
	  /*
	   * check variables 
	   */
	  for (vars = response->variables; vars; vars = vars->next_variable)
	    {
	      if ((vars->name_length < rootlen)
		  || (memcmp (root, vars->name, rootlen * sizeof (oid)) != 0))
		{
		  /*
		   * not part of this subtree 
		   */
		  running = 0;
		  continue;
		}

	      if (verbose)
		{
		  print_variable (vars->name, vars->name_length, vars);
		}
	      /* If the value is a STRING */
	      if (vars->type == ASN_OCTET_STR)
		{

		  /* Check if the string is equal to a searched one 
		   * (ie : in argument (-m) )
		   */
		  for (count = 0, procactuel = process; count < procnbr;
		       count++, procactuel++)
		    {

		      /* Case ignored */

		      if (!strncasecmp
			  ((vars->val).string, procactuel->procstr,
			   vars->val_len))
			{

			  /* Copy of the INDEX (last number of OID) */
			  processid = (int) vars->name[11];
			  nbr = procactuel->nbr;

			  /* Fill the index table */

			  /* If the table is empty : malloc for 10 int */
			  if (nbr == 0)
			    {
			      procactuel->index = malloc (10 * sizeof (int));
			    }
			  /* If 10,20,30 index are in table index, realloc
			   * 10 more int
			   */
			  else if ((nbr % 10) == 0)
			    {
			      procactuel->index =
				realloc (procactuel->index,
					 (nbr + 10) * sizeof (int));
			    }

			  /* Copy of the INDEX in the table */

			  procactuel->index[nbr] = processid;

			  /* Incrementation of the number of index */

			  (procactuel->nbr)++;

			}
		    }

		}

	      /*  exception check */

	      if ((vars->type != SNMP_ENDOFMIBVIEW) &&
		  (vars->type != SNMP_NOSUCHOBJECT) &&
		  (vars->type != SNMP_NOSUCHINSTANCE))
		{

		  /* walk in the MIB :) */

		  memmove ((char *) name, (char *) vars->name,
			   vars->name_length * sizeof (oid));
		  name_length = vars->name_length;

		}
	      else
		/*
		 * exception , so stop 
		 */
		running = 0;
	    }
	}
      else
	{
	  /*
	   * error in response, print it 
	   */
	  running = 0;
	  printf ("Error in response");
	  return UNKNOWN;
	}

      if (response)
	snmp_free_pdu (response);
    }

  /* Go to check and print */
  exitval = check_and_print (ss, procnbr);

  free (process);


  return exitval;


}

/*
 * check_and_print : parse *process , check memory / alerts , and print 
 *
 *	arguments :  *ss : session (to do memory checks)
 *		     procnbr : number of process to check
 */



int
check_and_print (netsnmp_session * ss, int procnbr)
{

  int count, count2, nbr, somme_ram;
  int exitstatus = OK;
  int *index;
  t_process *procactuel = process;

  /* The oid for RAM check */
  oid ram[] = { 1, 3, 6, 1, 2, 1, 25, 5, 1, 1, 2, 0 };

  size_t ramlen = sizeof (ram) / sizeof (oid);

/* Parse process structure */
  for (count = 0; count < procnbr; count++, procactuel++)
    {
      nbr = procactuel->nbr;
      /* If no process found */
      if (nbr == 0)
	{
	  if (warnzero)
	    {
	  	if(perfdata) {
	          printf ("WARNING : 0 %s |proc_nbr=0;%d;%d\n", procactuel->procstr, warningmin,criticalmin);
	          return WARNING;
			
		}
		else {
	          printf ("WARNING : 0 %s --- ", procactuel->procstr);
	          exitstatus = WARNING;
		}
	    }
	  else
	    {
	     if(perfdata) {
	          printf ("CRITICAL : 0 %s |proc_nbr=0;%d;%d\n", procactuel->procstr, warningmin,criticalmin);
	          return CRITICAL;
			
		}
	     else {

	        printf ("CRITICAL : 0 %s --- ", procactuel->procstr);
	        exitstatus = CRITICAL;
	     }
	    }

	  continue;
	}


      /* RAM CHECK */

      index = procactuel->index;
      somme_ram = 0;

      for (count2 = 0; count2 < nbr; count2++)
	{
	  /* Sum of memory */
	  ram[11] = index[count2];
	  somme_ram += snmp_get_int (ss, ram, ramlen);
	}
      /* We don't need the index table anymore */
      free (procactuel->index);

      procactuel->ram = somme_ram;


      /* Check if the number of proc excess limit */

      if (nbr >= warningmin)
	{
	  if (nbr >= criticalmin)
	    {
	      printf ("CRITICAL : ");
	      exitstatus = CRITICAL;
	    }
	  else
	    {
	      exitstatus = WARNING;
	      printf ("WARNING : ");
	    }
	}
      if ((somme_ram / 1024) > rammin)
	{
	  if (critmem == 0)
	    {
	      if (exitstatus == OK)
		{
		  exitstatus = WARNING;
		  printf ("WARNING : ");
		}
	    }
	  else if (exitstatus < 2)
	    {
	      printf ("CRITICAL : ");
	      exitstatus = CRITICAL;
	    }
	}
     if(perfdata) {
        printf ("%d %s Running (Ram:%.2f MB) | proc_nbr=%d;%d;%d,proc_ram=%dKB", nbr, procactuel->procstr,
	      somme_ram / (double) 1024,nbr,warningmin,criticalmin,somme_ram);
	}
     else {
        printf ("%d %s Running (Ram:%.2f MB) --", nbr, procactuel->procstr,
	      somme_ram / (double) 1024);
     }
    }

  printf ("\n");
  return exitstatus;
}
