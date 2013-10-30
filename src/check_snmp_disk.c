/*
    check_snmp_disk . A Nagios plugin to monitor storage via SNMP	    

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
#include "check_snmp_disk.h"


void
usage (void)
{
  fprintf (stderr, "USAGE:check_snmp_disk ");
  fprintf (stderr, " -H HOST -C COMMUNITY -w xx -c xx -m [r,v,d,n]\n\n");
  fprintf (stderr,
	   " Required options :\n"
	   "  -H HOST\tHostname/IP to query\n"
	   "  -C COMMUNITY\tSNMP community name\n"
	   "  -m STRING\tWhat must be monitored (m = monitor)\n"
	   "\t\t\t r = Physical Memory(RAM)\n"
	   "\t\t\t v = Virtual Memory\n"
	   "\t\t\t d = Fixed Disks\n"
	   "\t\t\t n = Network Disks\n"
	   "\t\t\t Example : '-m rvdn'  monitor all\n"
	   "  -w xx\t\tWarning limit in percent\n"
	   "  -c xx\t\tCritical limit in percent\n"
	   " Additionnals options :\n"
	   "  -h -?\t\tPrint this help\n"
	   "  -V \t\tPrint Version\n"
	   "  -d \t\tProvide Performance data output\n"
	   "  -s VERSION\tSNMP VERSION=[1|2c], 3 not supported (1 by default)\n"
	   "  -f STRING\tAdditional filter\n"
	   "\t\t\t Example : -f C: , -f /tmp \n");
}

/* main function :
 *  -> parse command line arguments
 *  -> open the SNMP session
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
  
  /* Print the help if not arguments provided */ 
  if(argc==1) {
	usage();
	return(UNKNOWN);
  }

  /*
   * get the common command line arguments with getopt
   */

  while ((opt = getopt (argc, argv, "?hVdvt:w:c:m:C:H:s:f:")) != -1)
    {
      switch (opt)
	{
	case '?':
	case 'h':
	  /* Print the help */
	  usage ();
	  exit (UNKNOWN);

	case 'V':
	  /* Print the version */
	  print_version ();
	  exit (UNKNOWN);
	
	case 'd':
	  perfdata = 1;
	  break;

	case 't':
	  /* Change timeout */
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
	  /* Set SNMP community */
	  community = strdup (optarg);

	  if (verbose)
	    printf ("%s: Community set to %s\n", bn, community);

	  break;

	case 'H':
	  /* Set SNMP Hostname */
	  hostname = strdup (optarg);

	  if (verbose)
	    printf ("%s: Hostname set to %s\n", bn, hostname);

	  break;

	case 'v':
	  /* Set verbose */
	  verbose = 1;
	  printf ("%s: Verbose mode activated\n", bn);
	  break;

	case 'm':
	  /* Parse the string which tell the program what to check */
	  while (*optarg)
	    {
	      switch (*optarg++)
		{
		case 'r':
		  check_ram = 1;
		  break;

		case 'd':
		  check_disk = 1;
		  break;

		case 'n':
		  check_net = 1;
		  break;

		case 'v':
		  check_vmem = 1;
		  break;

		default:
		  printf ("Unknown flag passed to -m: %c\n", optarg[-1]);
		  exit (UNKNOWN);
		}
	    }
	  break;
	case 's':
	  /* Set SNMP version */
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
	  /* Set warn limit */
	  if (strlen (optarg) <= 3)
	    {
	      warningmin = atoi (optarg);
	    }
	  else
	    {
	      printf ("Format : -w xx\n xx in percent\n");
	      exit (UNKNOWN);
	    }
	  break;

	case 'c':
	  if (strlen (optarg) <= 3)
	    {
	      criticalmin = atoi (optarg);
	    }
	  else
	    {
	      printf ("Format : -c xx\n xx in percent\n");
	      exit (UNKNOWN);
	    }
	  break;

	case 'f':
	  if ((filteron = strlen (optarg)) < 20)
	    {
	      strcpy (filter, optarg);
	    }
	  else
	    {
	      printf ("Filter string can't exceed 20 char\n");
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


  if (criticalmin <= warningmin)
    {
      printf ("Warning limit is greater than Critical limit\n");
      exit (UNKNOWN);
    }

  if (!hostname || !community)
    {
      printf ("Both Community and Hostname must be set\n");
      exit (UNKNOWN);

    }


  snmp_sess_init (&session);

  init_snmp ("check_disk");

  session.version = version;

  session.peername = hostname;
  session.community = (unsigned char *) community;
  session.community_len = strlen (community);
  /* Set timeout */
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
       * diagnose snmp_open errors 
       */
      snmp_sess_perror ("check_snmp_disk", &session);
      SOCK_CLEANUP;
      exit (UNKNOWN);
    }
  /* launch the principal function with the session pointer */

  exitcode = checkDisk (ss);

  snmp_close (ss);


  SOCK_CLEANUP;

  free (hostname);
  free (community);

  return exitcode;
}


/*
 * checkDisk : the principal function 
 *
 * return : nagios code
 */


int
checkDisk (netsnmp_session * ss)
{

  netsnmp_pdu *response;
  netsnmp_variable_list *vars;
  t_storage *storage = NULL;
  oid name[MAX_OID_LEN];
  size_t name_length;
  oid root[MAX_OID_LEN];
  size_t rootlen;
  int count;
  int running;
  int exitval = 0;

  int fixed_id[100], net_id[100], mem_id = 0, virtual_id = 0;

  int index_fixed = 0;
  int index_net = 0;
  int index_storage = 0;

  size_t typelen;

  char *tmp;

  unsigned char desc_uchar[50];
  int allocunit, totalsize, used;



  typelen = sizeof (FIXED_DISK);

  memmove (root, objid_mib, sizeof (objid_mib));
  rootlen = sizeof (objid_mib) / sizeof (oid);
  /*
   * first object to start walk 
   */
  memmove (name, root, rootlen * sizeof (oid));
  name_length = rootlen;

  running = 1;


  while (running)
    {

      if ((response =
	   getResponse (name, name_length, ss, SNMP_MSG_GETNEXT)) == NULL)
	{
	  printf ("Erreur SNMP : timeout\n");
	  return UNKNOWN;

	}
      /* If no response error */
      if (response->errstat == SNMP_ERR_NOERROR)
	{

	  for (vars = response->variables; vars; vars = vars->next_variable)
	    {
	      if ((vars->name_length < rootlen)
		  || (memcmp (root, vars->name, rootlen * sizeof (oid)) != 0))
		{
		  /*
		   * not part of subtree 
		   */
		  running = 0;
		  continue;
		}
	      if (verbose)
		{
		  print_variable (vars->name, vars->name_length, vars);
		}

	      if ((int) vars->name[10] == 2)
		{
		  /* If var is an OID */
		  if (vars->type == ASN_OBJECT_ID)
		    {

		      if ((check_disk == 1)
			  &&
			  (!memcmp ((vars->val).objid, FIXED_DISK, typelen)))
			{
			  if (index_fixed < 100)
			    {
			      /* We put in the table fixed_id the last number of the OID
			       * which is the index of the fixed disk 
			       * (and index_fixed is incremented to be equal with the 
			       * number of disk parsed)
			       */
			      fixed_id[index_fixed++] = (int) vars->name[11];
			    }
			  else
			    {
			      printf
				("snmp_check_disk doesn't support more than 100 fixed disks\n");

			    }
			}

		      else if ((check_ram == 1)
			       && (!memcmp ((vars->val).objid, RAM, typelen)))
			{
			  /* Index of physical memory = the last number of the OID */
			  mem_id = (int) vars->name[11];
			}
		      else
			if ((check_vmem == 1)
			    &&
			    (!memcmp
			     ((vars->val).objid, VIRTUAL_MEM, typelen)))
			{
			  virtual_id = (int) vars->name[11];
			}
		      else
			if ((check_net == 1) && (!memcmp
						 ((vars->val).objid,
						  NETWORK_DISK, typelen)))
			{
			  if (index_net < 100)
			    {
			      net_id[index_net++] = (int) vars->name[11];
			    }
			  else
			    {
			      printf
				("check_snmp_disk doesn't support more than 100 network disks\n");
			    }
			}
		    }

		}
	      /*  exception check */

	      if ((vars->type != SNMP_ENDOFMIBVIEW) &&
		  (vars->type != SNMP_NOSUCHOBJECT) &&
		  (vars->type != SNMP_NOSUCHINSTANCE))
		{

		  /* And we walk in the MIB :) */

		  memmove ((char *) name, (char *) vars->name,
			   vars->name_length * sizeof (oid));
		  name_length = vars->name_length;

		}
	      else
		/*
		 *  exception , so stop 
		 */
		running = 0;
	    }
	}
      else
	{
	  /*
	   * error in response, print  
	   */
	  running = 0;
	  printf ("Error in response");
	  return UNKNOWN;
	}

      if (response)
	snmp_free_pdu (response);
    }



  /* MALLOC of initial storage to contain 6 structure
   */

  storage = malloc (6 * sizeof (t_storage));


  /*
   * Physical memory
   */

  if (mem_id != 0)
    {
      name[10] = 3;
      name[11] = mem_id;

      memset (desc_uchar, '\0', 50);

      snmp_get_uchar (ss, name, 12, desc_uchar, 50);

      name[10] = 4;
      allocunit = snmp_get_int (ss, name, 12);

      name[10] = 5;
      totalsize = snmp_get_int (ss, name, 12);

      name[10] = 6;
      used = snmp_get_int (ss, name, 12);

      storage =
	newStorageEntry (index_storage, storage, desc_uchar, 50, allocunit,
			 totalsize, used, mem_id, TYPE_MEM);
      index_storage++;
    }

  /*
   * Virtual Memory
   */


  if (virtual_id != 0)
    {
      name[10] = 3;
      name[11] = virtual_id;

      snmp_get_uchar (ss, name, 12, desc_uchar, 50);

      name[10] = 4;
      allocunit = snmp_get_int (ss, name, 12);

      name[10] = 5;
      totalsize = snmp_get_int (ss, name, 12);

      name[10] = 6;
      used = snmp_get_int (ss, name, 12);

      storage =
	newStorageEntry (index_storage, storage, desc_uchar, 50, allocunit,
			 totalsize, used, mem_id, TYPE_MEM);
      index_storage++;
    }


  /*
   * number of hard disks : index_fixed
   * id table : fixed_id
   * */
  if (index_fixed != 0)
    {

      for (count = 0; count < index_fixed; count++)
	{


	  name[10] = 3;
	  name[11] = fixed_id[count];
	  snmp_get_uchar (ss, name, 12, desc_uchar, 50);

	  if ((tmp = strchr (desc_uchar, ' ')) != NULL)
	    {
	      *tmp = '\0';
	    }

	  name[10] = 4;
	  allocunit = snmp_get_int (ss, name, 12);
	  name[10] = 5;
	  totalsize = snmp_get_int (ss, name, 12);

	  name[10] = 6;
	  used = snmp_get_int (ss, name, 12);

	  storage =
	    newStorageEntry (index_storage, storage, desc_uchar, 50,
			     allocunit, totalsize, used, mem_id, TYPE_MEM);
	  index_storage++;
	}

    }
  /*
   * number of net disks : index_net
   * id table : net_id
   * */

  if (index_net != 0)
    {

      for (count = 0; count < index_net; count++)
	{


	  name[10] = 3;
	  memset (desc_uchar, '\0', 50);
	  name[11] = net_id[count];
	  snmp_get_uchar (ss, name, 12, desc_uchar, 50);

	  if ((tmp = strchr (desc_uchar, ' ')) != NULL)
	    {
	      *tmp = '\0';
	    }

	  name[10] = 4;
	  allocunit = snmp_get_int (ss, name, 12);
	  name[10] = 5;
	  totalsize = snmp_get_int (ss, name, 12);

	  name[10] = 6;
	  used = snmp_get_int (ss, name, 12);

	  storage =
	    newStorageEntry (index_storage, storage, desc_uchar, 50,
			     allocunit, totalsize, used, mem_id, TYPE_MEM);
	  index_storage++;
	}

    }

  exitval = check_and_print (storage, index_storage);

  free (storage);

  return exitval;


}

/*
* check_and_print : parse storage structure, check warn / critical
* 		     and print
*
*	arguments :  *storage : structure t_storage
*		     storage_length :  count of allocated structs
*/

int
check_and_print (t_storage * storage, int storage_length)
{

  int count;
  double totalMB, usedMB;
  int percent;
  int exitstatus = UNKNOWN;
  t_storage *current_storage = storage;
  
  /*
   * For each structure stored in *storage 
   *
   */

  if (check_disk && !check_ram && !check_vmem)
    printf ("DISKS ");

  for (count = 0; count < storage_length; count++, current_storage++)
    {
      if (filteron != 0)
	{
	  if (strncmp (current_storage->descr, filter, filteron + 1) != 0)
	    {
	      continue;
	    }

	}

      /* Calc of the Total / Used Space , and value in percent 
       * Double  because values can be bigger than INTEGER maximum
       */
      totalMB = current_storage->allocunit * (double) current_storage->totalsize / 1048576;
      usedMB = current_storage->allocunit * (double) current_storage->used / 1048576;
      percent = usedMB / totalMB * 100;
      /* If totalsize = 0, pass (case of some /dev) */
      if (totalMB == 0)
	{
	  continue;
	}


      /* Checks for alert */
      if (percent <= criticalmin)
	{
	  if (percent <= warningmin)
	    {
	      if (exitstatus != CRITICAL && exitstatus != WARNING ) {
	        exitstatus = OK;
	      }
	      printf ("OK= ");
	    }
	  else
	    {
	      if (exitstatus != CRITICAL) {
                exitstatus = WARNING;
	      }
	      printf ("WARNING= ");
	    }
	} else {
	  exitstatus = CRITICAL;
	  printf ("CRITICAL= ");
	}

/* Print entry */
      printf ("%s : (%.0f M/%.0f M) %d%% --- ", current_storage->descr,
	      usedMB, totalMB, percent);
    }
/* Display perfdata */
  if (perfdata) {
    printf ("| ");	  
    for (current_storage=storage,count = 1; count <= storage_length; count++, current_storage++) {
	printf("'disk%d_label'=%s,'disk%d_used\'=%.0fKB,\'disk%d_total\'=%.0fKB,\'disk%d_percent\'=%.2f%%;%d;%d"
		,count
		,current_storage->descr
		,count
		,current_storage->allocunit * (double) current_storage->used /1024
		,count
		,current_storage->allocunit * (double) current_storage->totalsize /1024
		,count
		,((double)current_storage->used / current_storage->totalsize) * 100
		,warningmin
		,criticalmin
		);
	if(count != storage_length)
	   printf(",");	
    }
	  
  }
  
  if ( exitstatus == UNKNOWN ) {
    exitstatus = CRITICAL;
    printf ("CRITICAL - no entries found");
  }

  
  printf ("\n");

  return exitstatus;

}

/* newStorageEntry : create a new structure in *storage and allocate memory 
*
* args 	   : -> index_storage : number of the structure 
* 		     ->*storage      : container
* 	    	     -> and everything useful to fill t_storage struct
*
* return 	   : *storage (in case of the realloc change the memory zone) 
* 	
*/

t_storage *
newStorageEntry (int index_storage, t_storage * storage, unsigned char * descr,
		 size_t descr_length, int allocunit, int totalsize, int used,
		 int index_oid, int type)
{

  /* If more than 6 entry (initial malloc) and every 3 values 
   * Realloc of 3 more struct
   */

  if ((index_storage >= 6) && (index_storage % 3 == 0))
    {
      storage = realloc (storage, (index_storage + 3) * sizeof (t_storage));
    }

  /* Fill the struct */
  storage[index_storage].index = index_oid;
  /* Copy string descr */
  memcpy (storage[index_storage].descr, descr, descr_length);
  storage[index_storage].type = type;
  storage[index_storage].allocunit = allocunit;
  storage[index_storage].totalsize = totalsize;
  storage[index_storage].used = used;

  return storage;
}
