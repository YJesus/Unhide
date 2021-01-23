/*
          http://sourceforge.net/projects/unhide/
*/

/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Needed for unistd.h to declare getpgid() and others
#define _XOPEN_SOURCE 500

// Needed for sched.h to declare sched_getaffinity()
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wait.h>
#include <sys/resource.h>
#include <errno.h>
#include <dirent.h>
#include <sched.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>

#include "unhide-output.h"
#include "unhide-linux.h"


// header
const char header[] =
   "Unhide 20130526\n"
   "Copyright © 2013 Yago Jesus & Patrick Gouin\n"
   "License GPLv3+ : GNU GPL version 3 or later\n"
   "http://www.unhide-forensics.info\n\n"
   "NOTE : This version of unhide is for systems using Linux >= 2.6 \n\n";

// defauly sysctl kernel.pid_max
int maxpid = 32768;

// Threads id for sync
int tid ;

// our own PID
pid_t mypid ;

// options
int verbose = 0;
int morecheck = FALSE;
int RTsys = FALSE;
int brutesimplecheck = TRUE;

// Found hidden proccess flag
int found_HP = 0;

// For logging to file
int logtofile;
FILE *unlog;

// Temporary string for output
char used_options[1000];

// Temporary string for output
char scratch[1000];

// table of test to perform
struct tab_test_t tab_test[MAX_TESTNUM];


/*
 *  Get the maximum number of process on this system. 
 */
void get_max_pid(int* newmaxpid) 
{
   char path[]= "/proc/sys/kernel/pid_max";
   pid_t tmppid = 0;
   FILE* fd= fopen(path,"r");
   if(!fd) 
   {
      warnln(1, unlog, "Cannot read current maximum PID. Using default value %d", * newmaxpid) ;
      return;
   }


   if((fscanf(fd, "%d", &tmppid) != 1) || tmppid < 1) 
   {
      msgln(unlog, 0, "Warning : Cannot get current maximum PID, error parsing %s format. Using default value %d", path, * newmaxpid) ;
      return;
   } 
   else 
   {
      *newmaxpid = tmppid;
   }
   fclose(fd) ;
}

/*
 *  Verify if ps see a given pid. 
 */
int checkps(int tmppid, int checks) 
{

   int ok = 0;
   char pids[30];

   char compare[100];
   char command[60];


   FILE *fich_tmp ;

// printf("in --> checkps\n");   // DEBUG

// The compare string is the same for all test
   sprintf(compare,"%i\n",tmppid);

   if (PS_PROC == (checks & PS_PROC)) 
   {
      sprintf(command,COMMAND,tmppid) ;

      fich_tmp=popen (command, "r") ;
      if (fich_tmp == NULL) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", command, tmppid) ;
         return(0);
      }

      {
         char* tmp_pids = pids;

         if (NULL != fgets(pids, 30, fich_tmp)) 
         {
            pids[29] = 0;

//          printf("pids = %s\n", pids);   // DEBUG
            while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
            {
               tmp_pids++;
            }

            if (strncmp(tmp_pids, compare, 30) == 0) {ok = 1;}
         }
      }

      if (NULL != fich_tmp)
         pclose(fich_tmp);

      if (1 == ok) return(ok) ;   // pid is found, no need to go further
   }

   if (PS_THREAD == (checks & PS_THREAD)) 
   {
      FILE *fich_thread ;

      fich_thread=popen (THREADS, "r") ;
      if (NULL == fich_thread) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", THREADS, tmppid) ;
         return(0);
      }

      while ((NULL != fgets(pids, 30, fich_thread)) && ok == 0) 
      {
         char* tmp_pids = pids;

         pids[29] = 0;

         while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
         {
            tmp_pids++;
         }

         if (strncmp(tmp_pids, compare, 30) == 0) {ok = 1;}
      }
      if (fich_thread != NULL)
         pclose(fich_thread);

      if (1 == ok) return(ok) ;   // thread is found, no need to go further
   }

   if (PS_MORE == (checks & PS_MORE)) 
   {

      FILE *fich_session ;

      sprintf(command,SESSION,tmppid) ;

      fich_session=popen (command, "r") ;
      if (fich_session == NULL) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", command, tmppid) ;
         return(0);
      }


      while ((NULL != fgets(pids, 30, fich_session)) && ok == 0) 
      {
         char* tmp_pids = pids;

         pids[29] = 0;

         while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
         {
            tmp_pids++;
         }

         if (strncmp(tmp_pids, compare, 30) == 0) 
         {
            ok = 1;
         }
      }

      pclose(fich_session);

      if (1 == ok) 
         return(ok) ;   // session is found, no need to go further

      FILE *fich_pgid ;

      fich_pgid=popen (PGID, "r") ;
      if (NULL == fich_pgid) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", PGID, tmppid) ;
         return(0);
      }

      while ((NULL != fgets(pids, 30, fich_pgid)) && ok == 0) 
      {
         char* tmp_pids = pids;

         pids[29] = 0;

         while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
         {
            tmp_pids++;
         }

         if (strncmp(tmp_pids, compare, 30) == 0) 
         {
            ok = 1;
         }
      }

      pclose(fich_pgid);

   }
   return ok;
}

/*
 *  Display hidden process and possibly some information on it. 
 */
void printbadpid (int tmppid) 
{

   int statuscmd ;
   char cmd[100] ;
   struct stat buffer;
   FILE *cmdfile ;
   char cmdcont[1000], fmtstart[128];
   int cmdok = 0, cmdok2 = 0;

   found_HP = 1;
   sprintf(fmtstart,"Found HIDDEN PID: %i", tmppid) ;
   msgln(unlog, 0, "%s", fmtstart) ;

   sprintf(cmd,"/proc/%i/cmdline",tmppid);

   statuscmd = stat(cmd, &buffer);
// statuscmd = 0 ;  // DEBUG

   if (statuscmd == 0) 
   {
      cmdfile=fopen (cmd, "r") ;
      if (cmdfile != NULL) 
      {
         while ((NULL != fgets (cmdcont, 1000, cmdfile)) && 0 == cmdok)
         {
            cmdok++ ;
            msgln(unlog, 0, "\tCmdline: \"%s\"", cmdcont) ;
         }
         fclose(cmdfile);
      }
   }
   if (0 == cmdok) 
   {
      msgln(unlog, 0, "\tCmdline: \"<none>\"") ;
   }
   
   {  // try to readlink the exe
      ssize_t length ;

      sprintf(cmd,"/proc/%i/exe",tmppid);
      statuscmd = lstat(cmd, &buffer);
//    printf("%s",cmd) ; //DEBUG
//      printf("\tstatuscmd : %d\n",statuscmd) ; //DEBUG
      if (statuscmd == 0) 
      {
         length = readlink(cmd, cmdcont, 1000) ;
//         printf("\tLength : %0d\n",(int)length) ; //DEBUG
         if (-1 != length) 
         {
            cmdcont[length] = 0;   // terminate the string
            cmdok++;
            msgln(unlog, 0, "\tExecutable: \"%s\"", cmdcont) ;
         }
         else
         {
            msgln(unlog, 0, "\tExecutable: \"<nonexistant>\"") ;

         }
      }
      else
      {
         msgln(unlog, 0, "\tExecutable: \"<no link>\"") ;
      }
   }
   {       // read internal command name
      sprintf(cmd,"/proc/%i/comm",tmppid);
      statuscmd = stat(cmd, &buffer);
      if (statuscmd == 0) 
      {
         cmdfile=fopen (cmd, "r") ;
         if (cmdfile != NULL) 
         {
//       printf("\tCmdFile : %s\n",cmd) ; //DEBUG
            while ((NULL != fgets (cmdcont, 1000, cmdfile)) && 0 == cmdok2) 
            {
               cmdok2++;
//               printf("\tLastChar : %x\n",cmdcont[strlen(cmdcont)]) ; //DEBUG
               if (cmdcont[strlen(cmdcont)-1] == '\n')
               {
                  cmdcont[strlen(cmdcont)-1] = 0 ;  // get rid of newline
               }
               if (0 == cmdok) // it is a kthreed : add brackets
               {
                  msgln(unlog, 0, "\tCommand: \"[%s]\"", cmdcont) ;
               }
               else
               {
                  msgln(unlog, 0, "\tCommand: \"%s\"", cmdcont) ;
               }
              
            }
            fclose(cmdfile);
         }
         else
         {
            msgln(unlog, 0, "\tCommand: \"can't read file\"") ;
         }
      }
      else 
      {
         msgln(unlog, 0, "\t\"<none>  ... maybe a transitory process\"") ;
      }
   }
   // try to print some useful info about the hidden process
   // does not work well for kernel processes/threads and deamons
   {
      FILE *fich_tmp ;

      sprintf(cmd,"/proc/%i/environ",tmppid);
      statuscmd = stat(cmd, &buffer);
      if (statuscmd == 0) 
      {
         sprintf(cmd,"cat /proc/%i/environ | tr \"\\0\" \"\\n\" | grep -w 'USER'",tmppid) ;
   //      printf(cmd) ;
         fich_tmp=popen (cmd, "r") ;
         if (fich_tmp == NULL) 
         {
            warnln(verbose, unlog, "\tCouldn't read USER for pid %d", tmppid) ;
         }

         if (NULL != fgets(cmdcont, 30, fich_tmp)) 
         {
            cmdcont[strlen(cmdcont)-1] = 0 ;  // get rid of newline
            msgln(unlog, 0, "\t$%s", cmdcont) ;
         }
         else
         {
            msgln(unlog, 0, "\t$USER=<undefined>", cmdcont) ;
         }
         pclose(fich_tmp);

         sprintf(cmd,"cat /proc/%i/environ | tr \"\\0\" \"\\n\" | grep -w 'PWD'",tmppid) ;
   //      printf(cmd) ;
         fich_tmp=popen (cmd, "r") ;
         if (fich_tmp == NULL) 
         {
            warnln(verbose, unlog, "\tCouldn't read PWD for pid %d", tmppid) ;
         }

         if (NULL != fgets(cmdcont, 30, fich_tmp)) 
         {
            cmdcont[strlen(cmdcont)-1] = 0 ;  // get rid of newline
            msgln(unlog, 0, "\t$%s", cmdcont) ;
         }
         else
         {
            msgln(unlog, 0, "\t$PWD=<undefined>", cmdcont) ;
         }
         pclose(fich_tmp);

   //      printf("Done !\n");
      }
   }
   printf("\n");
}


/*
 *  Display short help 
 */
void usage(char * command) 
{

   printf("Usage: %s [options] test_list\n\n", command);
   printf("Option :\n");
   printf("   -V          Show version and exit\n");
   printf("   -v          verbose\n");
   printf("   -h          display this help\n");
   printf("   -m          more checks (available only with procfs, checkopendir & checkchdir commands)\n");
   printf("   -r          use alternate sysinfo test in meta-test\n");
   printf("   -f          log result into unhide-linux.log file\n");
   printf("   -o          same as '-f'\n");
   printf("   -d          do a double check in brute test\n");
   printf("Test_list :\n");
   printf("   Test_list is one or more of the following\n");
   printf("   Standard tests :\n");
   printf("      brute\n");
   printf("      proc\n");
   printf("      procall\n");
   printf("      procfs\n");
   printf("      quick\n");
   printf("      reverse\n");
   printf("      sys\n");
   printf("   Elementary tests :\n");
   printf("      checkbrute\n");
   printf("      checkchdir\n");
   printf("      checkgetaffinity\n");
   printf("      checkgetparam\n");
   printf("      checkgetpgid\n");
   printf("      checkgetprio\n");
   printf("      checkRRgetinterval\n");
   printf("      checkgetsched\n");
   printf("      checkgetsid\n");
   printf("      checkkill\n");
   printf("      checknoprocps\n");
   printf("      checkopendir\n");
   printf("      checkproc\n");
   printf("      checkquick\n");
   printf("      checkreaddir\n");
   printf("      checkreverse\n");
   printf("      checksysinfo\n");
   printf("      checksysinfo2\n");
   printf("      checksysinfo3\n");
}

/*
 * Parse command line arguments (exiting if requested by any option).
 */
void parse_args(int argc, char **argv) 
{
   int c = 0;
   int index = 0;
   
   static struct option long_options[] =
   {
   /* These options set a flag. */
      {"brute-doublecheck",  no_argument,      &brutesimplecheck,   0},
      {"alt-sysinfo",        no_argument,      &RTsys,              1},
      {"log",                no_argument,      &logtofile,          1},
      /* These options don't set a flag.
         We distinguish them by their indices. */
      {"morecheck",          no_argument,      0,                 'm'},
      {"verbose",            no_argument,      0,                 'v'},
      {"help",               no_argument,      0,                 'h'},
      {"version",            no_argument,      0,                 'V'},
      {0, 0, 0, 0}
   };

   for(;;)  // until there's no more option
   {
      /* getopt_long stores the option index here. */
      int option_index = 0;

      c = getopt_long (argc, argv, "dformhvV",
                        long_options, &option_index);

      /* Detect the end of the options. */
      if (c == -1)
         break;

      switch(c)
      {
      case 0 :   // flag long options
         if (long_options[option_index].flag != 0) //if this option set a flag
         {
            break;  // nothing to do
         }
         printf ("option %s", long_options[option_index].name);
         if (optarg) // if there's an argument
         {
            printf (" with arg %s", optarg);
         }
         printf ("\n");
         break ;
      case 'd' :
         brutesimplecheck = FALSE;
         break ;
      case 'h' :
         usage(argv[0]) ;
         exit (0) ;
         break ;
      case 'f' :
         logtofile = 1;
         break;
      case 'o' :
         logtofile = 1 ;
         break ;
      case 'm' :
         morecheck = TRUE;
         verbose = TRUE;
         break ;
      case 'r' :
         RTsys = TRUE;
         break ;
      case 'v' :
         verbose++ ; ;
         break ;
      case 'V' :
         exit (0) ;
         break ;
      case '?' :     // invalid option
         exit (2) ;
         break ;
      default :      // something very nasty happened
         exit(-1) ;
         break ;
      }
     
   }
   
   // generate options string for logging
   strncpy(used_options, "Used options: ", 1000);
   if (verbose)
      strncat(used_options, "verbose ", 1000-1-strlen(used_options));
   if (!brutesimplecheck)
      strncat(used_options, "brutesimplecheck ", 1000-1-strlen(used_options));
   if (morecheck)
      strncat(used_options, "morecheck ", 1000-1-strlen(used_options));
   if (RTsys)
      strncat(used_options, "RTsys ", 1000-1-strlen(used_options));
   if (logtofile)
      strncat(used_options, "logtofile ", 1000-1-strlen(used_options));
      
   // Process list of tests to do
   for (index = optind; index < argc; index++)
   {
      if ((strcmp(argv[index], "proc") == 0) ||
               (strcmp(argv[index], "checkproc") == 0)) 
      {
         tab_test[TST_PROC].todo = TRUE;
      }
      else if (strcmp(argv[index], "procfs") == 0) 
      {
         tab_test[TST_CHDIR].todo = TRUE;
         tab_test[TST_OPENDIR].todo = TRUE;
         tab_test[TST_READDIR].todo = TRUE;
      }
      else if (strcmp(argv[index], "procall") == 0) 
      {
         tab_test[TST_PROC].todo = TRUE;
         tab_test[TST_CHDIR].todo = TRUE;
         tab_test[TST_OPENDIR].todo = TRUE;
         tab_test[TST_READDIR].todo = TRUE;
      }
      else if (strcmp(argv[index], "sys") == 0) 
      {
         tab_test[TST_KILL].todo = TRUE;
         tab_test[TST_NOPROCPS].todo = TRUE;
         tab_test[TST_GETPRIO].todo = TRUE;
         tab_test[TST_GETPGID].todo = TRUE;
         tab_test[TST_GETSID].todo = TRUE;
         tab_test[TST_GETAFF].todo = TRUE;
         tab_test[TST_GETPARM].todo = TRUE;
         tab_test[TST_GETSCHED].todo = TRUE;
         tab_test[TST_RR_INT].todo = TRUE;
/* Remove sysinfo test from sys compound test as it give FP in some case
         if (TRUE == RTsys) 
         {
            tab_test[TST_SYS_INFO2].todo = TRUE;
         }
         else 
         {
            tab_test[TST_SYS_INFO].todo = TRUE;
         }
*/
      }
      else if (strcmp(argv[index], "quick") == 0) 
      {
         tab_test[TST_QUICKONLY].todo = TRUE;
/* Remove sysinfo test from quick compound test as it give FP in some case
         if (TRUE == RTsys) 
         {
            tab_test[TST_SYS_INFO2].todo = TRUE;
         }
         else 
         {
            tab_test[TST_SYS_INFO].todo = TRUE;
         }
*/
      }
      else if ((strcmp(argv[index], "brute") == 0) ||
               (strcmp(argv[index], "checkbrute") == 0)) 
      {
         tab_test[TST_BRUTE].todo = TRUE;
      }
      else if ((strcmp(argv[index], "reverse") == 0) ||
               (strcmp(argv[index], "checkreverse") == 0)) 
      {
         tab_test[TST_REVERSE].todo = TRUE;
      }
      else if (strcmp(argv[index], "opendir") == 0) 
      {
         tab_test[TST_OPENDIR].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkquick") == 0) 
      {
         tab_test[TST_QUICKONLY].todo = TRUE;
      }
      else if (strcmp(argv[index], "checksysinfo") == 0) 
      {
         tab_test[TST_SYS_INFO].todo = TRUE;
      }
      else if (strcmp(argv[index], "checksysinfo2") == 0) 
      {
         tab_test[TST_SYS_INFO2].todo = TRUE;
      }
      else if (strcmp(argv[index], "checksysinfo3") == 0) 
      {
         tab_test[TST_SYS_INFO3].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkchdir") == 0) 
      {
         tab_test[TST_CHDIR].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkreaddir") == 0) 
      {
         tab_test[TST_READDIR].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkopendir") == 0) 
      {
         tab_test[TST_OPENDIR].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkkill") == 0) 
      {
         tab_test[TST_KILL].todo = TRUE;
      }
      else if (strcmp(argv[index], "checknoprocps") == 0) 
      {
         tab_test[TST_NOPROCPS].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkgetprio") == 0) 
      {
         tab_test[TST_GETPRIO].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkgetpgid") == 0) 
      {
         tab_test[TST_GETPGID].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkgetsid") == 0) 
      {
         tab_test[TST_GETSID].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkgetaffinity") == 0) 
      {
         tab_test[TST_GETAFF].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkgetparam") == 0) 
      {
         tab_test[TST_GETPARM].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkgetsched") == 0) 
      {
         tab_test[TST_GETSCHED].todo = TRUE;
      }
      else if (strcmp(argv[index], "checkRRgetinterval") == 0) 
      {
         tab_test[TST_RR_INT].todo = TRUE;
      }
      else 
      { 
         printf("Unknown argument\n") ; usage(argv[0]); exit(0);
      }
   }

   
}


int main (int argc, char *argv[]) 
{
int i;

   printf(header) ;
   if(getuid() != 0){
      die(unlog, "You must be root to run %s !", argv[0]) ;
   }

   // Initialize the table of test to perform.
   // ---------------------------------------
   for (i=0 ; i<MAX_TESTNUM ; i++) {
      tab_test[i].todo = FALSE;
      tab_test[i].func = NULL;
   }
   tab_test[TST_PROC].func = checkproc;
   tab_test[TST_CHDIR].func = checkchdir;
   tab_test[TST_OPENDIR].func = checkopendir;
   tab_test[TST_READDIR].func = checkreaddir;
   tab_test[TST_GETPRIO].func = checkgetpriority;
   tab_test[TST_GETPGID].func = checkgetpgid;
   tab_test[TST_GETSID].func = checkgetsid;
   tab_test[TST_GETAFF].func = checksched_getaffinity;
   tab_test[TST_GETPARM].func = checksched_getparam;
   tab_test[TST_GETSCHED].func = checksched_getscheduler;
   tab_test[TST_RR_INT].func = checksched_rr_get_interval;
   tab_test[TST_KILL].func = checkkill;
   tab_test[TST_NOPROCPS].func = checkallnoprocps;
   tab_test[TST_BRUTE].func = brute;
   tab_test[TST_REVERSE].func = checkallreverse;
   tab_test[TST_QUICKONLY].func = checkallquick;
   tab_test[TST_SYS_INFO].func = checksysinfo;
   tab_test[TST_SYS_INFO2].func = checksysinfo2;
   tab_test[TST_SYS_INFO3].func = checksysinfo3;


   // get the number max of processes on the system.
   // ---------------------------------------------
   get_max_pid(&maxpid);

   // analyze command line args
   // -------------------------
   if(argc < 2) 
   {
      usage(argv[0]);
      exit (1);
   }
   used_options[0] = 0 ;
   parse_args(argc, argv) ;
   
   if (logtofile == 1) 
   {
      unlog = init_log(logtofile, header, "unhide-linux") ;
   }
   msgln(unlog, 0, used_options) ;

   setpriority(PRIO_PROCESS,0,-20);  /* reduce risk from intermittent processes - may fail, dont care */

   mypid = getpid();

   // Execute required tests.
   // ----------------------
   for (i=0 ; i<MAX_TESTNUM ; i++) {
      if ((tab_test[i].todo == TRUE) && (tab_test[i].func != NULL))
      {
         tab_test[i].func();
      }
   }

   if (logtofile == 1) {
      close_log(unlog, "unhide-linux") ;
   }
   return found_HP;
}
