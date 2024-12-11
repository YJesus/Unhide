/*
          http://sourceforge.net/projects/unhide/
*/

/*
Copyright © 2010-2024 Yago Jesus & Patrick Gouin

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

#include "unhide-output.h"
#include "unhide-linux.h"

// Shut up some warnings with over pedantic version of glibc
int ret;

/*
 *  Check all the pid that getpriority() see. 
 */
void checkgetpriority(void) 
{
   int syspids ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through getpriority() scanning\n") ;
   for ( syspids = 1; syspids <= maxpid; syspids = syspids +1 ) 
   {
      int which = PRIO_PROCESS;
      // int ret;

      errno = 0 ;
      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }

      ret = getpriority(which, syspids);
      if ( errno != 0) 
      {
         continue;
      }

      if(checkps(syspids,PS_PROC | PS_THREAD)) 
      {
         continue;
      }

      errno = 0;
      ret = getpriority(which, syspids);
      if ( errno != 0) 
      {
         continue;
      }
      printbadpid(syspids);
   }
}

/*
 *  Check all the pid that getpgid() see. 
 */
void checkgetpgid(void) 
{
   int syspids ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through getpgid() scanning\n") ;
   for ( syspids = 1; syspids <= maxpid; syspids = syspids +1 ) 
   {
      // int ret;

      errno = 0 ;
      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }

      ret = getpgid(syspids);
      if ( errno != 0 ) 
      {
         continue;
      }

      if(checkps(syspids,PS_PROC | PS_THREAD)) 
      {
         continue;
      }

      errno = 0;
      ret = getpgid(syspids);
      if ( errno != 0 ) 
      {
         continue;
      }
      printbadpid(syspids);
   }
}

/*
 *  Check all the pid that getsid() see. 
 */
void checkgetsid(void) 
{
   int syspids ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through getsid() scanning\n") ;
   for ( syspids = 1; syspids <= maxpid; syspids = syspids + 1 ) 
   {
      // int ret;

      errno = 0 ;
      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }

      ret = getsid(syspids);
      if ( errno != 0) 
      {
         continue;
      }
      if(checkps(syspids,PS_PROC | PS_THREAD)) 
      {
         continue;
      }
      errno = 0;
      ret = getsid(syspids);
      if ( errno != 0) 
      {
         continue;
      }
      printbadpid(syspids);
   }
}

/*
 *  Check all the pid that sched_getaffinity() see. 
 */
void checksched_getaffinity(void) 
{

   int syspids;
   cpu_set_t mask;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sched_getaffinity() scanning\n") ;
   for ( syspids = 1; syspids <= maxpid; syspids = syspids + 1 ) 
   {
      // int ret;

      errno = 0 ;
      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }

      ret = sched_getaffinity(syspids, sizeof(cpu_set_t), &mask);
      if (errno != 0) 
      {
         continue;
      }
      if (checkps(syspids,PS_PROC | PS_THREAD)) 
      {
         continue;
      }
      errno = 0;
      ret = sched_getaffinity(syspids, sizeof(cpu_set_t), &mask);
      if (errno != 0) 
      {
         continue;
      }
      printbadpid(syspids);
   }
}

/*
 *  Check all the pid that sched_getparam() see. 
 */
void checksched_getparam(void) 
{

   int syspids;
   struct sched_param param;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sched_getparam() scanning\n") ;
   for ( syspids = 1; syspids <= maxpid; syspids = syspids + 1 ) 
   {
      // int ret;

      errno = 0 ;
      // avoid ourselves
      if (syspids == mypid) {
         continue;
      }

      ret = sched_getparam(syspids, &param);
      if ( errno != 0) 
      {
         continue;
      }

      if(checkps(syspids,PS_PROC | PS_THREAD)) 
      {
         continue;
      }

      errno = 0;
      ret = sched_getparam(syspids, &param);
      if ( errno != 0) 
      {
         continue;
      }
      printbadpid(syspids);
   }
}

/*
 *  Check all the pid that sched_getscheduler() see. 
 */
void checksched_getscheduler(void) 
{
   int syspids ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sched_getscheduler() scanning\n") ;
   for ( syspids = 1; syspids <= maxpid; syspids = syspids + 1 ) 
   {
      // int ret;

      errno = 0 ;
      // avoid ourselves
      if (syspids == mypid) {
         continue;
      }

      ret = sched_getscheduler(syspids);
      if ( errno != 0) 
      {
         continue;
      }

      if(checkps(syspids,PS_PROC | PS_THREAD)) 
      {
         continue;
      }

      errno = 0;
      ret = sched_getscheduler(syspids);
      if ( errno != 0) 
      {
         continue;
      }
      printbadpid(syspids);
   }
}

/*
 *  Check all the pid that sched_rr_get_interval() see. 
 */
void checksched_rr_get_interval(void) 
{

   int syspids;
   struct timespec tp;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sched_rr_get_interval() scanning\n") ;
   for ( syspids = 1; syspids <= maxpid; syspids = syspids + 1 ) 
   {
      // int ret;

      errno = 0 ;
      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }

      ret = sched_rr_get_interval(syspids, &tp);
      if ( errno != 0) 
      {
         continue;
      }

      if(checkps(syspids,PS_PROC | PS_THREAD)) 
      {
         continue;
      }

      errno = 0;
      ret = sched_rr_get_interval(syspids, &tp);
      if ( errno != 0) 
      {
         continue;
      }
      printbadpid(syspids);
   }
}

/*
 *  Check all the pid that kill() see. 
 */
void checkkill(void) 
{
   int syspids;

   msgln(unlog, 0, "[*]Searching for Hidden processes through kill(..,0) scanning\n") ;
   for ( syspids = 1; syspids <= maxpid; syspids = syspids +1 ) 
   {
      // int ret;

      errno = 0 ;
      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }

      ret = kill(syspids, 0);
      if ( errno != 0) 
      {
         continue;
      }

      if(checkps(syspids,PS_PROC | PS_THREAD)) 
      {
         continue;
      }

      errno = 0 ;
      ret = kill(syspids, 0);
      if ( errno != 0) 
      {
         continue;
      }
      printbadpid(syspids);
   }
}

/*
 *  Compare the various system calls against each other,
 *  without invoking 'ps' or looking at /proc
 */
void checkallnoprocps(void) 
{
   // int ret;
   int syspids;
   struct timespec tp;
   struct sched_param param;
   cpu_set_t mask;
   int found = 0;
   int found_killbefore = 0;
   int found_killafter = 0;

   msgln(unlog, 0, "[*]Searching for Hidden processes through  comparison of results of system calls\n") ;
   for ( syspids = 1; syspids <= maxpid; syspids++ ) 
   {
      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }

      found = 0;
      found_killbefore = 0;
      found_killafter = 0;

      errno = 0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killbefore = 1;

      errno = 0 ;
      ret = getpriority(PRIO_PROCESS, syspids);
      if (errno == 0) found++;

      errno = 0 ;
      ret = getpgid(syspids);
      if (errno == 0) found++;

      errno = 0 ;
      ret = getsid(syspids);
      if (errno == 0) found++;

      errno = 0 ;
      ret = sched_getaffinity(syspids, sizeof(cpu_set_t), &mask);
      if (errno == 0) found++;

      errno = 0 ;
      ret = sched_getparam(syspids, &param);
      if (errno == 0) found++;

      errno = 0 ;
      ret = sched_getscheduler(syspids);
      if (errno == 0) found++;

      errno = 0;
      ret = sched_rr_get_interval(syspids, &tp);
      if (errno == 0) found++;

      errno = 0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killafter = 1;


      /* these should all agree, except if a process went or came in the middle */
      if (found_killbefore == found_killafter) 
      {
         if ( ! ((found_killbefore == 0 && found == 0) ||
                 (found_killbefore == 1 && found == 7)) ) 
         {
            printbadpid(syspids);
         }
      } /* else: unreliable */
      else 
      {
         errno = 0 ;
         warnln(verbose, unlog, "syscall comparison test skipped for PID %d.", syspids) ;
      }
   }
}


void genpscmd(char *cmd)
{
   if (unbufferedstdout == TRUE)
   { 
      strcpy(cmd, NO_BUF_PIPE SYS_COMMAND) ;
   }
   else
   {
      strcpy(cmd, SYS_COMMAND) ;
   }
   printf("Commande : %s\n", cmd) ;
}

void checksysinfo(void) 
{

   struct sysinfo info;
   int procnumber = 0;
   int initial_result = 0;
   int final_result = 0;
   int result = 0;
   char buffer[500];
   char command[60];

   FILE *ps_fh ;


   buffer[499] = '\0';

   sysinfo(&info);
   result = initial_result = info.procs;
   
   genpscmd(command) ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sysinfo() scanning (1st variant)\n") ;

   ps_fh = popen (command, "r") ;
   if (ps_fh == NULL) 
   {
      warnln(verbose, unlog, "Couldn't run command: %s, test aborted", SYS_COMMAND) ;
      return;
   }

   while (NULL != fgets(buffer, 499, ps_fh)) 
   {
      procnumber++;
      if(verbose) 
      {
         sysinfo(&info);
         if (result != info.procs) 
         {
            msgln(unlog, 1, "\tWARNING : info.procs changed during test : %d (was %d)",info.procs,result) ;
            result = info.procs;
         }
         if (verbose >= 2) 
         {
            buffer[strlen(buffer)-1] = 0;  // get rid of \n
            snprintf(scratch, 1000, "\"%s\"",buffer) ;
            msgln(unlog, 1, scratch) ;
         }
      }
   }
   pclose(ps_fh);

   sysinfo(&info);
   final_result = info.procs;
   if(verbose >= 1) {
      if (result != final_result) {
         msgln(unlog, 1, "\tWARNING : info.procs changed during test : %d (was %d)",final_result,result) ;
      }
   }


   if (initial_result == final_result) /* otherwise intermittent activity.. */
   {
      int hidennumber = 0;
      // We add one as ps sees itself and not sysinfo.
      hidennumber = final_result  + 1 - procnumber ;

      if (hidennumber != 0) {
         msgln(unlog, 1, "%i HIDDEN Processes Found\tsysinfo.procs reports %d processes and ps sees %d processes",abs(hidennumber), final_result,procnumber-1) ;
         found_HP = 1;
      }
   }
   else 
   {
      errno = 0 ;
      warnln(verbose, unlog, "sysinfo test skipped due to intermittent activity") ;
   }

}


/*
 *  Compare the number of processes reported by sysinfo
 *  with the number of processes seen by ps
 *  Alternate version.
 */
void checksysinfo2() 
{

   struct sysinfo info;
   int procnumber = 0;
   int initial_result = 0;
   int final_result = 0;
   int result = 0;
   char buffer[500];
   char command[60];

   FILE *ps_fh ;


   buffer[499] = '\0';

   genpscmd(command) ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sysinfo() scanning (2nd variant)\n") ;

   ps_fh = popen (command, "r") ;
   if (ps_fh == NULL) 
   {
      warnln(verbose, unlog, "Couldn't run command: %s, test aborted", SYS_COMMAND) ;
      return;
   }

   sysinfo(&info);
   result = initial_result = info.procs;

   while (NULL != fgets(buffer, 499, ps_fh)) 
   {
      procnumber++;
      if(verbose) 
      {
         sysinfo(&info);                     // DEBUG
         if (result != info.procs) 
         {      // DEBUG
            msgln(unlog, 1, "\tWARNING : info.procs changed during test : %d (was %d)",info.procs,result) ;
            result = info.procs;          // DEBUG
         }
         if (verbose >= 2) 
         {
            buffer[strlen(buffer)-1] = 0;  // get rid of \n
            snprintf(scratch, 1000, "\"%s\"",buffer) ;
            msgln(unlog, 1, scratch) ;
         }
      }
   }

   sysinfo(&info);
   final_result = info.procs;
   if(verbose >= 1) 
   {
      if (result != final_result) 
      {
         msgln(unlog, 1, "\tWARNING : info.procs changed during test : %d (was %d)", final_result, result) ;
      }
   }

   pclose(ps_fh);

   if (initial_result == final_result)   /* otherwise intermittent activity.. */
   {
      int hidennumber = 0;

      hidennumber = final_result - procnumber;
      if (hidennumber != 0) 
      {
         msgln(unlog, 1, "%i HIDDEN Processes Found\tsysinfo.procs reports %d processes and ps sees %d processes", abs(hidennumber), final_result,procnumber) ;
         found_HP = 1;
      }
   }
   else 
   {
      errno = 0 ;
      warnln(verbose, unlog, "sysinfo test skipped due to intermittent activity") ;
   }

}

/*
 *  Compare the number of processes reported by sysinfo
 *  with the number of processes seen by ps
 *  minimal version.
 */
void checksysinfo3() 
{

   struct sysinfo info;
   char buffer[500];
   char command[60];

   FILE *ps_fh ;


   buffer[499] = '\0';

   genpscmd(command) ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sysinfo() scanning (3rd variant)\n") ;
   
   if (NULL != (ps_fh = popen (command, "r"))) 
   {
      int procnumber = 0;
      int initial_result = 0;
      int final_result = 0;

      sysinfo(&info);
      initial_result = info.procs;

      while (NULL != fgets(buffer, 499, ps_fh)) 
      {
         procnumber++;
      }

      sysinfo(&info);
      final_result = info.procs;
      pclose(ps_fh);

      if (initial_result == final_result)   /* otherwise intermittent activity.. */
      {
         int hidennumber = 0;

         hidennumber = final_result - procnumber;
         if (hidennumber != 0) 
         {
            msgln(unlog, 1, "%i HIDDEN Processes Found\tsysinfo.procs reports %d processes and ps sees %d processes", abs(hidennumber), final_result,procnumber) ;
            found_HP = 1;
         }
      }
      else 
      {
         errno = 0 ;
         warnln(verbose, unlog, "sysinfo test skipped due to intermittent activity") ;
      }
   }
   else
   {
      warnln(verbose, unlog, "Couldn't run command: %s, test aborted", SYS_COMMAND) ;
      return;
   }

}


char big_buffer[32768*6+1] ;
/*
 *  Compare the number of processes reported by sysinfo
 *  with the number of processes seen by ps
 *  unbuffered version.
 *  In fact there is no way to accelerate sysinfo test with
 *  the procps version of ps, as it always sorts its output.
 *  Therefore its outpout is only available when all processing
 *  is finished.
 */
void checksysinfo4() 
{

   struct sysinfo info;
//   char buffer[500];
   ssize_t read_size, avail ;
   char *buf_pt ;
   char command[60];


   FILE *ps_fh ;


//   buffer[499] = '\0';

   buf_pt = big_buffer ;
   read_size = 0 ;
   avail = 32768*6 ;

   genpscmd(command) ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sysinfo() scanning (4th variant)\n") ;

   if (NULL != (ps_fh = popen (command, "r"))) 
   {
      int procnumber = 0;
      int initial_result = 0;
      int final_result = 0;
      int fd ;

      fd = fileno(ps_fh) ;
      sysinfo(&info);
      initial_result = info.procs;

      while ((read_size = read(fd, buf_pt, avail))) 
      {
         buf_pt += read_size ;
         avail -= read_size ;
         printf("%d\n", (int)read_size) ;
      }

      *buf_pt = 0 ;
      
      sysinfo(&info);
      final_result = info.procs;
      pclose(ps_fh);

      buf_pt = big_buffer ;
      while (*buf_pt)
      {
         if (*buf_pt == '\n')
            procnumber++ ;
         buf_pt++ ;
      }

      if (initial_result == final_result)   /* otherwise intermittent activity.. */
      {
         int hidennumber = 0;

         hidennumber = final_result - procnumber;
         if (hidennumber != 0) 
         {
            msgln(unlog, 1, "%i HIDDEN Processes Found\tsysinfo.procs reports %d processes and ps sees %d processes", abs(hidennumber), final_result,procnumber) ;
            found_HP = 1;
         }
      }
      else 
      {
         errno = 0 ;
         warnln(verbose, unlog, "sysinfo test skipped due to intermittent activity") ;
      }
   }
   else
   {
      warnln(verbose, unlog, "Couldn't run command: %s, test aborted", SYS_COMMAND) ;
      return;
   }

}

