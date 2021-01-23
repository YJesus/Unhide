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

      errno= 0 ;
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

      errno=0;
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

      errno= 0 ;
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

      errno=0;
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
   for ( syspids = 1; syspids <= maxpid; syspids = syspids +1 ) 
   {
      // int ret;

      errno= 0 ;
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
      errno=0;
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
   for ( syspids = 1; syspids <= maxpid; syspids = syspids +1 ) 
   {
      // int ret;

      errno= 0 ;
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
      errno=0;
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
   for ( syspids = 1; syspids <= maxpid; syspids = syspids +1 ) 
   {
      // int ret;

      errno= 0 ;
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

      errno=0;
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
   for ( syspids = 1; syspids <= maxpid; syspids = syspids +1 ) 
   {
      // int ret;

      errno= 0 ;
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

      errno=0;
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
   for ( syspids = 1; syspids <= maxpid; syspids = syspids +1 ) 
   {
      // int ret;

      errno= 0 ;
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

      errno=0;
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

      errno= 0 ;
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

      errno= 0 ;
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
   int found=0;
   int found_killbefore=0;
   int found_killafter=0;

   msgln(unlog, 0, "[*]Searching for Hidden processes through  comparison of results of system calls\n") ;
   for ( syspids = 1; syspids <= maxpid; syspids++ ) 
   {
      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }

      found=0;
      found_killbefore=0;
      found_killafter=0;

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killbefore=1;

      errno= 0 ;
      ret = getpriority(PRIO_PROCESS, syspids);
      if (errno == 0) found++;

      errno= 0 ;
      ret = getpgid(syspids);
      if (errno == 0) found++;

      errno= 0 ;
      ret = getsid(syspids);
      if (errno == 0) found++;

      errno= 0 ;
      ret = sched_getaffinity(syspids, sizeof(cpu_set_t), &mask);
      if (errno == 0) found++;

      errno= 0 ;
      ret = sched_getparam(syspids, &param);
      if (errno == 0) found++;

      errno= 0 ;
      ret = sched_getscheduler(syspids);
      if (errno == 0) found++;

      errno=0;
      ret = sched_rr_get_interval(syspids, &tp);
      if (errno == 0) found++;

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killafter=1;


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

void checksysinfo(void) 
{

   struct sysinfo info;
   int contador=0;
   int resultado_antes=0;
   int resultado_despues=0;
   int resultado = 0;
   int ocultos=0;
   char buffer[500];

   FILE *fich_proceso ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sysinfo() scanning\n") ;

   buffer[499] = '\0';

   sysinfo(&info);
   resultado = resultado_antes=info.procs;

   fich_proceso=popen (SYS_COMMAND, "r") ;
   if (fich_proceso == NULL) 
   {
      warnln(verbose, unlog, "Couldn't run command: %s, test aborted", SYS_COMMAND) ;
      return;
   }

   while (NULL != fgets(buffer, 499, fich_proceso)) 
   {
      contador++;
      if(verbose) 
      {
         sysinfo(&info);
         if (resultado != info.procs) 
         {
            msgln(unlog, 1, "\tWARNING : info.procs changed during test : %d (was %d)",info.procs,resultado) ;
            resultado = info.procs;
         }
         if (verbose >=2) 
         {
            buffer[strlen(buffer)-1] = 0;  // get rid of \n
            snprintf(scratch, 1000, "\"%s\"",buffer) ;
            msgln(unlog, 1, scratch) ;
         }
      }
   }
   pclose(fich_proceso);

   sysinfo(&info);
   resultado_despues=info.procs;
   if(verbose >= 1) {
      if (resultado != resultado_despues) {
         msgln(unlog, 1, "\tWARNING : info.procs changed during test : %d (was %d)",resultado_despues,resultado) ;
      }
   }


   if (resultado_antes == resultado_despues) /* otherwise intermittent activity.. */
   {
      // We add one as ps sees itself and not sysinfo.
      ocultos=resultado_despues  + 1 - contador ;

      if (ocultos != 0) {
         msgln(unlog, 1, "%i HIDDEN Processes Found\tsysinfo.procs reports %d processes and ps sees %d processes",abs(ocultos), resultado_despues,contador-1) ;
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
   int contador=0;
   int resultado_antes=0;
   int resultado_despues=0;
   int resultado = 0;
   int ocultos=0;
   char buffer[500];

   FILE *fich_proceso ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sysinfo() scanning\n") ;

   buffer[499] = '\0';

   fich_proceso=popen (SYS_COMMAND, "r") ;
   if (fich_proceso == NULL) 
   {
      warnln(verbose, unlog, "Couldn't run command: %s, test aborted", SYS_COMMAND) ;
      return;
   }

   sysinfo(&info);
   resultado = resultado_antes = info.procs;

   while (NULL != fgets(buffer, 499, fich_proceso)) 
   {
      contador++;
      if(verbose) 
      {
         sysinfo(&info);                     // DEBUG
         if (resultado != info.procs) 
         {      // DEBUG
            msgln(unlog, 1, "\tWARNING : info.procs changed during test : %d (was %d)",info.procs,resultado) ;
            resultado = info.procs;          // DEBUG
         }
         if (verbose >=2) 
         {
            buffer[strlen(buffer)-1] = 0;  // get rid of \n
            snprintf(scratch, 1000, "\"%s\"",buffer) ;
            msgln(unlog, 1, scratch) ;
         }
      }
   }

   sysinfo(&info);
   resultado_despues=info.procs;
   if(verbose >= 1) 
   {
      if (resultado != resultado_despues) 
      {
         msgln(unlog, 1, "\tWARNING : info.procs changed during test : %d (was %d)", resultado_despues, resultado) ;
      }
   }

   pclose(fich_proceso);

   if (resultado_antes == resultado_despues)   /* otherwise intermittent activity.. */
   {
      ocultos=resultado_despues - contador;
      if (ocultos != 0) 
      {
         msgln(unlog, 1, "%i HIDDEN Processes Found\tsysinfo.procs reports %d processes and ps sees %d processes", abs(ocultos), resultado_despues,contador) ;
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
   int contador=0;
   int resultado_antes=0;
   int resultado_despues=0;
   int ocultos=0;
   char buffer[500];

   FILE *fich_proceso ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sysinfo() scanning\n") ;

   buffer[499] = '\0';

   if (NULL != (fich_proceso=popen (SYS_COMMAND, "r"))) 
   {

      sysinfo(&info);
      resultado_antes = info.procs;

      while (NULL != fgets(buffer, 499, fich_proceso)) 
      {
         contador++;
      }

      sysinfo(&info);
      resultado_despues=info.procs;
      pclose(fich_proceso);

      if (resultado_antes == resultado_despues)   /* otherwise intermittent activity.. */
      {
         ocultos=resultado_despues - contador;
         if (ocultos != 0) 
         {
            msgln(unlog, 1, "%i HIDDEN Processes Found\tsysinfo.procs reports %d processes and ps sees %d processes", abs(ocultos), resultado_despues,contador) ;
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
   int contador=0;
   int resultado_antes=0;
   int resultado_despues=0;
   int ocultos=0;
//   char buffer[500];
   ssize_t read_size, avail ;
   char *buf_pt ;
   int fd ;

   FILE *fich_proceso ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through sysinfo() scanning\n") ;

//   buffer[499] = '\0';

   buf_pt = big_buffer ;
   read_size = 0 ;
   avail = 32768*6 ;
   if (NULL != (fich_proceso=popen (SYS_COMMAND, "r"))) 
   {
      fd = fileno(fich_proceso) ;
      sysinfo(&info);
      resultado_antes = info.procs;

      while ((read_size = read(fd, buf_pt, avail))) 
      {
         buf_pt += read_size ;
         avail -= read_size ;
         printf("%d\n", (int)read_size) ;
      }

      *buf_pt = 0 ;
      
      sysinfo(&info);
      resultado_despues=info.procs;
      pclose(fich_proceso);

      buf_pt = big_buffer ;
      while (*buf_pt)
      {
         if (*buf_pt == '\n')
            contador++ ;
         buf_pt++ ;
      }

      if (resultado_antes == resultado_despues)   /* otherwise intermittent activity.. */
      {
         ocultos=resultado_despues - contador;
         if (ocultos != 0) 
         {
            msgln(unlog, 1, "%i HIDDEN Processes Found\tsysinfo.procs reports %d processes and ps sees %d processes", abs(ocultos), resultado_despues,contador) ;
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

