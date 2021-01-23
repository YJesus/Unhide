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

/*
 *  Compare the various system calls against each other,
 *  and with fs function in /proc, finally check ps output
 */
void checkallquick(void) 
{

   int ret;
   int syspids;
   struct timespec tp;
   struct sched_param param;
   cpu_set_t mask;
   int found=0;
   int found_killbefore=0;
   int found_killafter=0;
   char directory[100], *pathpt;
   struct stat buffer;
   int statusproc, statusdir, backtodir ;
   char curdir[PATH_MAX] ;
   DIR *dir_fd;

   msgln(unlog, 0, "[*]Searching for Hidden processes through  comparison of results of system calls, proc, dir and ps\n") ;

   // get the path where Unhide is ran from.
   if (NULL == (pathpt = getcwd(curdir, PATH_MAX))) 
   {
      warnln(verbose, unlog, "Can't get current directory, test aborted.") ;
      return;
    }

   sprintf(directory,"/proc/");

   for ( syspids = 1; syspids <= maxpid; syspids++ ) 
   {
      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }
      // printf("syspid = %d\n", syspids); //DEBUG

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
      if (ret == 0) found++;

      errno= 0 ;
      ret = sched_getparam(syspids, &param);
      if (errno == 0) found++;

      errno= 0 ;
      ret = sched_getscheduler(syspids);
      if (errno == 0) found++;

      errno=0;
      ret = sched_rr_get_interval(syspids, &tp);
      if (errno == 0) found++;

      sprintf(&directory[6],"%d",syspids);

      statusproc = stat(directory, &buffer) ;
      if (statusproc == 0) 
      {
         found++;
      }

      statusdir = chdir(directory) ;
      if (statusdir == 0) 
      {
         found++;
         if (-1 == (backtodir = chdir(curdir))) 
         {
            warnln(verbose, unlog, "Can't go back to unhide directory, test aborted.") ;
            return;
         }
      }

      dir_fd = opendir(directory) ;
      if (NULL != dir_fd) 
      {
         found++;
         closedir(dir_fd);
      }

      // Avoid checkps call if nobody sees anything
      if ((0 != found) || (0 != found_killbefore)) 
      {
         if(checkps(syspids,PS_PROC | PS_THREAD)) 
         {
            found++;
         }
      }

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killafter=1;


      /* these should all agree, except if a process went or came in the middle */
      if (found_killbefore == found_killafter) 
      {
         if ( ! ((found_killbefore == 0 && found == 0) ||
                 (found_killbefore == 1 && found == 11)) ) 
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

/*
 *  Check that all processes seen by ps are also seen by
 *  fs function in /proc and by syscall
 */
void checkallreverse(void) 
{

   int ret;
   int syspids;
   struct timespec tp;
   struct sched_param param;
   cpu_set_t mask;
   int not_seen=0;
   int found_killbefore=0;
   int found_killafter=0;
   FILE *fich_tmp;
   char command[50];
   char read_line[1024];
   char lwp[7];
   int  index;
   char directory[100];
   struct stat buffer;
   int statusproc, statusdir, backtodir;
   char curdir[PATH_MAX], *pathpt ;
   DIR *dir_fd;

   msgln(unlog, 0, "[*]Searching for Fake processes by verifying that all threads seen by ps are also seen by others\n") ;

   sprintf(command,REVERSE) ;

   fich_tmp=popen (command, "r") ;
   if (fich_tmp == NULL) 
   {
      warnln(verbose, unlog, "Couldn't run command: %s, test aborted", command) ;
      return;
   }
   // get the path where Unhide is ran from.
   if (NULL == (pathpt = getcwd(curdir, PATH_MAX))) 
   {
      warnln(verbose, unlog, "Can't get current directory, test aborted") ;
      return;
   }

   strcpy(directory,"/proc/");

   while (NULL != fgets(read_line, 1024, fich_tmp)) 
   {
      char* curline = read_line;

      read_line[1023] = 0;
      read_line[strlen(read_line)-1] = 0;

//    printf("read_line = %s\n", read_line);   // DEBUG
      while( *curline == ' ' && curline <= read_line+1023) 
      {
         curline++;
      }

      // get LWP
      index=0;
      while( isdigit(*curline) && curline <= read_line+1023) 
      {
         lwp[index++] = *curline;
         curline++;
      }
      lwp[index] = 0; // terminate string

      syspids = -1;
      syspids = atol(lwp);
      if (-1 == syspids) continue ; // something went wrong

      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }

      not_seen=0;
      found_killbefore=0;
      found_killafter=0;

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killbefore=1;

      strcpy(&directory[6],lwp);

      statusproc = stat(directory, &buffer) ;
      if (statusproc != 0) 
      {
         not_seen++;
      }

      statusdir = chdir(directory) ;
      if (statusdir != 0) 
      {
         not_seen++;
      }
      else 
      {
         if (-1 == (backtodir = chdir(curdir))) 
         {
            warnln(verbose, unlog, "Can't go back to unhide directory, test aborted") ;
            return;
         }
      }

      dir_fd = opendir(directory) ;
      if (NULL == dir_fd) 
      {
         not_seen++;
      }
      else 
      {
         closedir(dir_fd);
      }

      errno= 0 ;
      ret = getpriority(PRIO_PROCESS, syspids);
      if (errno != 0) not_seen++;

      errno= 0 ;
      ret = getpgid(syspids);
      if (errno != 0) not_seen++;

      errno= 0 ;
      ret = getsid(syspids);
      if (errno != 0) not_seen++;

      errno= 0 ;
      ret = sched_getaffinity(syspids, sizeof(cpu_set_t), &mask);
      if (ret != 0) not_seen++;

      errno= 0 ;
      ret = sched_getparam(syspids, &param);
      if (errno != 0) not_seen++;

      errno= 0 ;
      ret = sched_getscheduler(syspids);
      if (errno != 0) not_seen++;

      errno=0;
      ret = sched_rr_get_interval(syspids, &tp);
      if (errno != 0) not_seen++;

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killafter=1;

//    printf("FK_bef = %d FK_aft = %d not_seen = %d\n",found_killbefore, found_killafter, not_seen);  //DEBUG
      /* these should all agree, except if a process went or came in the middle */
      if (found_killbefore == found_killafter) 
      {
         if (found_killafter == 1) 
         {
            if (0 != not_seen) 
            {
               if (NULL == strstr(curline, REVERSE)) // avoid our spawn ps
               {  
                  // printbadpid should NOT be used here : we are looking for faked process
                  msgln(unlog, 0, "Found FAKE PID: %i\tCommand = %s not seen by %d sys fonc", syspids, curline, not_seen) ;
                  found_HP = 1;
               }
            }
         }
         else 
         {
            if (NULL == strstr(curline, REVERSE))  // avoid our spawned ps
            {  
               // printbadpid should NOT be used here : we are looking for faked process
               msgln(unlog, 0, "Found FAKE PID: %i\tCommand = %s not seen by %d sys fonc", syspids, curline, not_seen + 2) ;
               found_HP = 1;
            }
         }
      } /* else: unreliable */
      else
      {
         errno = 0 ;
         warnln(verbose, unlog, "reverse test skipped for PID %d", syspids) ;
      }
   }

   if (fich_tmp != NULL)
      pclose(fich_tmp);
}
