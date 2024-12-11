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
   int test_number = 0 ;
   int found=0;
   int hidenflag = 0;
   int found_killbefore=0;
   int found_killafter=0;
   char directory[100];
   struct stat buffer;
   int statusproc, statusdir ;
   char curdir[PATH_MAX] ;
   DIR *dir_fd;

   msgln(unlog, 0, "[*]Searching for Hidden processes through  comparison of results of system calls, proc, dir and ps") ;

   // get the path where Unhide is ran from.
   if (NULL == getcwd(curdir, PATH_MAX))
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

      found=0;
      found_killbefore=0;
      found_killafter=0;
      test_number = 0 ;

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killbefore=1;

      errno= 0 ;
      test_number += 1 ;
      ret = getpriority(PRIO_PROCESS, syspids);
      if (errno == 0) found++;

      errno= 0 ;
      test_number += 1 ;
      ret = getpgid(syspids);
      if (errno == 0) found++;

      errno= 0 ;
      test_number += 1 ;
      ret = getsid(syspids);
      if (errno == 0) found++;

      errno= 0 ;
      test_number += 1 ;
      ret = sched_getaffinity(syspids, sizeof(cpu_set_t), &mask);
      if (ret == 0) found++;

      errno= 0 ;
      test_number += 1 ;
      ret = sched_getparam(syspids, &param);
      if (errno == 0) found++;

      errno= 0 ;
      test_number += 1 ;
      ret = sched_getscheduler(syspids);
      if (errno == 0) found++;

      errno=0;
      test_number += 1 ;
      ret = sched_rr_get_interval(syspids, &tp);
      if (errno == 0) found++;

      sprintf(&directory[6],"%d",syspids);

      test_number += 1 ;
      statusproc = stat(directory, &buffer) ;
      if (statusproc == 0) 
      {
         found++;
      }

      test_number += 1 ;
      statusdir = chdir(directory) ;
      if (statusdir == 0) 
      {
         found++;
         if (-1 ==  chdir(curdir))
         {
            warnln(verbose, unlog, "Can't go back to unhide directory, test aborted.") ;
            return;
         }
      }

      test_number += 1 ;
      dir_fd = opendir(directory) ;
      if (NULL != dir_fd) 
      {
         found++;
         closedir(dir_fd);
      }

      // Avoid checkps call if nobody sees anything
      if ((0 != found) || (0 != found_killbefore)) 
      {
         test_number += 1 ;
         if(checkps(syspids,PS_PROC | PS_THREAD)) 
         {
            found++;
         }
      }

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killafter=1;

      // printf("Nb_test : %d\n", test_number);
      // fflush(stdout) ;

      /* these should all agree, except if a process went or came in the middle */
      if (found_killbefore == found_killafter) 
      {
         if ( ! ((found_killbefore == 0 && found == 0) ||
                 (found_killbefore == 1 && found == test_number)) ) 
         {
            printbadpid(syspids);
            hidenflag = 1 ;

         }
      } /* else: unreliable */
      else 
      {
         errno = 0 ;
         warnln(verbose, unlog, "syscall comparison test skipped for PID %d.", syspids) ;
      }
   }
   if (humanfriendly == TRUE)
   {
      if (hidenflag == 0)
      {
         msgln(unlog, 0, "No hidden PID found\n") ;
      }
      else
      {
         msgln(unlog, 0, "") ;
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
   long int syspids = 0;
   struct timespec tp;
   struct sched_param param;
   cpu_set_t mask;
   int not_seen = 0;
   int hidenflag = 0;
   int found_killbefore = 0;
   int found_killafter = 0;
   FILE *fich_tmp;
   char command[50];
   // char read_line[1024];
   char *read_line = NULL;
   size_t length = 0 ;
   ssize_t rlen ;
   char lwp[11];  // extended to 11 char for 32 bit PID
   int  index;
   char directory[100];
   struct stat buffer;
   // int statusproc, statusdir, backtodir;
   int statusproc, statusdir;
   char curdir[PATH_MAX] ;
   DIR *dir_fd;

   msgln(unlog, 0, "[*]Searching for Fake processes by verifying that all threads seen by ps are also seen by others") ;

   sprintf(command,REVERSE) ;

   fich_tmp=popen (command, "r") ;
   if (fich_tmp == NULL) 
   {
      warnln(verbose, unlog, "Couldn't run command: %s, test aborted", command) ;
      return;
   }
   // get the path where Unhide is ran from.
   if (NULL == getcwd(curdir, PATH_MAX))
   {
      warnln(verbose, unlog, "Can't get current directory, test aborted") ;
      return;
   }

   strcpy(directory,"/proc/");

   // while (NULL != fgets(read_line, 1024, fich_tmp)) 
   while ((rlen = getline(&read_line, &length, fich_tmp)) != -1)
   {
      char* curline = read_line;


      read_line[rlen] = 0;

      while( *curline == ' ' && curline <= read_line+rlen) 
      {
         curline++;
      }

      // get LWP
      index=0;
      while( isdigit(*curline) && curline <= read_line+rlen) 
      {
         lwp[index++] = *curline;
         curline++;
     }
      lwp[index] = 0; // terminate string

      syspids = atol(lwp);

      if (0 == syspids) 
      {
          errno = 0 ; // this warning should not display previous old error.
          warnln(verbose, unlog, "No numeric pid found on ps output line, skip line") ;
          continue ; // something went wrong
      }

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
         if (-1 == chdir(curdir))
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

      // printf("FK_bef = %d FK_aft = %d not_seen = %d\n",found_killbefore, found_killafter, not_seen);  //DEBUG
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
                  msgln(unlog, 0, "Found FAKE PID: %i\tCommand = %s not seen by %d system function(s)", syspids, curline, not_seen) ;
                  found_HP = 1;
                  hidenflag = 1 ;
               }
            }
         }
         else // even kill() doesn't see this process.
         {
            if (NULL == strstr(curline, REVERSE))  // avoid our spawned ps
            {  
               // printbadpid should NOT be used here : we are looking for faked process
               msgln(unlog, 0, "Found FAKE PID: %i\tCommand = %s not seen by %d system function(s)", syspids, curline, not_seen + 2) ;
               found_HP = 1;
               hidenflag = 1 ;
            }
         }
      } /* else: unreliable */
      else
      {
         errno = 0 ;
         warnln(verbose, unlog, "reverse test skipped for PID %d", syspids) ;
      }
   }

      free(read_line) ;

   if (rlen == -1)
      warnln(verbose, unlog, "Something went wrong with getline reading pipe, reverse test stopped at PID %ld\n", syspids) ;
   
   if (humanfriendly == TRUE)
   {
      if (hidenflag == 0)
      {
         msgln(unlog, 0, "No FAKE PID found\n") ;
      }
      else
      {
         msgln(unlog, 0, "") ;
      }
   }

   if (fich_tmp != NULL)
      pclose(fich_tmp);
}
