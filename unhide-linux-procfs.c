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
 *  Check all the PID stat() see in /proc. 
 */
void checkproc(void) 
{

   int procpids ;
   int statusprocbefore, statusprocafter;
   struct stat buffer;
   char directory[100] ;

   msgln(unlog, 0, "[*]Searching for Hidden processes through /proc stat scanning\n") ;

   sprintf(directory,"/proc/");

   for ( procpids = 1; procpids <= maxpid; procpids = procpids +1 ) 
   {
      // avoid ourselves
      if (procpids == mypid) 
      {
         continue;
      }
      sprintf(&directory[6],"%d",procpids);

      statusprocbefore = stat(directory, &buffer) ;
      if (statusprocbefore != 0) 
      {
         continue;
      }

      if(checkps(procpids,PS_PROC | PS_THREAD)) 
      {
         continue;
      }

      statusprocafter = stat(directory, &buffer) ;
      if (statusprocafter != 0) 
      {
         continue;
      }

      printbadpid(procpids);
   }
}

/*
 *  Check all the pid that chdir() see in /proc. 
 */
void checkchdir(void) 
{

   int procpids ;
   int statusdir, backtodir;
   char curdir[PATH_MAX], *pathpt ;
   char directory[100] ;
// char scratch[PATH_MAX] ;   // DEBUG
// int count = 0;    //DEBUG

   msgln(unlog, 0, "[*]Searching for Hidden processes through /proc chdir scanning\n") ;

   // get the path where Unhide is ran from.
   if (NULL == (pathpt = getcwd(curdir, PATH_MAX))) 
   {
      warnln(verbose, unlog, "Can't get current directory, test aborted") ;
      return;
   }

   sprintf(directory,"/proc/");

   for ( procpids = 1; procpids <= maxpid; procpids = procpids +1 ) 
   {
      // avoid ourselves
      if (procpids == mypid) 
      {
         continue;
      }

      sprintf(&directory[6],"%d",procpids);
      statusdir = chdir(directory) ;
      // the directory doesn't exist continue with the next one
      if (statusdir != 0) 
      {
         continue;
      }
      if (morecheck == TRUE) 
      {
         // find process group ID (the master thread) by reading the status file of the current dir
         FILE* fich_tmp ;
         int   found_tgid = FALSE;
         char  line[128] ;
         char* tmp_pids = line;
         char* end_pid;
         char  new_directory[100];

//       printf("directory = '%s'\n", directory);  // DEBUG
//       getcwd(scratch, PATH_MAX);                // DEBUG
//       printf("CWD = '%s'\n", scratch);          // DEBUG

         // we are in the /proc/pid directory
         fich_tmp=fopen("status", "r") ;
         if (NULL == fich_tmp) 
         {
            warnln(verbose, unlog, "can't open status file for process: %d", procpids) ;
            continue ; // next process
         }
         while ((FALSE == found_tgid) && (NULL != fgets (line, 128, fich_tmp))) 
         {
            line[127] = 0;
            if (0 == strncmp (line, "Tgid:", 5)) 
            {
               found_tgid = TRUE;
            }
         }
         fclose(fich_tmp);

         if (TRUE == found_tgid) 
         {
            tmp_pids = line + 5;
            while( ((*tmp_pids == ' ') || (*tmp_pids == '\t'))  && (tmp_pids <= line+127)) 
            {
               tmp_pids++;
            }
//          printf("tmp_pids2 = '%s'\n", tmp_pids);   // DEBUG
            end_pid = tmp_pids;
            while( isdigit(*end_pid) && end_pid <= line+127) 
            {
               end_pid++;
            }
            *end_pid = 0;  // remove \n
//          if the number of threads is < to about 40 % of the number of processes,
//          the next "optimising" test actually produce a slower executable.
//          if(procpids != atoi(tmp_pids))
            {   // if the thread isn't the master thread (process)
//             count++;    // DEBUG
               sprintf(new_directory,"/proc/%s/task/%d", tmp_pids, procpids) ;
//             printf("new_dir = %s\n", new_directory);   // DEBUG
               statusdir = chdir(new_directory) ;
               if (statusdir != 0) 
               {
                  // the thread is not listed in the master thread task directory
                  errno = 0 ;
                  warnln(1, unlog, "Thread %d said it's in group %s but isn't listed in %s", procpids, tmp_pids, new_directory) ;
               }
            }
         }
         else 
         {
            errno = 0 ;
            warnln(1, unlog, "Can't find TGID in status file for process: %d", procpids) ;
         }
      }

      // unlock the proc directory so it can disappear if it's a transitory process
      if (-1 == (backtodir = chdir(curdir))) 
      {
         warnln(verbose, unlog, "Can't go back to unhide directory, test aborted") ;
         return;
      }

      if(checkps(procpids, PS_PROC | PS_THREAD)) 
      {
         continue;
      }

      // Avoid false positive on short life process/thread
      statusdir = chdir(directory) ;
      if (statusdir != 0) 
      {
         continue;
      }

      printbadpid(procpids);
   }
   // go back to our path
   if (-1 == (backtodir = chdir(curdir))) 
   {
      warnln(verbose, unlog, "Can't go back to unhide directory, test aborted") ;
      return;
   }
// printf("Passages = %d\n", count);   // DEBUG
}

/*
 *  Check all the pid that opendir() see in /proc. 
 */
void checkopendir(void) 
{

   int procpids ;
   DIR *statusdir;
// char curdir[PATH_MAX] ;
   char directory[100] ;
// char scratch[PATH_MAX] ;   // DEBUG
// int count = 0;    //DEBUG

   msgln(unlog, 0, "[*]Searching for Hidden processes through /proc opendir scanning\n") ;

   sprintf(directory,"/proc/");

   for ( procpids = 1; procpids <= maxpid; procpids = procpids +1 ) 
   {
      // avoid ourselves
      if (procpids == mypid) 
      {
         continue;
      }

      sprintf(&directory[6],"%d",procpids);
      statusdir = opendir(directory) ;
      // the directory doesn't exist continue with the next one
      if (statusdir == NULL)
         continue;

      if (morecheck == TRUE) 
      {
         // find process group ID (the master thread) by reading the status file of the current dir
         FILE* fich_tmp ;
         int   found_tgid = FALSE;
         char  line[128] ;
         char* tmp_pids = line;
         char* end_pid;
         char  new_directory[100] ;
         DIR*  statdir;

//       printf("directory = '%s'\n", directory);  // DEBUG
//       getcwd(scratch, PATH_MAX);                // DEBUG
//       printf("CWD = '%s'\n", scratch);          // DEBUG

         snprintf(line, 128, "%s/status", directory);
//       printf("STATUS_FILE : %s\n", line);
         fich_tmp=fopen(line, "r") ;
         if (NULL == fich_tmp) 
         {
            msgln(unlog, 0, "Can't open status file for process: %d", procpids) ;
            continue ; // next process
         }
         while ((FALSE == found_tgid) && (NULL != fgets (line, 128, fich_tmp))) 
         {
            line[127] = 0;
            if (0 == strncmp (line, "Tgid:", 5)) 
            {
               found_tgid = TRUE;
            }
         }
         fclose(fich_tmp);

         if (TRUE == found_tgid) 
         {
            tmp_pids = line + 5;
            while( ((*tmp_pids == ' ') || (*tmp_pids == '\t'))  && (tmp_pids <= line+127)) 
            {
               tmp_pids++;
            }
//          printf("tmp_pids2 = '%s'\n", tmp_pids);   // DEBUG
            end_pid = tmp_pids;
            while( isdigit(*end_pid) && end_pid <= line+127) 
            {
               end_pid++;
            }
            *end_pid = 0;  // remove \n
//          if the number of threads is < to about 40 % of the number of processes,
//          the next "optimising" test actually produce a slower executable.
//          if(procpids != atoi(tmp_pids))
            {   // if the thread isn't the master thread (process)
//             count++;    // DEBUG
               sprintf(new_directory,"/proc/%s/task/%d", tmp_pids, procpids) ;
//             printf("new_dir = %s\n", new_directory);   // DEBUG
//             errno = 0;
               statdir = opendir(new_directory) ;
               if (NULL == statdir) 
               {
               // the thread is not listed in the master thread task directory
//                printf("opendir failed : %s)\n", strerror(errno)) ;
                  errno = 0 ;
                  warnln(1, unlog, "Thread %d said it's in group %s but isn't listed in %s", procpids, tmp_pids, new_directory) ;
               }
               else 
               {
                  closedir(statdir);
               }
            }
         }
         else 
         {
            errno = 0 ;
            warnln(1, unlog, "Can't find TGID in status file for process: %d", procpids) ;
         }
      }

      // unlock the proc directory so it can disappear if it's a transitory process
      closedir(statusdir);

      if(checkps(procpids, PS_PROC | PS_THREAD)) {
         continue;
      }

      // Avoid false positive on short life process/thread
      statusdir = opendir(directory) ;
      if (statusdir == NULL) {
         continue;
      }
      // unlock dir & free descriptor
      closedir(statusdir);

      printbadpid(procpids);
   }
// printf("Passages = %d\n", count);   // DEBUG
}

/*
 *  Check all the pid that readdir() see in all /proc/pid/task. 
 */
void checkreaddir(void) 
{

   int procpids ;
   DIR *procdir, *taskdir;
   struct dirent *dir, *dirproc;
   char task[100] ;

   msgln(unlog, 0, "[*]Searching for Hidden thread through /proc/pid/task readdir scanning\n") ;

   procdir = opendir("/proc");
   if (NULL == procdir) 
   {
      warnln(verbose, unlog, "Cannot open /proc directory ! Exiting test.") ;
      return ;
   }

   sprintf(task, "/proc/") ;

   while ((dirproc = readdir(procdir))) 
   {
   // As of Linux kernel 2.6 :
   // readdir directly in /proc only see process, not thread
   // because procfs voluntary hides threads to readdir
      char *directory ;

      directory = dirproc->d_name;
      if(!isdigit(*directory)) 
      {
         // not a process directory of /proc
         continue;
      }
//    sprintf(currentproc, "%d", directory);

      sprintf(&task[6], "%s/task", directory) ;
//    printf("task : %s", task) ; // DEBUG
      taskdir = opendir(task);
      if (NULL == taskdir) 
      {
         warnln(verbose, unlog, "Cannot open %s directory ! ! Skipping process %s.", task, directory) ;
         continue ;
      }

      while ((dir = readdir(taskdir)))
      {
         char *tmp_d_name ;
         tmp_d_name = dir->d_name;
//       printf(" thread : %s\n",tmp_d_name) ;  // DEBUG
         if (!strcmp(tmp_d_name, ".") || !strcmp(tmp_d_name, "..")) // skip parent and current dir
            continue;
         if(!isdigit(*tmp_d_name)) 
         {
            errno = 0 ;
            warnln(verbose, unlog, "Not a thread ID (%s) in %s.", tmp_d_name, task) ;
            continue;
         }
         else if (0 != strcmp(tmp_d_name, directory)) { // thread ID is not the process ID
//          printf("thread : %s\n",tmp_d_name) ;  // DEBUG
            procpids = atoi(tmp_d_name) ;
            if(checkps(procpids,PS_THREAD)) {
               continue;
            }
            printbadpid(atoi(tmp_d_name));
         }
         else {
//          printf("process : %s\n",tmp_d_name) ;  // DEBUG
            procpids = atoi(tmp_d_name) ;
            if(checkps(procpids,PS_PROC)) {
               continue;
            }
            printbadpid(atoi(tmp_d_name));
         }
      }
      closedir(taskdir);
   }
   closedir(procdir) ;
}

