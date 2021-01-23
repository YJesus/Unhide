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

#define UNHIDE_RB "ps axhHo lwp,cmd"

// boolean value
#define FALSE        0
#define TRUE         1
#define UNKNOWN      -1

// sysctl kernel.pid_max
int maxpid = 32768;

// Temporary string for output
char scratch[1000] ;
char cmdcont[1000] ;

unsigned int proc_parent_pids[65536] ;

char *proc_tasks[65536];
char *ps_pids[65536];
char *messages_pids[65536];
char message[1000] ;
char description[1000] ;
int ps_count = 0 ;

const char *pid_detectors[] =
{
   "ps", "/proc ", "/proc_tasks ", "/proc_parent", "getsid()", "getpgid()",
   "getpriority()", "sched_getparam()",
   "sched_getaffinity()", "sched_getscheduler()", "sched_rr_get_interval()"
} ;

enum n_detector
{
   N_PS,
   N_PROC,
   N_PROC_TASK,
   N_PROC_PARENT,
   N_GETSID,
   N_GET_PGID,
   N_GETPRIORITY,
   N_SCHED_GETPARAM,
   N_SCHED_GETAFFINITY,
   N_SCHED_GETSCHEDULER,
   N_SCHED_RR_GET_INTERVAL
} ;

void setup(int phase)
{
   // setup part of unhide.rb
   // -----------------------

   DIR *procdir, *taskdir;
   struct dirent *dirtask, *dirproc;
   char mypath[512] = "/proc/" ;
   sprintf(mypath, "/proc/") ;

   procdir = opendir(mypath);
   while ((dirproc = readdir(procdir)))
   {
   // As of Linux kernel 2.6 :
   // readdir directly in /proc only see process, not thread
   // because procfs voluntary hides threads to readdir
      char *directory ;

      if (dirproc->d_type != DT_DIR)
      {
         // not a directory or not a process directory
         continue ;
      }
      directory = dirproc->d_name;
      if(!isdigit(*directory))
      {
         // not a process directory of /proc
         continue;
      }
      else
      {
         FILE* fich_tmp ;
         char  line[128] ;
         int tmp_pid ;
// proc_parent_pids
         sprintf(&mypath[6],"%s/status",directory);
//         printf("%s\n",mypath);
         if(NULL != (fich_tmp=fopen(mypath, "r")))
         {
            while (!feof (fich_tmp))
            {

               if (NULL != fgets (line, 128, fich_tmp))
               {
                  line[127] = 0;
                  if (0 == strncmp (line, "ppid:", 5))
                  {
                     tmp_pid = strtol(line+5, NULL, 10);
                     proc_parent_pids[tmp_pid] = tmp_pid ;
                  }
               }
            }
            fclose(fich_tmp);
         }
// proc_tasks
         sprintf(&mypath[6],"%s/task/", directory) ;
         taskdir = opendir(mypath);
         while ((dirtask = readdir(taskdir)))
         {
            char *directory ;

            directory = dirtask->d_name;
            if(!isdigit(*directory))
            {
               // not a process directory of /proc
               continue;
            }
            else
            {
//               FILE* fich_tmp ;
//               char  line[128] ;
//               int tmp_pid ;
               size_t length ;
               char myexe[512] ;

               sprintf(myexe,"%s%s/exe",mypath,directory);
//               printf("%s\n",myexe);

               length = readlink(myexe, cmdcont, 1000) ;
               if (-1 != length)
               {
                  if (2 == phase)
                  {
                     cmdcont[length] = 0;   // terminate the string
                     proc_tasks[strtol(directory, NULL, 10)] = malloc(length+1) ;
                     strcpy(proc_tasks[strtol(directory, NULL, 10)],cmdcont) ;
//                   printf("proc_tasks[%d] = %s\n",strtol(directory, NULL, 10), proc_tasks[strtol(directory, NULL, 10)]) ;
                  }
                  else
                  {
                     proc_tasks[strtol(directory, NULL, 10)] = (char *)1L ;
                  }
               }
            }
         }
         closedir(taskdir) ;
      }
      mypath[6] = 0 ;
   }
   closedir(procdir);
// ps_pids

   FILE *fich_tmp ;
   char myline[1000] ;
   int mypid ;
//   char ch_pid[30] ;

   fich_tmp=popen (UNHIDE_RB, "r") ;

   while (!feof(fich_tmp))
   {
      if (NULL != fgets(myline, 1000, fich_tmp))
      {
         myline[999] = 0;
         if (myline[0] != '\n')
         {
            mypid = strtol(myline, NULL,10) ;
//      printf("line+5 = --%s--\n", myline+5);   // DEBUG
            if (NULL == strstr(myline+5,UNHIDE_RB))
            {
               ps_count++ ;
               if (2 == phase)
               {
                  char *my_end ;
/*
                  int my_len ;
                  my_len = strlen(myline);
                  my_end=myline ;
                  if (1 == mypid)
                     while (my_end < myline+my_len)
                     {
                        printf(" %2x",*my_end);
                        my_end++;
                     }
*/
                  my_end = myline + strlen(myline) -1 ;
//                  printf("line = --%s--\n", myline);   // DEBUG
                  while (' ' == *my_end || '\n' == *my_end || '\r' == *my_end || '\t' == *my_end)
                  {
                     *my_end = 0 ;
                     my_end-- ;
                  }
//                  printf("line = --%s--\n", myline);   // DEBUG
                  ps_pids[mypid] = malloc(strlen(myline+5)+1) ;
//                printf("ps_pids[%d] = %p for %d bytes\n", mypid,ps_pids[mypid],strlen(myline+5)+1);
                  strcpy(ps_pids[mypid],myline+5) ;
//                printf("pid = %d\t", mypid);   // DEBUG
//                printf("cmd = --%s--\n",ps_pids[mypid]);
               }
               else
               {
                  ps_pids[mypid] = (char *)1L ;
               }
            }
         }
      }
   }

   if (fich_tmp != NULL)
      pclose(fich_tmp);
// end of unhide_rb setup

}

int get_suspicious_pids(int pid_num)
{
   int pid_min, pid_max, my_pid ;
   int pid_exists[N_SCHED_RR_GET_INTERVAL+1];
   char mypath[50] ;
   struct stat buffer;
//   FILE *cmdfile ;
   char proc_exe[512] ;
   int statuscmd, length;
   struct sched_param param;
   cpu_set_t mask;
   struct timespec tp;
   int found_p = FALSE ;


   if (pid_num == -1)
   {
      char path[]= "/proc/sys/kernel/pid_max";
      pid_t tmppid = 0;
      FILE* fd= fopen(path,"r");
      if(!fd)
      {
         snprintf(scratch, 1000, "[*] Error: cannot get current maximum PID: %s\n", strerror(errno));
         fputs(scratch, stdout);
      }
      else if((fscanf(fd, "%d", &tmppid) != 1) || tmppid < 1)
      {
         snprintf(scratch, 1000, "[*] cannot get current maximum PID: Error parsing %s format\n", path);
         fputs(scratch, stdout);
      } else
      {
         maxpid = tmppid;
      }
      fclose(fd) ;

      pid_min = 1 ;
      pid_max = maxpid ;
   }
   else
      pid_min = pid_max = pid_num ;

   for (my_pid = pid_min ; my_pid <= pid_max; my_pid++)
   {
//      printf("pid_min = %d, pid_max = %d, my_pid = %d\n", pid_min, pid_max, my_pid) ;
   // ps
      if (ps_pids[my_pid] != NULL)
         pid_exists[N_PS] = TRUE ;
      else
         pid_exists[N_PS] = FALSE ;
   // proc
      sprintf(mypath,"/proc/%d",my_pid);
      statuscmd = stat(mypath, &buffer) ;
      if ((statuscmd == 0) && S_ISDIR(buffer.st_mode))
      {
         pid_exists[N_PROC] = TRUE ;
         strcat(mypath,"/exe") ;
         length = readlink(mypath, cmdcont, 1000) ;
         if (-1 != length)
         {
            cmdcont[length] = 0;   // terminate the string
//            printf("cmdcont(proc_exe) = %s\n", cmdcont) ;   //DEBUG
            strcpy(proc_exe,cmdcont) ;
         }
         else
         {
            strcpy(proc_exe,"unknown exe") ;
         }
      }
      else
      {
         pid_exists[N_PROC] = FALSE ;
      }
   // proc/#/task
      if (proc_tasks[my_pid] != NULL)
         pid_exists[N_PROC_TASK] = TRUE ;
      else
         pid_exists[N_PROC_TASK] = FALSE ;

   // proc_parent
      if (proc_parent_pids[my_pid] != 0)
         pid_exists[N_PROC_PARENT] = TRUE ;
      else
         pid_exists[N_PROC_PARENT] = UNKNOWN ;
   // getsid()
      if (-1 != getsid(my_pid))
      {
         pid_exists[N_GETSID] = TRUE ;
      }
      else
      {
         pid_exists[N_GETSID] = FALSE ;
      }
   // getpgid()
      if (-1 != getpgid(my_pid))
      {
         pid_exists[N_GET_PGID] = TRUE ;
      }
      else
      {
         pid_exists[N_GET_PGID] = FALSE ;
      }
   // getpriority()
      if (-1 != getpriority(PRIO_PROCESS, my_pid))
      {
         pid_exists[N_GETPRIORITY] = TRUE ;
      }
      else
      {
         pid_exists[N_GETPRIORITY] = FALSE ;
      }
   // sched_getparam()
      if (-1 != sched_getparam(my_pid, &param))
      {
         pid_exists[N_SCHED_GETPARAM] = TRUE ;
      }
      else
      {
         pid_exists[N_SCHED_GETPARAM] = FALSE ;
      }
    // sched_getaffinity()
      if (-1 != sched_getaffinity(my_pid, sizeof(cpu_set_t), &mask))
      {
         pid_exists[N_SCHED_GETAFFINITY] = TRUE ;
      }
      else
      {
         pid_exists[N_SCHED_GETAFFINITY] = FALSE ;
      }
    // sched_getscheduler()
      if (-1 != sched_getscheduler(my_pid))
      {
         pid_exists[N_SCHED_GETSCHEDULER] = TRUE ;
      }
      else
      {
         pid_exists[N_SCHED_GETSCHEDULER] = FALSE ;
      }
    // sched_rr_get_interval()
      if (-1 != sched_rr_get_interval(my_pid, &tp))
      {
         pid_exists[N_SCHED_RR_GET_INTERVAL] = TRUE ;
      }
      else
      {
         pid_exists[N_SCHED_RR_GET_INTERVAL] = FALSE ;
      }

      int suspicious = FALSE ;
      int existence_consensus = UNKNOWN ;
      int index ;
      for (index = 0; index <= N_SCHED_RR_GET_INTERVAL; index++)
      {
         if (UNKNOWN == existence_consensus)
         {
            existence_consensus = pid_exists[index] ;
         }
         if (UNKNOWN == pid_exists[index])
            continue ;
         if (FALSE == existence_consensus)
         {
            if (TRUE == pid_exists[index])
               suspicious = TRUE ;
               break ;
         }
         else
         {
            if (FALSE == pid_exists[index])
               suspicious = TRUE ;
               break ;
         }

      }

//    if (1 == my_pid)  suspicious = TRUE ;  //DEBUG
      if(TRUE == suspicious)
      {
         found_p = TRUE ;
         sprintf(message, "Suspicious PID %5d:", my_pid) ;
         int index ;
         for (index = 0; index <= N_SCHED_RR_GET_INTERVAL; index++)
         {
            if (UNKNOWN == pid_exists[index])
               continue;
            description[0] = 0 ;
            if (-1 != pid_num)
            {
               if(N_PS == index)
               {
                  if (NULL != ps_pids[my_pid])
                     strcpy(description, ps_pids[my_pid]) ;
               }
               else if (N_PROC_TASK == index)
               {
                  if (NULL != proc_tasks[my_pid])
                  {
//                     printf("proc_tasks[%d] = %s", my_pid, proc_tasks[my_pid]) ;  // DEBBUG
                     strcpy(description, proc_tasks[my_pid]) ;
                  }
               }
               else if (N_PROC == index)
               {
//                  printf("proc_exe = %s\n", proc_exe) ;  // DEBBUG
                  strcpy(description, proc_exe) ;
               }
            }
            sprintf(scratch, "\n  %s %s%s", (pid_exists[index] ? "Seen by" : "Not seen by"), pid_detectors[index], description) ;
            strcat(message, scratch) ;
         }
//         puts(message) ;  //DEBUG
         if (-1 == pid_num)
         {
            messages_pids[my_pid] = malloc(strlen(message)+1) ;
            strcpy(messages_pids[my_pid], message) ;
         }
      }
   }
   return(found_p);
}


int main (int argc, char *argv[])
{
/*
   time_t scantime1, scantime2;
   char cad[80];
   struct tm *tmPtr;
   double duree ;
*/
   int i ;
   int found_something = FALSE ;
   int phase1_ko = FALSE ;

	strncpy(scratch,"Unhide_rb 20130526\n", 1000) ;

	strncat(scratch, "Copyright © 2013 Yago Jesus & Patrick Gouin\n", 1000);
	strncat(scratch, "License GPLv3+ : GNU GPL version 3 or later\n", 1000);
	strncat(scratch, "http://www.unhide-forensics.info\n\n", 1000);
	strncat(scratch, "NOTE : This version of unhide_rb is for systems using Linux >= 2.6 \n\n", 1000);
	fputs(scratch, stdout);

//   printf(header) ;
   if(getuid() != 0){
      printf("You must be root to run %s !\n", argv[0]) ;
   }


/*
   scantime1 = time(NULL);
   tmPtr = localtime(&scantime1);
   strftime( cad, 80, "%H:%M.%S, %F", tmPtr );
   printf("Unhide_rb scan starting at: %s\n", cad );
*/
   puts ("Scanning for hidden processes...") ;

// initializing memory pointers
   for (i = 0 ; i < maxpid; i++)
   {
      ps_pids[i] = NULL ;
      proc_tasks[i] = NULL ;
      messages_pids[i] = NULL ;
   }

   setup(1);
   struct sysinfo info;
   sysinfo(&info);
   if (ps_count != info.procs)
   {
      puts("ps and sysinfo() process count mismatch:\n") ;
      printf("  ps: %d processes\n", ps_count) ;
      printf("  sysinfo(): %d processes\n", info.procs) ;
   }

   phase1_ko = get_suspicious_pids(-1) ;
// re-initializing memory pointers (were used as boolean in setup() phase 1)
   for (i = 0 ; i < maxpid; i++)
   {
      ps_pids[i] = NULL ;
      proc_tasks[i] = NULL ;
   }
   if (TRUE == phase1_ko)
   {
      setup(2);
      for (i=1; i<maxpid; i++)
      {
         if(NULL != messages_pids[i])
         {
            if (TRUE == get_suspicious_pids(i))
            {
               found_something = TRUE ;
               puts(message) ;
            }
         }
      }
   }



// freeing memory
   for (i = 2 ; i < maxpid; i++)
   {
      if (ps_pids[i] != NULL)
      {
//         printf("free : ps_pids[%d] = %p\n", i,ps_pids[i]);
         free(ps_pids[i]) ;
         ps_pids[i] = NULL ;
      }
      if (proc_tasks[i] != NULL)
      {
         free(proc_tasks[i]) ;
         proc_tasks[i] = NULL ;
      }
      if (messages_pids[i] != NULL)
      {
         free(messages_pids[i]) ;
         messages_pids[i] = NULL ;
      }

   }

// That's all folks
/*
   scantime2 = time(NULL);
   duree = difftime(scantime2,scantime1) ;
   tmPtr = localtime(&scantime2);
   strftime( cad, 80, "%H:%M.%S, %F", tmPtr );
   printf("Unhide_rb scan ending at: %s running for %3.1f s\n", cad, duree );
*/
   if (found_something)
      return(-2);
   else
   {
      puts("No hidden processes found!") ;
      return(0);
   }
}


