/*
          http://www.unhide-forensics.info
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


#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/resource.h>
#include <errno.h>
#include <stdlib.h>


#ifdef __linux__
   // Linux
   #define COMMAND "ps -eLf | awk '{ print $2 }' | grep -v PID"
// Old Linux (without threads)
// #define COMMAND "ps -ax | awk '{ print $1 }' | grep -v PID"
// CentOS / RHEL linux (thanks  unspawn@rootshell.be and Martin.Bowers@freescale.com )
// #define COMMAND "ps -emf --no-headers| awk '{ print $2 }'"
#else
   #ifdef __OpenBSD__
      //OpenBSD
      #define COMMAND "ps -axk | awk '{ print $1 }' | grep -v PID"
   #else
      #if defined(sun) || defined(__sun)
         # if defined(__SVR4) || defined(__svr4__)
            /* Solaris */
            #define COMMAND "ps -elf | awk '{ print $4 }' | grep -v PID"
         # else
            /* SunOS */
         # endif
      #else
         #if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
            //FreeBSD
            #define COMMAND "ps -axH | awk '{ print $1 }' | grep -v PID"
         #else
            //default : unknown OS
            #define COMMAND "ps -ax | awk '{ print $1 }' | grep -v PID"
         #endif
      #endif
   #endif
#endif



int maxpid= 999999;
// Temporary string for output
char scratch[1000];

// Shut up some warnings with over pedantic version of glibc
int ret;


void checkps(int tmppid) {

	int ok = 0;
	char pids[30];
	char compare[100];

	FILE *fich_tmp ;

	fich_tmp=popen (COMMAND, "r") ;


	while (!feof(fich_tmp) && ok == 0) {

		fgets(pids, 30, fich_tmp);

		sprintf(compare,"%i\n",tmppid);

		if (strcmp(pids, compare) == 0) {ok = 1;}


        }

	pclose(fich_tmp);

	if ( ok == 0 ) {

		int statuscmd ;
		char cmd[100] ;

		struct stat buffer;

		printf ("Found HIDDEN PID: %i\n", tmppid) ;

		sprintf(cmd,"/proc/%i/cmdline",tmppid);

		statuscmd = stat(cmd, &buffer);

		if (statuscmd == 0) {

			FILE *cmdfile ;
			char cmdcont[1000];

			cmdfile=fopen (cmd, "r") ;


			while (!feof (cmdfile)) {

				fgets (cmdcont, 1000, cmdfile);
				printf ("Command: %s\n\n", cmdcont);

			}
		}

	}

}

void checkproc() {

	int procpids ;

	int statusproc;
	struct stat buffer;

	printf ("[*]Searching for Hidden processes through /proc scanning\n\n") ;

	for ( procpids = 1; procpids <= maxpid; procpids = procpids +1 ) {

		char directory[100] ;


		sprintf(directory,"/proc/%d",procpids);


		statusproc = stat(directory, &buffer) ;

		if (statusproc == 0) {

			checkps(procpids);

		}

	}
}

void checkgetpriority() {

	int syspids ;

	printf ("[*]Searching for Hidden processes through getpriority() scanning\n\n") ;


	for ( syspids = 1; syspids <= maxpid; syspids = syspids +1 ) {

		int which = PRIO_PROCESS;

//		int ret;

		errno= 0 ;

		ret = getpriority(which, syspids);

		if ( errno == 0) {

			checkps(syspids);
		}
	}
}

void checkgetpgid() {

	int syspids ;

	printf ("[*]Searching for Hidden processes through getpgid() scanning\n\n") ;



	for ( syspids = 1; syspids <= maxpid; syspids = syspids +1 ) {

//		int ret;

		errno= 0 ;

		ret = getpgid(syspids);

		if ( errno == 0) {

			checkps(syspids);
		}
	}
}


void checkgetsid() {

	int syspids ;


	printf ("[*]Searching for Hidden processes through getsid() scanning\n\n") ;


	for ( syspids = 1; syspids <= maxpid; syspids = syspids +1 ) {

//		int ret;

		errno= 0 ;

		ret = getsid(syspids);

		if ( errno == 0) {

			checkps(syspids);
		}
	}
}



int main (int argc, char *argv[]) {

	strncpy(scratch,"Unhide-posix 20130526\n", 1000) ;
	strncat(scratch, "Copyright © 2013 Yago Jesus & Patrick Gouin\n", 1000);
	strncat(scratch, "License GPLv3+ : GNU GPL version 3 or later\n", 1000);
	strncat(scratch, "http://www.unhide-forensics.info\n\n", 1000);
	strncat(scratch, "NOTE : This is legacy version of unhide, it is intended\n\
       for systems using Linux < 2.6 or other UNIX systems\n\n", 1000);
	fputs(scratch, stdout);


	if(argc != 2) {

		printf("usage: %s proc | sys\n\n", argv[0]);
		exit (1);

	}

	if (strcmp(argv[1], "proc") == 0) {checkproc();}

	else if (strcmp(argv[1], "sys") == 0) {
		checkgetpriority();
		checkgetpgid() ;
		checkgetsid();

	}

	else {
		printf("usage: %s proc | sys\n\n", argv[0]);
		exit (1);
	}
    return(0) ;
}
