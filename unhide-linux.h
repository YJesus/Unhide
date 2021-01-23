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


// External commands
// =================
// we are looking only for real process not thread and only one by one
#define COMMAND "ps --no-header -p %i o pid"
// we are looking for session ID one by one
#define SESSION "ps --no-header -s %i o sess"
// We are looking for group ID one by one
// but ps can't select by pgid
#define PGID "ps --no-header -eL o pgid"
// We are looking for all processes even threads
#define THREADS "ps --no-header -eL o lwp"
// for sysinfo scanning, fall back to old command, as --no-header seems to create
// an extra process/thread
// #define SYS_COMMAND "ps -eL o lwp"
#define SYS_COMMAND "ps --no-header -eL o lwp"
// an extra process/thread
#define REVERSE "ps --no-header -eL o lwp,cmd"

// Masks for the checks to do in checkps
// =====================================
#define PS_PROC         0x00000001
#define PS_THREAD       0x00000002
#define PS_MORE         0x00000004

// Test numbers
// ============
// note that checkps can't be call alone.
enum test_num {
   // Individual test
   TST_NONE  = 0,
   TST_VERSION,
   TST_PROC,
   TST_CHDIR,
   TST_OPENDIR,
   TST_READDIR,
   TST_GETPRIO,
   TST_GETPGID,
   TST_GETSID,
   TST_GETAFF,
   TST_GETPARM,
   TST_GETSCHED,
   TST_RR_INT,
   TST_KILL,
   TST_NOPROCPS,
   TST_BRUTE,
   TST_REVERSE,
   TST_QUICKONLY,
   TST_SYS_INFO,
   TST_SYS_INFO2,
   TST_SYS_INFO3,
   // meta test
   TST_DIR,
   TST_SYS,
   TST_QUICK,
   TST_PROCALL,
   // MAX number, should be the last of enum.
   MAX_TESTNUM
};

// boolean values
// ==============
#define FALSE        0
#define TRUE         1

// Structure of the table of tests
// ===============================
struct tab_test_t {
   int todo;
   void (*func)(void);
} ;


// Default sysctl kernel.pid_max
extern int maxpid ;

// Threads id for sync
extern int tid ;

// our own PID
extern pid_t mypid ;

// options
extern int verbose ;
extern int morecheck ;
extern int RTsys ;
extern int brutesimplecheck ;

// Found hidden proccess flag
extern int found_HP ;

// Temporary string for output
extern char used_options[1000];

// For logging to file
extern int logtofile;
extern FILE *unlog;

// Temporary string for output
extern char scratch[1000];

extern struct tab_test_t tab_test[MAX_TESTNUM];

// prototypes
// ==========
// unhide-linux-bruteforce.c
extern void *funcionThread (void *parametro) ;
extern void brute(void) ;

// unhide-linux.c
extern void get_max_pid(int* newmaxpid) ;
extern int  checkps(int tmppid, int checks) ;
extern void printbadpid (int tmppid) ;
extern void usage(char * command) ;
extern void parse_args(int argc, char **argv) ;

// unhide-linux-procfs.c
extern void checkproc(void) ;
extern void checkchdir(void) ;
extern void checkopendir(void) ;
extern void checkreaddir(void) ;

// unhide-linux-syscall.c
extern void checkgetpriority(void) ;
extern void checkgetpgid(void) ;
extern void checkgetsid(void) ;
extern void checksched_getaffinity(void) ;
extern void checksched_getparam(void) ;
extern void checksched_getscheduler(void) ;
extern void checksched_rr_get_interval(void) ;
extern void checkkill(void) ;
extern void checkallnoprocps(void) ;
extern void checksysinfo(void) ;
extern void checksysinfo2(void) ;
extern void checksysinfo3(void) ;
extern void checksysinfo4(void) ;

// unhide-linux-compound.c
extern void checkallquick(void) ;
extern void checkallreverse(void) ;
