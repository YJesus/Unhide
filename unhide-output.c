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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#ifdef __linux__
   #include <linux/limits.h>
#else
   #include <limits.h>
#endif
#include <string.h>
#include <time.h>

#include "unhide-output.h"

/*
 * Print a message to a file stream (and log the message if necessary).
 */
void vfmsg(FILE * unlog, FILE* fp, const char* fmt, va_list ap)
{
   char buf[BUFSIZ];

   vsnprintf(buf, BUFSIZ, fmt, ap);
   fputs(buf, fp);

   if (NULL != unlog)
      fputs(buf, unlog);
}


/*
 * Print a message to a stdout (and log the message if necessary), appending \n.
 */
void msgln(FILE * unlog, int indent, const char* fmt, ...)
{
   char buf[BUFSIZ];
   va_list ap;

   if(1 == indent)
   {
      strncpy(buf, "\t", BUFSIZ);
      strncat(buf, fmt, BUFSIZ-strlen(buf));
   }
   else
   {
      strncpy(buf, fmt, BUFSIZ);
   }
   strncat(buf, "\n", BUFSIZ-1-strlen(buf));

   va_start(ap, fmt);
   vfmsg(unlog, stdout, buf, ap);
   va_end(ap);
}


/*
 * Print a warning message to a stderr (and log the message if necessary),
 * appending \n, only if in verbose mode.
 *
 * If errno is not 0, then information about the last error is printed too.
 */
void warnln(int verbose, FILE * unlog, const char* fmt, ...)
{
   char buf[BUFSIZ];
   va_list ap;
   int e = errno; /* save it in case some other function fails */

   if (!verbose)
   {
      return;
   }

   strncpy(buf, "Warning : ", BUFSIZ);
   strncat(buf, fmt, BUFSIZ-1-strlen(buf));
   if (e != 0)
   {
      strncat(buf, " [", BUFSIZ-1-strlen(buf));
      strncat(buf, strerror(e), BUFSIZ-1-strlen(buf));
      strncat(buf, "]", BUFSIZ-1-strlen(buf));
   }
   strncat(buf, "\n", BUFSIZ-1-strlen(buf));

   va_start(ap, fmt);
   vfmsg(unlog, stderr, buf, ap);
   va_end(ap);
}


/*
 * Print an error to stderr and exit with code 1.
 *
 * If errno is not 0, then information about the last error is printed too.
 */
void die(FILE * unlog, const char* fmt, ...)
{
   va_list ap;
   char buf[BUFSIZ];
   int e = errno; /* save it in case some other function fails */

   strncpy(buf, "Error : ", BUFSIZ);
   strncat(buf, fmt, BUFSIZ-1-strlen(buf));
   if (e != 0) 
   {
      strncat(buf, " [", BUFSIZ-1-strlen(buf));
      strncat(buf, strerror(e), BUFSIZ-1-strlen(buf));
      strncat(buf, "]", BUFSIZ-1-strlen(buf));
   }
   strncat(buf, "\n", BUFSIZ-1-strlen(buf));

   va_start(ap, fmt);
   vfmsg(unlog, stderr, buf, ap);
   va_end(ap);

   exit(1);
}

/*
 * Initialize and write a header to the log file. 
 */
FILE *init_log(int logtofile, const char *header, const char *basename)
{
   FILE *fh ;
   char filename[PATH_MAX] ;
   time_t scantime;
   struct tm *tmPtr;
   char cad[80];
   
   if (0 == logtofile)
   {
      return(NULL);
   }

   scantime = time(NULL);
   tmPtr = localtime(&scantime);
   sprintf(filename, "%s_%4d-%02d-%02d.%s", basename, tmPtr->tm_year+1900, tmPtr->tm_mon + 1, tmPtr->tm_mday, "log"  );

   fh = fopen(filename, "w");

   if (NULL == fh)
   {
      logtofile = 0; // inhibit write to log file
      warnln(1, NULL, "Unable to open log file (%s)!", filename) ;
      return(NULL) ;
   }

   fputs(header, fh);

   strftime( cad, 80, "%H:%M:%S, %F", tmPtr );

   fprintf(fh, "\n%s scan starting at: %s\n", basename, cad) ;
   return(fh);
}

/* Write a footer and close the log file. */
void close_log(FILE *fh, const char *basename)
{

   if (NULL == fh)
   {
      return ;
   }

   time_t scantime;
   char cad[80];
   struct tm *tmPtr;

   scantime = time(NULL);
   tmPtr = localtime(&scantime);
   strftime( cad, 80, "%H:%M:%S, %F", tmPtr );

   fprintf(fh, "%s scan ending at: %s\n", basename, cad );
   fclose(fh);
}


