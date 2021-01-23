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

#include <stdarg.h>

/*
 * Globals
 */


/*
 * unhide-output
 */

// Print a message to a file stream (and log the message if necessary).
extern void vfmsg(FILE * unlog, FILE* fp, const char* fmt, va_list ap) ;

// Print a message to a stdout (and log the message if necessary), appending \n.
extern void msgln(FILE * unlog, int indent, const char* fmt, ...) ;

// Print a warning message to a stderr (and log the message if necessary),
extern void warnln(int verbose, FILE * unlog, const char* fmt, ...) ;

// Print an error to stderr and exit with code 1.
extern void die(FILE * unlog, const char* fmt, ...) ;

// Initialize and write a header to the log file. 
extern FILE *init_log(int logtofile, const char *header, const char *basename) ;

// Write a footer and close a log file.
extern void close_log(FILE *fh, const char *basename) ;

