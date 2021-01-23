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


/*
 * Globals
 */

enum Proto
{
       TCP = 0,
       UDP = 1
};


/*
 * unhide-tcp
 */
// options
extern int verbose ;
extern int use_fuser ;
extern int use_lsof ;
extern int logtofile ;
extern FILE *unlog ;
extern int hidden_found;
extern char tcpcommand1[] ;
extern char udpcommand1[] ;

/* Print a port, optionally querying info about it via lsof or fuser. */
extern void print_port(enum Proto proto, int port);



/*
 * unhide-tcp-fast
 */
/*
 * Print ports not visible to netstat but that are being used.
 */
void print_hidden_ports(enum Proto proto);
