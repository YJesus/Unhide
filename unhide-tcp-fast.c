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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include <string.h>
#include <unistd.h>
// #include <time.h>

#include "unhide-output.h"
#include "unhide-tcp.h"

/*
 * These are simplified hash set to store the ports that:
 *
 * - are visible to netstat
 * - are found to be hidden by us
 * - we want to check
 *
 * A value of 0 means the port is NOT in the set, and a value != 0 means
 * otherwise.
 */

static char netstat_ports[65536];
static char hidden_ports[65536];
static char check_ports[65536];

/* Fill netstat_ports with the ports netstat see as used for protocol proto. */
static void get_netstat_ports(enum Proto proto)
{
   FILE *fp;
   int port;

   if (TCP == proto)
   {
      fp=popen (tcpcommand1, "r");
   }
   else
   {
      fp=popen (udpcommand1, "r");
   }

   if (fp == NULL)
   {
      die(unlog, "popen failed to open netstat to get the ports list");
   }

   memset(netstat_ports, 0, sizeof(netstat_ports));

   errno = 0;
   while (!feof(fp))
   {
      if (fscanf(fp, "%i\n", &port) == EOF && errno != 0)
      {
         die(unlog, "fscanf failed to parse int");
      }

      netstat_ports[port] = 1;
   }

   pclose(fp);
}


/*
 * Check a list of ports against what netstat report as used ports.
 *
 * All ports that are not reported as used by netstat are opened, binded and
 * put in listen state (for the TCP proto). If any of that operations fail with
 * an EADDRINUSE, it's reported as a port hidden to netstat.
 */
static void check(enum Proto proto)
{
   int i;
   int protocol;

   if (proto == TCP)
      protocol = SOCK_STREAM;
   else if (proto == UDP)
      protocol = SOCK_DGRAM;
   else
      abort();

   memset(hidden_ports, 0, sizeof(hidden_ports));
   hidden_found = 0;

   get_netstat_ports(proto);
   for (i = 0; i < 65536; i++)
   {
      int fd;
      int reuseaddr;
      struct sockaddr_in addr;

      /*
      * skip if is not a port to check or is already visible to
      * netstat
      */
      if (!check_ports[i] || netstat_ports[i])
      {
         continue;
      }

      fd = socket(AF_INET, protocol, 0);
      if (fd == -1)
      {
         die(unlog, "socket creation failed");
      }

      reuseaddr = 1;
      if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                     sizeof(reuseaddr)) != 0)
      {
         die(unlog, "setsockopt can't set SO_REUSEADDR");
      }

      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = INADDR_ANY;
      addr.sin_port = htons(i);

      /*
       * if we can't bind or listen because the address is used, the
       * port is asumed to be used and added to the hidden_ports list
       * because we only check for ports not visible by netstat.
       * If we can bind them, we remove them from the check_ports
       * list so we don't try to check them again if a new pass is
       * performed in the future.
       */
      errno = 0;
      if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0 ||
                      (proto == TCP && listen(fd, 1) != 0))
      {
         if (errno == EADDRINUSE)
         {
            hidden_ports[i] = 1;
            hidden_found++;
         }
         else 
         {
            warnln(verbose, unlog, "bind failed, maybe you are not root?");
            check_ports[i] = 0;
         }
      }
      else
      {
         check_ports[i] = 0;
      }

      close(fd);
   }
}


/*
 * Print ports not visible to netstat but that are being used.
 *
 * The check for hidden ports is retried to minimize false positives, see
 * comments inside the function for details.
 */
void print_hidden_ports(enum Proto proto)
{
   /* reset the list of ports to check (we start wanting to check all of
    * them) and the list of hidden ports (none is hidden until we prove
    * otherwise)
    */
   memset(check_ports, 1, sizeof(check_ports));
   memset(hidden_ports, 0, sizeof(hidden_ports));

   /*
    * Double-check to minimize false positives.
    *
    * For very short lived connections we have a race condition between
    * getting the output from netstat and trying to open the port
    * ourselves. To minize this problem we check again the ports reported
    * as hidden. If in the next run of netstat those ports are not present
    * anymore, is fairly safe to asume they were false positives.
    */
   check(proto);
   if (hidden_found)
   {
      memcpy(check_ports, hidden_ports, sizeof(hidden_ports));
      check(proto);
   }

   if (hidden_found)
   {
      int i;
      for (i = 0; i < 65536; i++)
      {
         if (hidden_ports[i])
         {
            print_port(proto, i);
         }
      }
   }
}


