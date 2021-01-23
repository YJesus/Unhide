**-Unhide-**
               http://www.unhide-forensics.info

Unhide is a forensic tool to find hidden processes and TCP/UDP ports by rootkits / LKMs
or by another hiding technique.

// Unhide (unhide-linux or unhide-posix)
// -------------------------------------

Detecting hidden processes. Implements six main techniques

1- Compare /proc vs /bin/ps output

2- Compare info gathered from /bin/ps with info gathered by walking thru the procfs. ONLY for unhide-linux version

3- Compare info gathered from /bin/ps with info gathered from syscalls (syscall scanning).

4- Full PIDs space ocupation (PIDs bruteforcing). ONLY for unhide-linux version

5- Compare /bin/ps output vs /proc, procfs walking and syscall. ONLY for unhide-linux version
   Reverse search, verify that all thread seen by ps are also seen in the kernel.

6- Quick compare /proc, procfs walking and syscall vs /bin/ps output. ONLY for unhide-linux version
  It's about 20 times faster than tests 1+2+3 but maybe give more false positives.

// Unhide_rb
// ---------

It's a back port in C language of the ruby unhide.rb
As the original unhide.rb, it is roughly equivalent to "unhide-linux quick reverse" :
- it makes three tests less (kill, opendir and chdir),
- it only run /bin/ps once at start and once for the double check,
- also, its tests are less accurate (e.g.. testing return value instead of errno),
- processes are only identified by their exe link (unhide-linux also use cmdline and
  "sleeping kernel process" name),
- there's little protection against failures (failed fopen or popen by example),
- there's no logging capability.
It is very quick, about 80 times quicker than "unhide-linux quick reverse"

// Unhide-TCP
// ----------

Identify TCP/UDP ports that are listening but not listed in sbin/ss or /bin/netstat.
It use two methods: 
- brute force of all TCP/UDP ports availables and compare with SS/netstat output.
- probe of all TCP/UDP ports not reported by netstat.

// Files
// -----

unhide-linux.c      -- Hidden processes, for Linux >= 2.6
unhide-linux.h

unhide-tcp.c        -- Hidden TCP/UDP Ports
unhide-tcp-fast.c
unhide-tcp.h

unhide-output.c     -- Common routines of unhide tools
unhide-output.h

unhide_rb.c         -- C port of unhide.rb (a very light version of unhide-linux in ruby)

unhide-posix.c      -- Hidden processes, for generic Unix systems (*BSD, Solaris, linux 2.2 / 2.4)
                       It doesn't implement PIDs brute forcing check yet. Needs more testing
                       Warning : This version is somewhat outdated and may generate false positive.
                                 Prefer unhide-linux.c if you can use it.

changelog           -- As the name implied log of the change to unhide

COPYING             -- License file, GNU GPL V3

LEEME.txt           -- Spanish version of this file

LISEZ-MOI.TXT       -- French version of this file

NEWS                -- Release notes

README.txt          -- This file

sanity.sh           -- unhide-linux testsuite file

TODO                -- Evolutions to do (any volunteers ?)

man/unhide.8        -- English man page of unhide

man/unhide-tcp.8    -- English man page of unhide-tcp

man/fr/unhide.8     -- French man page of unhide

man/fr/unhide-tcp.8 -- French man page of unhide-tcp

// Compiling
// ---------

Build requires
   glibc-devel
   glibc-static-devel

Require
- unhide-tcp under linux :
   iproute2
   net-tools (for netstat)
   lsof
   psmisc (for fuser)
- unhide-tcp under freeBSD :
   sockstat
   lsof
   netstat
   
unhide-linux, unhide-posix, unhide_rb :
   procps


If you ARE using a Linux kernel >= 2.6
      gcc -Wall -O2 --static -pthread unhide-linux*.c unhide-output.c -o unhide-linux
      gcc -Wall -O2 --static unhide_rb.c -o unhide_rb
      gcc -Wall -O2 --static unhide-tcp.c unhide-tcp-fast.c unhide-output.c -o unhide-tcp
      ln -s unhide unhide-linux

Else (Linux < 2.6, *BSD, Solaris and other Unice)
      gcc --static unhide-posix.c -o unhide-posix
      ln -s unhide unhide-posix

// Using
// -----
You MUST be root to use unhide-linux and unhide-tcp.

Examples:
 # ./unhide-linux  -vo quick reverse
 # ./unhide-linux  -vom procall sys
 # ./unhide_rb

 # ./unhide-tcp  -flov
 # ./unhide-tcp  -flovs

// License
// -------

GPL V.3 (http://www.gnu.org/licenses/gpl-3.0.html)

// Greets
// ------

A. Ramos (aramosf@unsec.net) for some regexps

unspawn (unspawn@rootshell.be) CentOS support

Martin Bowers (Martin.Bowers@freescale.com) CentOS support

Lorenzo Martinez (lorenzo@lorenzomartinez.homeip.net) Some ideas to improve and betatesting

Francois Marier (francois@debian.org) Author of the man pages and Debian support

Johan Walles (johan.walles@gmail.com) Find and fix a very nasty race condition bug

Jan Iven (jan.iven@cern.ch) Because of his great improvements, new tests and bugfixing

P. Gouin (patrick-g@users.sourceforge.net) Because of his incredible work fixing bugs and improving the performance

François Boisson for his idea of a double check in brute test

Leandro Lucarella (leandro.lucarella@sociomantic.com) for the fast scan method and his factorization work for unhide-tcp

Nikos Ntarmos (ntarmos@ceid.upatras.gr) for its invaluable help in the FreeBSD port of unhide-tcp and for packaging unhide on FreeBSD.
