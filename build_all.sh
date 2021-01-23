#! /bin/sh
   gcc -Wall -O2 --static -pthread unhide-linux*.c unhide-output.c -o unhide-linux
   gcc -Wall -O2 --static unhide_rb.c -o unhide_rb
   gcc -Wall -O2 --static unhide-tcp.c unhide-tcp-fast.c unhide-output.c  -o unhide-tcp
   gcc -Wall -O2 --static unhide-posix.c -o unhide-posix
