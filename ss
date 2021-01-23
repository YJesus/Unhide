#!/bin/sh

set -e

# echo "Le 1er paramètre est  : $1" >&2
# echo "Le 2ème paramètre est : $2" >&2
# echo "Le 3ème paramètre est : $3" >&2
# echo "Le 4ème paramètre est : $4" >&2

if [ 0 -eq 1 ]
then
   /usr/bin/netstat $@ | grep -v 631
   exit
elif [ "$4" != ":631" ]
then
   # appelle le véritable ss
   /sbin/ss $@
else
   echo "Le 4ème paramètre est : $4" >&2
fi

