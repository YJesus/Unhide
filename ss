#!/bin/sh

# Copyright (C) 2010-2024 Patrick Gouin.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Original Author: Patrick Gouin

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

