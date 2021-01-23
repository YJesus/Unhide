#! /bin/sh

#	sanity.sh -- a growing testsuite for unhide.
#
# Copyright (C) 2010 Patrick Gouin.
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

# remove pre-existing local ps
rm -f ./ps

#test 0
# Call ps, but add a faked process.
cat <<EOF
   Test #0
   Call ps, but add a faked process.
   This should show "my_false_proc" as faked process

EOF
cat <<EOF >./ps
#! /bin/bash

/bin/ps "\$@"
echo 65535  my_false_proc
EOF
chmod 754 ./ps
PATH=.:$PATH ./unhide-linux -v checksysinfo checksysinfo2

# remove pre-existing local ps
rm -f ./ps
# test2
# Don't call ps : let all processes appear hidden
cat <<EOF
   
   Test #2
   Don't call ps : let all processes appear hidden.
   This should find all processes as hidden..

EOF
cat <<EOF >./ps
#! /bin/bash

false
EOF
chmod 754 ./ps
PATH=.:$PATH ./unhide-linux procall

# remove pre-existing local ps
rm -f ./ps

# test 1
# Call ps, but hide the last line of output
cat <<EOF
   
   Test #1
   Call ps, but hide the last line of its output.
   Usually, this should find no hidden process, as the last
   process is very often the ps command launched by unhide.
   This ps is not check by unhide (C version).

EOF
cat <<EOF >./ps
#! /bin/bash

/bin/ps "\$@" | head -n-1
EOF
chmod 754 ./ps
PATH=.:$PATH ./unhide-linux sys


# remove pre-existing local ps
rm -f ./ps
# test2
# Don't call ps : let all processes appear hidden
cat <<EOF
   
   Test #2
   Don't call ps : let all processes appear hidden.
   This should find all processes as hidden..

EOF
cat <<EOF >./ps
#! /bin/bash

false
EOF
chmod 754 ./ps
PATH=.:$PATH ./unhide-linux procall

# remove pre-existing local ps
rm -f ./ps
#test 3
# Call ps, but add a faked process.
cat <<EOF
   
   Test #3
   Call ps, but add a faked process.
   This should show "my_false_proc" as faked process

EOF
cat <<EOF >./ps
#! /bin/bash

/bin/ps "\$@"
echo 65535  my_false_proc
EOF
chmod 754 ./ps
PATH=.:$PATH ./unhide-linux reverse

