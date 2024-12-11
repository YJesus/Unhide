#! /bin/sh

#	sanity.sh -- a growing testsuite for unhide.
#
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

# test 2
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

# test 3
# Call ps, but add a faked process.
cat <<EOF
   Test #3
   Call ps, but add a faked process.
   This should show something like:
   "1 HIDDEN Process Found        sysinfo.procs reports xxx processes and ps sees xxx-1 processes"
   But due to the large increase in the number of processes in recent years checksysinfo tests take a very long time.
   Processes therefore have time to appear and disappear making the tests unreliable.

EOF
cat <<EOF >./ps
#! /bin/bash

/bin/ps "\$@"
echo 65535  my_false_proc
EOF
chmod 754 ./ps
PATH=.:$PATH ./unhide-linux -v checksysinfo checksysinfo2


# test 4
# Call ps, but add a faked process.
cat <<EOF
   
   Test #4
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

# remove pre-existing local ps
rm -f ./ps

# test 5
# Call ps, but add a faked process.
cat <<EOF
   
   Test #5
   Call ps, but add a faked process.
   This should show "my_false_proc" repeated enough times for a length > 1023 as faked process

EOF
cat <<EOF >./ps
#! /bin/bash

/bin/ps "\$@"
echo 65535  my_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_00procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_procmy_false_proc
EOF
chmod 754 ./ps
PATH=.:$PATH ./unhide-linux reverse

# remove pre-existing local ps
rm -f ./ps


# test 6
# Call ps, but add a faked process.
cat <<EOF
   
   Test #6
   Call ps, but add a faked process with a non numeric PID
   This should show: "Warning : No numeric pid found on ps output line, skip line"

EOF
cat <<EOF >./ps
#! /bin/bash

/bin/ps "\$@"
echo abcde bad_proc_number
EOF
chmod 754 ./ps
PATH=.:$PATH ./unhide-linux  -v reverse


# test 7
# Call ps, but add a temporary process.
# not working
cat <<EOF
   
   Test #7
   Call ps, but add a temporary process 
   This should show: "Warning : No numeric pid found on ps output line, skip line"
   This test does not work.

EOF
unset UNH_PASSAGE
cat <<'EOF' >./ps
#! /bin/bash
/bin/ps "$@"
if [[ -z "${UNH_PASSAGE}" ]]; then
   export UNH_PASSAGE=1
   echo abcde bad_proc_number
fi

EOF
chmod 754 ./ps
PATH=.:$PATH ./unhide-linux  -v quick
