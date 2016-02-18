# /bin/bash
#  vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   1090549 - [RHEL7] Backport TAINT_LIVEPATCH
#   Description: This is used for the future kpatch support
#                the patch module can also check the /sys/moudle/<modname>/taint
#   Author: Chunyu Hu <chuhu@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2015 Red Hat, Inc.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

taint_mask=(
        [0]="P  (G=Gnu)TAINT_PROPRIETARY_MODULE"
        [1]="F  TAINT_FORCED_MODULE"
        [2]="S  TAINT_UNSAFE_SMP"
        [3]="R  TAINT_FORCED_RMMOD"
        [4]="M  TAINT_MACHINE_CHECK"
        [5]="B  TAINT_BAD_PAGE"
        [6]="U  TAINT_USER"
        [7]="D  TAINT_DIE"
        [8]="A  TAINT_OVERRIDDEN_ACPI_TABLE"
        [9]="W  TAINT_WARN"
        [10]="C TAINT_CRAP"
        [11]="I TAINT_FIRMWARE_WORKAROUND"
        [12]="0 TAINT_OOT_MODULE [RHEL7 ONLY]"
        [13]="E TAINT_UNSIGNED_MODULE"
        [14]="L TAINT_SOFTLOCKUP"
        [15]="K TAINT_LIVEPATCH"
        [16]="? TAINT_16"
        [17]="? TAINT_17"
        [18]="? TAINT_18"
        [19]="? TAINT_19"
        [20]="? TAINT_20"
        [21]="? TAINT_21"
        [22]="? TAINT_22"
        [23]="? TAINT_23"
        [24]="? TAINT_24"
        [25]="? TAINT_25"
        [26]="? TAINT_26"
        [27]="? TAINT_BIT_BY_ZOMBIE"
        [28]="H TAINT_HARDWARE_UNSUPPORTED"
        [29]="T TAINT_TECH_PREVIEW"
        [30]="? TAINT_RESERVED30"
        [31]="? TAINT_RESERVED31"
)

function parse_taint(){
        local taint_val=$1
        echo "Input: $taint_val ..."
        for mask in ${!taint_mask[*]};do
                if (( ((1<<mask)) & taint_val ));then
                        echo "bit$mask:         $((1<<mask))            ${taint_mask[$mask]}" |awk '{printf "%-7s %-13s %-5s %s\n", $1 ,$2, $3, $4, $5, $6}'
                fi
        done
}

parse_taint "${1:-$(cat /proc/sys/kernel/tainted)}" |tee TAINT
echo -n "Sum: "
cat TAINT | sed '1d' |awk 'BEGIN{sum=0}{sum+=$2}END{print sum}'
