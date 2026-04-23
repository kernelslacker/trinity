#!/bin/sh
#
# parse-bug-line.sh - normalize trinity __BUG() emissions for aggregation.
#
# Trinity's __BUG() (debug.c:__BUG) writes three consecutive stderr lines:
#
#     BUG!: <bugtext>
#     BUG!: <VERSION>
#     BUG!: [<pid>] <filename>:<funcname>:<lineno>
#
# The location line is the new bit (added when bug_func / bug_lineno were
# wired through include/child.h). This script reads stdin, finds those
# triplets, and emits one canonical line per BUG:
#
#     <file>:<line> in <func>() <bugtext>
#
# Pid and version are dropped so identical bugs collapse cleanly under
#   sort | uniq -c
# or
#   grep -c
# across many runs / many hosts.
#
# Lines that aren't part of a __BUG() block pass through silently (dropped).
#
# Usage:
#     cat run.log | scripts/parse-bug-line.sh
#     scripts/parse-bug-line.sh < run.log | sort | uniq -c | sort -rn
#

exec awk '
/^BUG!:/ {
    line = $0
    sub(/^BUG!: */, "", line)

    # Location line:  [<pid>] <file>:<func>:<lineno>
    if (match(line, /^\[[0-9]+\] [^:]+:[^:]+:[0-9]+$/)) {
        sub(/^\[[0-9]+\] */, "", line)
        n = split(line, a, ":")
        if (n < 3) { prev1 = ""; prev2 = ""; next }
        lineno = a[n]
        fn     = a[n-1]
        file   = a[1]
        for (i = 2; i <= n-2; i++) file = file ":" a[i]
        text = (prev2 != "" ? prev2 : "?")
        printf "%s:%s in %s() %s\n", file, lineno, fn, text
        prev1 = ""; prev2 = ""
        next
    }

    # Otherwise, ring-buffer the last two BUG!: text lines so that when
    # the location line lands, prev2 still holds the bug text (prev1 is
    # the version line that sits between text and location).
    prev2 = prev1
    prev1 = line
}
'
