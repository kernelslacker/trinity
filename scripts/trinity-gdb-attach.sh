#!/bin/bash
#
# trinity-gdb-attach.sh — interactive gdb session with Trinity helpers.
#
# Writes a temporary .gdbinit-style file that defines a small set of
# Trinity-aware commands, then execs gdb with it preloaded.  Either
# attach manually (`target remote ...`, `core-file ...`) or use the
# `attach` command provided here to grab the running parent.
#
# Helpers defined:
#   obj <addr>          dump (struct object *)<addr>
#   regions             dump shared_regions[] (mmap'd shared allocations)
#   sym <pc>            wrap `info symbol` for a one-liner
#   attach              find the parent trinity pid and `attach` to it
#

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
trinity_bin="${script_dir}/../trinity"

if [[ ! -x "${trinity_bin}" ]]; then
    echo "ERROR: trinity binary not found at ${trinity_bin} — build first." >&2
    exit 1
fi

tmp_gdbinit=$(mktemp -t trinity-gdbinit.XXXXXX)
trap 'rm -f "${tmp_gdbinit}"' EXIT

cat > "${tmp_gdbinit}" <<'GDBEOF'
set pagination off
set print pretty on
set print array on
set print elements 0
# `attach` below shadows gdb's built-in; silence the redefine prompt.
set confirm off

# ---------------------------------------------------------------------
# obj <addr>
# ---------------------------------------------------------------------
define obj
    if $argc != 1
        printf "usage: obj <addr>\n"
    else
        set $o = (struct object *) $arg0
        printf "(struct object *) %p\n", $o
        printf "  array_idx = %u   (slot in owning objhead->array[])\n", $o->array_idx
        # Best-effort: struct object stores its payload in an anonymous
        # union and does not carry an explicit name/type field — type
        # is implied by which objhead owns it.  Dump the full struct so
        # the union members are visible; the operator can pick out the
        # relevant arm.
        printf "----- full dump -----\n"
        print *$o
    end
end
document obj
Dump a struct object at <addr>.
Prints array_idx (the object's slot in its owning objhead->array[])
and the full struct (which includes the payload union — pick the arm
appropriate for the object type).  The list_head ring was removed in
the array-only refactor; objects are now reached via objhead->array[].

Usage: obj <addr>
end

# ---------------------------------------------------------------------
# regions
# ---------------------------------------------------------------------
# Formatted dump of shared_regions[] (the mmap'd shared-allocation
# tracker used by alloc_shared / range_overlaps_shared).  The array
# and its counter are file-static in utils.c, so qualify with the
# translation unit if the bare names fail to resolve.
define regions
    set $n = (unsigned int) 'utils.c'::nr_shared_regions
    printf "shared_regions: %u entr%s\n", $n, ($n == 1 ? "y" : "ies")
    printf "  %-4s  %-18s  %-18s  %-12s  %-13s\n", "idx", "start", "end", "size", "is_global_obj"
    set $i = 0
    while $i < $n
        set $r     = &(('utils.c'::shared_regions)[$i])
        set $start = $r->addr
        set $size  = $r->size
        set $end   = $start + $size
        set $gobj  = $r->is_global_obj
        printf "  %-4u  0x%016lx  0x%016lx  %-12lu  %s\n", $i, $start, $end, $size, ($gobj ? "true" : "false")
        set $i = $i + 1
    end
end
document regions
Dump shared_regions[] — every mmap'd region tracked by alloc_shared().
Shows index, start, end, size, and whether the region backs a global
object pool.  Note: the array is file-static in utils.c (the task spec
says shm.c — this is a documentation drift, the symbol lives in utils.c).
end

# ---------------------------------------------------------------------
# sym <pc>
# ---------------------------------------------------------------------
define sym
    if $argc != 1
        printf "usage: sym <pc>\n"
    else
        info symbol $arg0
    end
end
document sym
One-liner wrapper around `info symbol <pc>` — resolve a PC to its
nearest symbol + offset.

Usage: sym <pc>
end

# ---------------------------------------------------------------------
# attach
# ---------------------------------------------------------------------
# Find the parent trinity process: `trinity` whose ppid is 1 (the init
# parent — i.e. the top-level trinity that spawned children) or, as a
# fallback, the trinity process whose argv[0] starts with "trinity"
# and which has the most children.  Then `attach` to it.
define attach
    shell pid=""; \
        for p in $(pgrep -x trinity 2>/dev/null); do \
            ppid=$(awk '{print $4}' /proc/$p/stat 2>/dev/null); \
            if [ "$ppid" = "1" ]; then pid=$p; break; fi; \
        done; \
        if [ -z "$pid" ]; then \
            pid=$(ps -e --no-headers -o pid,comm,args | awk '$2=="trinity" || $3 ~ /^trinity/ {print $1}' | head -1); \
        fi; \
        if [ -z "$pid" ]; then \
            echo "trinity-attach: no trinity process found" >&2; \
        else \
            echo "trinity-attach: parent pid = $pid"; \
            echo "attach $pid" > /tmp/trinity-gdb-attach.cmd; \
        fi
    source /tmp/trinity-gdb-attach.cmd
    shell rm -f /tmp/trinity-gdb-attach.cmd
end
document attach
Find the parent trinity process and attach to it.
Picks the trinity pid whose ppid is 1 (the long-lived parent that
forks children); falls back to the first trinity pid otherwise.
Equivalent to running `gdb -p <pid>` by hand.

Usage: attach
end

printf "Trinity gdb helpers loaded — commands: obj, regions, sym, attach\n"
printf "  `help <cmd>` for details on each.\n"
GDBEOF

exec gdb -q -x "${tmp_gdbinit}" "${trinity_bin}" "$@"
