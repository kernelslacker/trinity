#!/bin/bash
#
# uapi-shim-values: compiler-authoritative whole-tree scan of uapi shim values.
#
# WHY THIS EXISTS: every #define of the form
#
#   #define IFLA_GRE_LOCAL  6
#
# (whether or not wrapped in #ifndef) is the EFFECTIVE definition on every
# build -- enum constants are not macros, so a cpp #ifndef is unconditionally
# true.  The exception is a shim under #ifndef HAVE_<SYMBOL>, which configure
# compile-tests: there the define is only a fallback for a header that lacks
# the member, and this check keeps its number right.  A typo or miscounted
# enum position compiles clean, links clean, and silently encodes the wrong
# netlink attribute forever.
#
# HOW IT WORKS:
#   1. Harvest  -- collect every "#define SYM <integer>" from the whole tree
#                  (excluding scripts/), stripping C comments first.  Both
#                  decimal and hex values are accepted; all are normalised to
#                  decimal for comparison.
#   2. Probe    -- build a precompiled header from a broad set of installed
#                  linux uapi headers, then compile symbol-checking batches in
#                  parallel to identify which symbols are compiler-resolvable.
#                  Symbols the compiler cannot find (trinity-private defines)
#                  are excluded.  The fixed-symbol final binary is then run to
#                  obtain the authoritative integer value for each symbol.
#                  With TRINITY_LINUS_SRC set the probe repeats against that
#                  kernel tree's installed headers, a macro still unresolved
#                  is read out of their text instead (Step 4c), and what is
#                  left is evaluated by compiling the one installed header
#                  that declares it (Step 4d).
#   3. Compare  -- for every compiler-resolved symbol, every occurrence of
#                  that symbol in trinity's source must carry the compiler's
#                  value, and for every text-resolved or header-compiled one
#                  the header's.  A mismatch is a FAIL.
#   4. Baseline -- scripts/check-static/uapi-shim-values.baseline pins
#                  specific symbol→value pairs.  Each baseline entry is an
#                  additional cross-check:
#                    * compiler value ≠ baseline value    →  FAIL
#                      (kernel headers changed; baseline needs updating)
#                    * no shim for the symbol in the tree →  FAIL
#                      (the entry is stale or misspelled)
#                    * shimmed, but the compiler can't resolve it  →  SKIP
#                      (the host's headers predate it; counted in the PASS
#                      line, and still checked if a Tier-2 tree resolves it)

set -u

NAME="uapi-shim-values"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/uapi-shim-values.baseline"
PROBED_FLOOR_FILE="$ROOT/scripts/check-static/uapi-shim-probed-floor.baseline"
TIER1_FLOOR_FILE="$(dirname "$PROBED_FLOOR_FILE")/uapi-shim-tier1-probed-floor.baseline"
HARVEST_FLOOR_FILE="$(dirname "$PROBED_FLOOR_FILE")/uapi-shim-harvest-floor.baseline"
TEXT_FLOOR_FILE="$(dirname "$PROBED_FLOOR_FILE")/uapi-shim-text-floor.baseline"
HDR_FLOOR_FILE="$(dirname "$PROBED_FLOOR_FILE")/uapi-shim-hdr-floor.baseline"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
command -v gcc  >/dev/null 2>&1 || { echo "ERROR: $NAME: gcc unavailable"; exit 1; }
command -v perl >/dev/null 2>&1 || { echo "ERROR: $NAME: perl unavailable"; exit 1; }

# ---------------------------------------------------------------------------
# Temp workspace
# ---------------------------------------------------------------------------
WORKDIR=$(mktemp -d /tmp/shim-gate-XXXXXX)
HARVEST="$WORKDIR/harvest.txt"
SYMS_ALL="$WORKDIR/syms-all.txt"
SYMS_BAD="$WORKDIR/syms-bad.txt"
SYMS_GOOD="$WORKDIR/syms-good.txt"
PCH_HDR="$WORKDIR/uapi-probe-headers.h"
FINAL_C="$WORKDIR/final-probe.c"
FINAL_BIN="$WORKDIR/final-probe"
FINAL_ERR="$WORKDIR/final-probe.err"
COMPILER_RAW="$WORKDIR/compiler-raw.txt"
COMPILER_TABLE="$WORKDIR/compiler-table.txt"
WIDE_TABLE="$WORKDIR/wide-table.txt"
trap 'rm -rf "$WORKDIR"' EXIT

# ---------------------------------------------------------------------------
# Step 1: Harvest
# Collect all "#define SYM <integer>" lines from the tree (excluding scripts/).
# Strip C block/line comments first so commented-out stale values are ignored.
# Decimal and hex values are both captured; stored as-is for normalization
# at comparison time.
#
# NEGATIVE decimals are captured too, and were not until this was fixed.  The
# comparison code has always handled them -- int32() carries a comment reading
# "decimal (may carry sign from -1, etc.)" -- but the harvest regex accepted
# only unsigned literals, so no negative shim ever reached that branch.  The
# symbols this hid are not incidental: negative-fd sentinels are a family
# (AT_FDCWD -100, PIDFD_SELF_THREAD -10000, FD_PIDFS_ROOT -10002,
# FD_NSFS_ROOT -10003, FD_FAILFS_ROOT -10004), they are precisely the
# constants that have to be exact, and a wrong one aims a syscall at the
# wrong magic fd instead of failing loudly.
#
# A literal may also carry a U or L suffix and sit in one pair of parentheses
# ("#define SYM (0x10UL)"), which is how the kernel's headers write much of
# what a shim copies.  The pattern used to skip every such shim, so their
# values were compared with nothing.  The literal has to end the line: with
# anything after it ("#define SYM 4 + 3") it is the start of an expression,
# and reading it as the whole value would accuse a correct shim.
# Output: "SYM VALUE" pairs, sorted and uniqued.
# ---------------------------------------------------------------------------
find "$ROOT" -path "$ROOT/scripts" -prune -o \
    \( -name '*.c' -o -name '*.h' \) -print 2>/dev/null | sort | \
  xargs perl -0777 -pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' 2>/dev/null | \
  grep -oE '#[[:space:]]*define[[:space:]]+[A-Z][A-Z0-9_]+[[:space:]]+\(?(0[xX][0-9a-fA-F]+|-?[0-9]+)[uUlL]*\)?[[:space:]]*$' | \
  sed -E 's/#[[:space:]]*define[[:space:]]*//; s/\(//; s/\)//; s/([0-9a-fA-F])[uUlL]+[[:space:]]*$/\1/' | \
  awk '{print $1, $2}' | sort -u > "$HARVEST"

# Second harvest pass: single-bit shift shims.
#
# A large share of flag constants are not written as literals at all --
# upstream writes them as shifts, and the shims copy that verbatim:
#
#   #define UFFD_FEATURE_RWP          (1<<17)
#   #define UFFDIO_REGISTER_MODE_RWP  ((__u64)1<<3)
#
# The literal-only pass above skips every one of those, so flag
# constants -- where an off-by-one shift is easy to make and invisible,
# because a wrong bit is still a plausible-looking flag -- were the
# least-checked class in the tree rather than the most.
#
# Evaluate only the unambiguous shape: an optional cast, a literal 1 (with
# an optional U or L suffix), a left shift, a decimal or hex count, nothing
# else.  Anything with
# arithmetic, an identifier, or a second term is left alone rather than
# half-parsed -- a wrong value here would be a false accusation against
# a correct shim, which is worse than no check at all.  Shifts wider
# than 63 are dropped; the comparison side truncates to int32 exactly as
# it does for a literal.
find "$ROOT" -path "$ROOT/scripts" -prune -o \
    \( -name '*.c' -o -name '*.h' \) -print 2>/dev/null | sort | \
  xargs perl -0777 -ne '
	s{/\*.*?\*/}{}gs; s{//[^\n]*}{}g;
	while (m{^[ \t]*\#[ \t]*define[ \t]+([A-Z][A-Z0-9_]+)[ \t]+
		 \(*\s* (?:\((?:__u\d+|unsigned\ long\ long|unsigned\ long|unsigned\ int|unsigned|int|long)\)\s*)?
		 1[uUlL]* \s*<<\s* (0[xX][0-9a-fA-F]+|[0-9]+) \s*\)*\s*$}gmx) {
		my ($sym, $sh) = ($1, $2);
		$sh = hex($sh) if $sh =~ /^0[xX]/;
		next if $sh > 63;
		printf("%s %s\n", $sym, 1 << $sh);
	}' 2>/dev/null | sort -u >> "$HARVEST"

sort -u -o "$HARVEST" "$HARVEST"

# Harvest floor: the pipeline collects every integer #define in the source
# tree (excluding scripts/).  The floor is ratcheted via
# uapi-shim-harvest-floor.baseline (matching the tier1-probed-floor pattern)
# so a silently-collapsed find/perl/grep pipeline fails hard rather than
# passing vacuously.  This check runs unconditionally and is the only
# surviving quantitative floor on the linus-tree-absent path.
harvest_floor=0
if [ -f "$HARVEST_FLOOR_FILE" ]; then
    harvest_floor=$(grep -oE '^[0-9]+' "$HARVEST_FLOOR_FILE" | head -1 || true)
    harvest_floor=${harvest_floor:-0}
fi
if [ "$harvest_floor" -eq 0 ]; then
    echo "FAIL: $NAME: harvest floor is unseeded (uapi-shim-harvest-floor.baseline contains 0 or is missing)"; exit 1
fi
# Do NOT lower the harvest floor to paper over a pipeline regression.
if [ ! -s "$HARVEST" ]; then
    echo "FAIL: $NAME: harvest is empty — find/perl/grep pipeline produced no output"
    exit 1
fi
harvest_count=$(wc -l < "$HARVEST" | tr -d ' ')
if [ "$harvest_count" -lt "$harvest_floor" ]; then
    echo "FAIL: $NAME: harvest floor: only $harvest_count shim define(s) found, need >= $harvest_floor (ratcheted baseline)"
    exit 1
fi

awk '{print $1}' "$HARVEST" | sort -u > "$SYMS_ALL"

# ---------------------------------------------------------------------------
# Step 2: Precompiled header
# Build a PCH from a broad set of installed linux uapi system headers.
# Using a PCH means each batch compilation only pays the header-parse cost
# once, keeping each batch fast even when errors are generated.
# The PCH is automatically selected by gcc when -include <hdr> is used and
# <hdr>.gch exists alongside <hdr>.
# ---------------------------------------------------------------------------

# Build the probe header from all available linux system headers in our list.
{
  echo '#include <stdio.h>'
  echo '#include <stdint.h>'
  echo '#include <stdbool.h>'
  for h in \
      linux/xfrm.h linux/nl80211.h linux/neighbour.h linux/if_tunnel.h \
      linux/if_link.h linux/if_addr.h linux/if_arp.h linux/if_bridge.h \
      linux/if_ether.h linux/if_tun.h linux/socket.h linux/in.h linux/in6.h \
      linux/ip.h linux/ipv6.h linux/tcp.h linux/udp.h linux/sctp.h \
      linux/dccp.h linux/rtnetlink.h linux/genetlink.h linux/veth.h \
      linux/netfilter/nf_tables.h linux/netfilter/nfnetlink_conntrack.h \
      linux/netfilter/ipset/ip_set.h linux/prctl.h linux/capability.h \
      linux/mman.h linux/futex.h linux/fcntl.h linux/sched.h \
      linux/perf_event.h linux/io_uring.h linux/bpf.h linux/landlock.h \
      linux/lsm.h linux/batman_adv.h linux/dpll.h linux/thermal.h \
      linux/vdpa.h linux/ovpn.h linux/nbd-netlink.h linux/net_dropmon.h \
      linux/net_shaper.h linux/nfsd_netlink.h linux/ioprio.h linux/nfc.h \
      linux/psample.h linux/psp-dbc.h linux/psp-sev.h \
      linux/ethtool_netlink.h linux/hw_breakpoint.h \
      linux/pkt_sched.h linux/pkt_cls.h linux/fib_rules.h linux/devlink.h \
      linux/dcbnl.h linux/netlink.h linux/netfilter/nfnetlink_log.h \
      linux/netfilter/nfnetlink_queue.h linux/tc_act/tc_mirred.h \
      linux/netfilter/nf_tables_compat.h; do
    [ -f "/usr/include/$h" ] && echo "#include <$h>"
  done
} > "$PCH_HDR"

# Compile PCH (best-effort; if it fails we fall back to plain -include)
gcc -w -x c-header -o "${PCH_HDR}.gch" "$PCH_HDR" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 3: Parallel batch probe
# Split the symbol list into batches of 100 and compile all batches
# concurrently.  Each batch generates a C file with one printf per symbol.
# Symbols that gcc reports as "undeclared" are collected into $SYMS_BAD.
#
# IMPORTANT: gcc reports "did you mean X?" suggestions alongside undeclared
# errors, and those suggestions look like quoted identifiers too.  We extract
# only the identifier that appears directly after "error: " on the same line,
# not the suggestion that may appear on the following "note:" line or in the
# same-line suffix.
# ---------------------------------------------------------------------------

LQ=$(printf '\xe2\x80\x98')  # U+2018 LEFT SINGLE QUOTATION MARK (gcc uses these)
RQ=$(printf '\xe2\x80\x99')  # U+2019 RIGHT SINGLE QUOTATION MARK

extract_bad_syms() {
    # Extract the undeclared identifier from gcc diagnostics.
    # Format: "file:line:col: error: 'SYM' undeclared ..."
    # We normalise the Unicode curly quotes to ASCII first, then pick only
    # the identifier directly following "error: '" -- not any suggestion.
    LC_ALL=C sed "s/${LQ}/'/g; s/${RQ}/'/g" "$@" 2>/dev/null | \
        grep "error:.*undeclared" | \
        grep -oE "error: '[A-Z][A-Z0-9_]+'" | \
        grep -oE "'[A-Z][A-Z0-9_]+'" | \
        tr -d "'" | sort -u
}

BATCH_DIR="$WORKDIR/batches"
mkdir -p "$BATCH_DIR"
split -l 100 "$SYMS_ALL" "$BATCH_DIR/batch-"

# Compile all batches in parallel
for batch in "$BATCH_DIR"/batch-*; do
    bname=$(basename "$batch")
    {
        echo 'int main(void){'
        awk '{printf "printf(\"%%d %%s\\n\",(int)%s,\"%s\");\n", $1, $1}' "$batch"
        echo 'return 0;}'
    } > "$BATCH_DIR/${bname}.c"
    gcc -w -fmax-errors=200 -include "$PCH_HDR" \
        -o "$BATCH_DIR/${bname}.out" "$BATCH_DIR/${bname}.c" \
        2>"$BATCH_DIR/${bname}.err" &
done
wait

# Collect all bad symbols from all batch error files
extract_bad_syms "$BATCH_DIR"/*.err > "$SYMS_BAD" 2>/dev/null || touch "$SYMS_BAD"

# Good symbols = all symbols minus bad ones
comm -23 "$SYMS_ALL" "$SYMS_BAD" > "$SYMS_GOOD"

# value_statements SYMFILE: the statements of a probe program that report the
# value of each symbol in SYMFILE.  Every symbol gets a line "VALUE SYM" with
# the value as an int, the operand of the 32-bit comparison.  A constant of a
# 64-bit type that is above 0xffffffff gets a second line, "W SYM HEX", with
# all 64 bits: as an int, CLONE_NNP and CLONE_AUTOREAP are both 0.  The type is
# part of the test because an int -1 becomes 0xffffffffffffffff when widened,
# and it still has to match the 32-bit spelling 0xffffffff, while a 64-bit
# constant of the same value has to match only the 64-bit one.
value_statements() {
    awk '{
        printf "printf(\"%%d %%s\\n\",(int)%s,\"%s\");\n", $1, $1
        printf "if(sizeof(%s)>4&&(unsigned long long)(%s)>0xffffffffULL)", $1, $1
        printf "printf(\"W %%s %%016llx\\n\",\"%s\",(unsigned long long)(%s));\n", $1, $1
    }' "$1"
}

# ---------------------------------------------------------------------------
# Step 4: Final compile and run
# Compile only the good symbols (those resolvable against uapi headers) into
# a final binary and run it to get the authoritative compiler values.
# This compilation should succeed cleanly.
# ---------------------------------------------------------------------------
{
    echo 'int main(void){'
    value_statements "$SYMS_GOOD"
    echo 'return 0;}'
} > "$FINAL_C"

if ! gcc -w -include "$PCH_HDR" -o "$FINAL_BIN" "$FINAL_C" 2>"$FINAL_ERR"; then
    # A second pass may catch any stragglers that slipped through batch filtering
    bad2=$(extract_bad_syms "$FINAL_ERR")
    if [ -n "$bad2" ]; then
        comm -23 "$SYMS_GOOD" <(printf '%s\n' "$bad2" | sort) > "$WORKDIR/syms-good2.txt"
        SYMS_GOOD="$WORKDIR/syms-good2.txt"
        {
            echo 'int main(void){'
            value_statements "$SYMS_GOOD"
            echo 'return 0;}'
        } > "$FINAL_C"
        gcc -w -include "$PCH_HDR" -o "$FINAL_BIN" "$FINAL_C" 2>"$FINAL_ERR" || true
    fi
fi

# TIER1_STATUS names the outcome of the Tier-1 probe build so callers and
# future routing logic can distinguish hard breakage from deliberate skips.
# "broken: probe binary unbuildable" means the gcc compile step failed even
# after the second-pass bad-symbol strip — this is a build-environment failure,
# not a "tree absent" style soft skip, so it routes to exit 1.
TIER1_STATUS="ok"
if [ ! -x "$FINAL_BIN" ]; then
    TIER1_STATUS="broken: probe binary unbuildable"
    echo "FAIL: $NAME: Tier-1 probe binary could not be built (TIER1_STATUS=$TIER1_STATUS)" >&2
    exit 1
fi

"$FINAL_BIN" > "$COMPILER_RAW" 2>/dev/null

# ---------------------------------------------------------------------------
# Step 4b: Tier 2 fallback — linux-linus source tree (headers built into scratch tmpdir)
# For symbols that failed to resolve against installed system headers, attempt
# a second compile-probe using the linux-linus source tree/include/uapi prepended.
# This catches symbols too new for the build host's installed headers — exactly
# the highest-risk class (freshly-added shims where an off-by-one is most
# likely).
#
# Motivating example: XFRM_MSG_MIGRATE_STATE sat at wrong value 42 (should be
# 41) from its first commit.  The installed-headers-only Tier 1 probe silently
# skipped it, reporting "1704/1704 verified correct" without touching the
# symbol at all.  The wrong value was live for multiple ticks before manual
# review caught it.
#
# Tier 2 is purely additive; headers_install builds into a scratch tmpdir to
# keep the linus source tree unmodified.
# If the linux-linus source tree does not exist the block is skipped silently.
#
# The tree location comes from $TRINITY_LINUS_SRC, and there is no default.
# It cannot have one: any built-in guess is somebody's home directory, and a
# home-anchored path does not belong in this repo.  The previous value here
# was the literal string "the linux-linus source tree", which is a sentence
# rather than a path -- [ -d ] on it is false on every machine that has ever
# run this check, so Tier 2 has never once executed and every run has reported
# "tier2=skipped: linus tree absent", including on boxes with the tree sitting
# right there.  That is the tier that exists to catch freshly-added shims
# whose symbols the build host's headers are too old to know, which is exactly
# the class the merge-window work produces.
#
#   TRINITY_LINUS_SRC=/path/to/linux scripts/check-static.sh
#
# Unset still skips silently, so the default posture is unchanged.
# ---------------------------------------------------------------------------
LINUS_SRC="${TRINITY_LINUS_SRC:-}"
LINUS_UAPI="${LINUS_SRC:+$LINUS_SRC/include/uapi}"
HDR_INSTALL=""
SYMS_TIER2_GOOD="$WORKDIR/syms-tier2-good.txt"
TIER2_STATUS="not-needed"
BUILD_SCRATCH=""
touch "$SYMS_TIER2_GOOD"

# Check all-resolved FIRST, independent of tree presence.  If Tier-1 resolved
# every symbol, TIER2_STATUS stays "not-needed" regardless of whether
# the linux-linus source tree exists.  Testing [ -d "$LINUS_UAPI" ] first would route a
# fully-resolved run on a tree-absent box into "skipped: linus tree absent",
# which causes the ratchet case to skip tier1_floor enforcement entirely —
# the stated intent at the not-needed case comment (lines below) is the opposite.
if [ ! -s "$SYMS_BAD" ]; then
    TIER2_STATUS="not-needed"   # all symbols resolved by Tier-1; tree presence irrelevant
elif [ -n "$LINUS_UAPI" ] && [ -d "$LINUS_UAPI" ]; then
    # Produce a sanitized uapi export via headers_install.  The raw source
    # tree's include/uapi pulls in kernel-internal headers (e.g. linux/compiler.h
    # via linux/if.h) that are not present under uapi/ and cause every
    # translation unit to die with a fatal error before a single symbol is
    # evaluated.  headers_install strips those internal dependencies.
    #
    # Cache the installed headers under XDG_CACHE_HOME keyed by the linus
    # revision so repeated runs skip the cold make invocation.  A hook or a
    # rebase exec exports GIT_DIR and friends, which would make git answer
    # for the caller's repository and key the cache on the wrong revision.
    LINUS_HASH=$(env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE \
                     -u GIT_OBJECT_DIRECTORY -u GIT_COMMON_DIR -u GIT_PREFIX \
                     git -C "$LINUS_SRC" rev-parse --short HEAD 2>/dev/null || true)
    LINUS_HDR_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/trinity/linus-hdrs-${LINUS_HASH}"

    if [ -n "$LINUS_HASH" ] && [ -f "$LINUS_HDR_CACHE/include/linux/version.h" ]; then
        # Cache hit: reuse previously-built headers; skip make entirely.
        HDR_INSTALL="$LINUS_HDR_CACHE"
        trap 'rm -rf "$WORKDIR"' EXIT
    else
        HDR_INSTALL=$(mktemp -d /tmp/linus-hdrs-XXXXXX)
        BUILD_SCRATCH=$(mktemp -d /tmp/trinity-linus-build-XXXXXX)
        trap 'rm -rf "$WORKDIR" "$HDR_INSTALL" "$BUILD_SCRATCH" "$HDR_SENTINEL"' EXIT
        HDR_SENTINEL=$(mktemp "$LINUS_SRC/.hdr-sentinel-XXXXXX")
        if ! make -C "$LINUS_SRC" O="$BUILD_SCRATCH" headers_install \
                 INSTALL_HDR_PATH="$HDR_INSTALL" -j"$(nproc)" 2>/dev/null; then
            echo "WARN: $NAME: Tier 2 skipped: headers_install failed" >&2
            TIER2_STATUS="skipped: headers_install failed"
            rm -rf "$HDR_INSTALL" "$BUILD_SCRATCH"
            HDR_INSTALL=""
            BUILD_SCRATCH=""
        elif [ -n "$LINUS_HASH" ]; then
            # Populate cache for future runs (best-effort; failure is non-fatal)
            mkdir -p "$(dirname "$LINUS_HDR_CACHE")" 2>/dev/null &&
                cp -a "$HDR_INSTALL/." "$LINUS_HDR_CACHE" 2>/dev/null || true
        fi
        # mtime probe: any source-tree file newer than the sentinel that
        # was touched by headers_install is litter.  Covers scripts/,
        # include/generated/, and usr/ -- all directories headers_install
        # may write into when O= is not honoured.  The sentinel lives in
        # $LINUS_SRC (same filesystem as the probed paths) so cross-fs
        # timestamp granularity skew cannot cause misses; it is removed
        # by the EXIT trap.
        _litter=""
        for _dir in scripts include/generated usr; do
            _abs="$LINUS_SRC/$_dir"
            [ -d "$_abs" ] || continue
            _litter="${_litter}${_litter:+$'\n'}$(find "$_abs" -newer "$HDR_SENTINEL" 2>/dev/null)"
        done
        if [ -n "$_litter" ]; then
            _shown=$(printf '%s\n' "$_litter" | head -20 | tr '\n' ' ')
            echo "FAIL: $NAME: headers_install wrote into source tree: ${_shown}"
            exit 1
        fi
    fi
else
    TIER2_STATUS="skipped: linus tree absent"
fi

if [ -n "$HDR_INSTALL" ] && [ -s "$SYMS_BAD" ]; then
    LINUS_HDR_INC="$HDR_INSTALL/include"

    # Build a PCH using the sanitized installed uapi headers (read-only).
    PCH_HDR2="$WORKDIR/uapi-probe-linus.h"
    {
        echo '#include <stdio.h>'
        echo '#include <stdint.h>'
        echo '#include <stdbool.h>'
        for h in \
            linux/xfrm.h linux/nl80211.h linux/neighbour.h linux/if_tunnel.h \
            linux/if_link.h linux/if_addr.h linux/if_arp.h linux/if_bridge.h \
            linux/if_ether.h linux/if_tun.h linux/socket.h linux/in.h linux/in6.h \
            linux/ip.h linux/ipv6.h linux/tcp.h linux/udp.h linux/sctp.h \
            linux/dccp.h linux/rtnetlink.h linux/genetlink.h linux/veth.h \
            linux/netfilter/nf_tables.h linux/netfilter/nfnetlink_conntrack.h \
            linux/netfilter/ipset/ip_set.h linux/prctl.h linux/capability.h \
            linux/mman.h linux/futex.h linux/fcntl.h linux/sched.h \
            linux/perf_event.h linux/io_uring.h linux/bpf.h linux/landlock.h \
            linux/lsm.h linux/batman_adv.h linux/dpll.h linux/thermal.h \
            linux/vdpa.h linux/ovpn.h linux/nbd-netlink.h linux/net_dropmon.h \
            linux/net_shaper.h linux/nfsd_netlink.h linux/ioprio.h linux/nfc.h \
            linux/psample.h linux/psp-dbc.h linux/psp-sev.h \
            linux/ethtool_netlink.h linux/hw_breakpoint.h \
            linux/pkt_sched.h linux/pkt_cls.h linux/fib_rules.h linux/devlink.h \
            linux/dcbnl.h linux/netlink.h linux/netfilter/nfnetlink_log.h \
            linux/netfilter/nfnetlink_queue.h linux/tc_act/tc_mirred.h \
            linux/netfilter/nf_tables_compat.h \
            linux/userfaultfd.h linux/nsfs.h linux/nexthop.h \
            linux/blkdev.h linux/ublk_cmd.h linux/vfio.h \
            linux/openvswitch.h linux/mount.h linux/pidfd.h; do
            if [ -f "$LINUS_HDR_INC/$h" ] || [ -f "/usr/include/$h" ]; then
                echo "#include <$h>"
            fi
        done
    } > "$PCH_HDR2"
    gcc -w -x c-header \
        -I"$LINUS_HDR_INC" \
        -o "${PCH_HDR2}.gch" "$PCH_HDR2" 2>/dev/null || true

    BATCH2_DIR="$WORKDIR/batches2"
    mkdir -p "$BATCH2_DIR"
    split -l 100 "$SYMS_BAD" "$BATCH2_DIR/batch-"

    # Compile the batches in parallel, as Tier 1 does.  A batch spends its time
    # in gcc's did-you-mean search for each undeclared symbol, about 20ms
    # apiece, which made one batch after another the longest step of the whole
    # gate.  Each leaves its exit status next to its diagnostics, so the
    # inspection below can still tell the batches apart.
    batches=("$BATCH2_DIR"/batch-*)
    for batch in "${batches[@]}"; do
        [ -f "$batch" ] || continue
        bname=$(basename "$batch")
        {
            echo 'int main(void){'
            awk '{printf "printf(\"%%d %%s\\n\",(int)%s,\"%s\");\n", $1, $1}' "$batch"
            echo 'return 0;}'
        } > "$BATCH2_DIR/${bname}.c"
        (
            gcc -w -fmax-errors=200 \
                -I"$LINUS_HDR_INC" \
                -include "$PCH_HDR2" \
                -o "$BATCH2_DIR/${bname}.out" "$BATCH2_DIR/${bname}.c" \
                2>"$BATCH2_DIR/${bname}.err"
            echo $? > "$BATCH2_DIR/${bname}.rc"
        ) &
    done
    wait

    # A batch that exits non-zero with a 'fatal error:' line (even alongside
    # undeclared-identifier diagnostics) did not fully evaluate its symbols;
    # those symbols must remain unresolved rather than be silently counted as
    # resolved.
    TIER2_OK=0
    FATAL_SYMS="$WORKDIR/tier2-fatal-syms.txt"
    touch "$FATAL_SYMS"

    for batch in "${batches[@]}"; do
        [ -f "$batch" ] || continue
        bname=$(basename "$batch")
        batch_exit=$(< "$BATCH2_DIR/${bname}.rc")
        if [ "$batch_exit" -ne 0 ]; then
            # A 'fatal error:' means the compiler stopped mid-translation-unit;
            # symbols after the cutoff were never evaluated.  Treat any non-zero
            # exit that carries a fatal error as a full batch failure regardless
            # of whether undeclared-identifier diagnostics were also emitted.
            if grep -q 'fatal error:' "$BATCH2_DIR/${bname}.err" || \
               ! extract_bad_syms "$BATCH2_DIR/${bname}.err" | grep -q .; then
                echo "WARN: $NAME: Tier 2 batch $bname fatal compile error; symbols remain unresolved" >&2
                cat "$batch" >> "$FATAL_SYMS"
                continue
            fi
        fi
        TIER2_OK=$((TIER2_OK + 1))
    done

    if [ $TIER2_OK -eq 0 ]; then
        echo "WARN: $NAME: Tier 2 (linux-linus) all batches failed with fatal errors; SYMS_BAD unchanged" >&2
        TIER2_STATUS="skipped: all batches fatal"
    else
        # Collect still-bad symbols: undeclared from successful batches PLUS
        # all symbols from fatally-failed batches (those must stay bad).
        SYMS_BAD2="$WORKDIR/syms-bad2.txt"
        {
            extract_bad_syms "$BATCH2_DIR"/*.err 2>/dev/null
            cat "$FATAL_SYMS"
        } | sort -u > "$SYMS_BAD2"

        # Tier 2 good = previously bad minus still-bad (both files are sorted)
        comm -23 "$SYMS_BAD" "$SYMS_BAD2" > "$SYMS_TIER2_GOOD"

        # Safe to update SYMS_BAD now: Tier 2 ran at least one batch successfully
        cp "$SYMS_BAD2" "$SYMS_BAD"

        TIER2_RESOLVED=$(wc -l < "$SYMS_TIER2_GOOD" | tr -d ' ')
        if [ -n "$LINUS_HASH" ]; then
            TIER2_STATUS="ran($TIER2_RESOLVED,oracle=$LINUS_HASH)"
        else
            TIER2_STATUS="ran($TIER2_RESOLVED)"
        fi

        if [ -s "$SYMS_TIER2_GOOD" ]; then
            # Build and run a final binary for Tier 2 symbols; append to compiler table
            FINAL_C2="$WORKDIR/final-probe2.c"
            FINAL_BIN2="$WORKDIR/final-probe2"
            FINAL_ERR2="$WORKDIR/final-probe2.err"
            {
                echo 'int main(void){'
                value_statements "$SYMS_TIER2_GOOD"
                echo 'return 0;}'
            } > "$FINAL_C2"
            if gcc -w -I"$LINUS_HDR_INC" \
                   -include "$PCH_HDR2" \
                   -o "$FINAL_BIN2" "$FINAL_C2" 2>"$FINAL_ERR2"; then
                # Append Tier 2 authoritative values to the shared compiler table
                "$FINAL_BIN2" >> "$COMPILER_RAW" 2>/dev/null
            fi
        fi
    fi
fi

# The probes report a constant that needs more than 32 bits on a second line,
# "W SYM HEX".  Those lines are a table of their own, which the text lookup and
# the per-header probe add to, so that the compiler table stays one "VALUE SYM"
# line per symbol.
grep -v '^W ' "$COMPILER_RAW" > "$COMPILER_TABLE"
sed -n 's/^W //p' "$COMPILER_RAW" > "$WIDE_TABLE"

# ---------------------------------------------------------------------------
# Step 4c: Tier 2 text -- macros no probe header declares
# The probe sets are finite, so a symbol whose header is in none of them is
# checked by nothing.  SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW sat at the wrong
# value that way: linux/vm_sockets.h is in neither set.  A macro does not need
# a compiler to be read, though.  When Tier 2 ran, every symbol still
# unresolved is looked up as a "#define SYM <value>" in the headers the kernel
# tree installed, and the value found is compared like a compiler's.  The
# installed copy is read rather than include/uapi because headers_install has
# already dropped the __KERNEL__ halves and added the host architecture's asm/
# headers, which is what userspace is built against.
#
# Only a reading that cannot be wrong is used.  A value is an integer literal
# (decimal, hex or octal, signed, with or without a U or L suffix) or a
# single-bit shift, the shapes the harvest reads from the tree.  A symbol
# with any other definition (another macro, an expression) or with two that
# disagree stays unresolved: a wrong accusation against a correct shim costs
# more than the check is worth.  Enum members are not macros and stay
# unresolved too; only a compile probe sees them (Step 4d).
#
# A literal that needs more than 32 bits keeps all 64, as in a compiler probe
# (value_statements).  There is no compiler to give it a type, so the type is
# read off the spelling the way C does: 8 bytes for an L in the suffix, or for
# more bits than the 4-byte types hold, which are int for a decimal without a
# suffix and unsigned int for the rest.
# ---------------------------------------------------------------------------
TEXT_OBS="$WORKDIR/text-obs.txt"
TEXT_TABLE="$WORKDIR/text-table.txt"
TEXT_VERIFIED=0
TEXT_RAN=0
: > "$TEXT_TABLE"
case "$TIER2_STATUS" in
ran*)
    if [ -s "$SYMS_BAD" ]; then
        TEXT_RAN=1
        # "SYM VALUE FILE WIDE" for every object-like #define of an ALL_CAPS
        # name: VALUE is a signed 32-bit decimal as in the compiler table, or
        # ? for a definition of any other shape, and WIDE the 64 bits in hex
        # of a constant that has an 8-byte type and needs them, - for any
        # other.  Deciding per symbol is left to awk below, so that xargs
        # cannot split a symbol's definitions between two perl processes.
        if ! (set -o pipefail
              find "$HDR_INSTALL/include" -name '*.h' | sort | \
              xargs perl -0777 -ne '
	# The value, and whether the constant has an 8-byte type: an L in the
	# suffix, or more bits than the 4-byte types hold (int for a decimal
	# without a suffix, unsigned int for the rest).
	sub ev {
		my $r = shift;
		$r =~ s/^\s+|\s+$//g;
		while ($r =~ /^(\((?:[^()]++|(?1))*\))$/) {
			$r = substr($1, 1, -1);
			$r =~ s/^\s+|\s+$//g;
		}
		if ($r =~ /^(-?)\s*(0[xX][0-9a-fA-F]{1,16}|0[0-7]*|[1-9][0-9]{0,18})([uUlL]*)$/) {
			my ($neg, $n, $suf) = ($1, $2, $3);
			my $unsigned = $n =~ /^0/ || $suf =~ /[uU]/;
			$n = $n =~ /^0[xX]/ ? hex($n) : $n =~ /^0/ ? oct($n) : $n + 0;
			return undef if $neg && $n > 0x7FFFFFFFFFFFFFFF;
			return ($neg ? -$n : $n, $suf =~ /[lL]/ || $n > ($unsigned ? 0xFFFFFFFF : 0x7FFFFFFF));
		}
		if ($r =~ /^(?:\(((?:__u\d+|unsigned long long|unsigned long|unsigned int|unsigned|int|long))\)\s*)?1([uUlL]*)\s*<<\s*(0[xX][0-9a-fA-F]{1,2}|[0-9]{1,2})$/) {
			my ($type, $suf, $sh) = ($1 // "", $2, $3);
			$sh = hex($sh) if $sh =~ /^0[xX]/;
			return undef if $sh > 63;
			return (1 << $sh, $suf =~ /[lL]/ || $type =~ /^(?:__u64|unsigned long long|unsigned long|long)$/);
		}
		return undef;
	}
	s{/\*.*?\*/}{ }gs; s{//[^\n]*}{}g; s{\\\n}{ }g;
	while (m{^[ \t]*\#[ \t]*define[ \t]+([A-Z][A-Z0-9_]+)(?:[ \t]+([^\n]*?))?[ \t]*$}gm) {
		my ($sym, $rhs) = ($1, $2);
		my ($v, $big) = defined $rhs ? ev($rhs) : ();
		my $w = "-";
		if (defined $v) {
			my $u = $v & 0xFFFFFFFFFFFFFFFF;
			$w = sprintf("%016x", $u) if $big && $u > 0xFFFFFFFF;
			$v &= 0xFFFFFFFF;
			$v -= 4294967296 if $v >= 2147483648;
		}
		printf("%s %s %s %s\n", $sym, defined $v ? $v : "?", $ARGV, $w);
	}' > "$TEXT_OBS"); then
            echo "FAIL: $NAME: Tier-2 text scan of $HDR_INSTALL/include failed"
            exit 1
        fi
        awk -v want_file="$SYMS_BAD" -v root="$HDR_INSTALL/include" \
            -v wide_out="$WIDE_TABLE" '
            FILENAME == want_file { want[$1]; next }
            !($1 in want) { next }
            $2 == "?" { bad[$1]; next }
            !($1 in val) { val[$1] = $2; src[$1] = $3; wid[$1] = $4; next }
            val[$1] != $2 || wid[$1] != $4 { bad[$1] }
            END {
                for (s in val) {
                    if (s in bad)
                        continue
                    f = src[s]
                    if (index(f, root "/") == 1)
                        f = substr(f, length(root) + 2)
                    print val[s], s, f
                    if (wid[s] != "-")
                        print s, wid[s] >> wide_out
                }
            }
        ' "$SYMS_BAD" "$TEXT_OBS" | sort -k2 > "$TEXT_TABLE"

        # A symbol read from text leaves the unresolved set.
        cut -d' ' -f2 "$TEXT_TABLE" | sort -u > "$WORKDIR/syms-text.txt"
        comm -23 "$SYMS_BAD" "$WORKDIR/syms-text.txt" > "$WORKDIR/syms-bad-text.txt"
        cp "$WORKDIR/syms-bad-text.txt" "$SYMS_BAD"
        TEXT_VERIFIED=$(wc -l < "$TEXT_TABLE" | tr -d ' ')
    fi
    ;;
esac

# ---------------------------------------------------------------------------
# Step 4d: Tier 2 per-header probe -- enumerators and expression macros
# What is unresolved here is what neither step above can see.  The text lookup
# reads a literal, and an enum member, or a macro defined as an expression or
# as another macro, is not one.  The compile probes see such a symbol only if
# its header is in the probe set, and some headers cannot join it: they
# redefine each other's types or need an include of their own first.  Given a
# translation unit to itself a header evaluates like any other, so when Tier 2
# ran, every installed header that names a symbol still unresolved is compiled
# alone against those symbols.  What the header declares is compared like a
# compiler's value; a symbol it only mentions (in a comment, as a macro
# argument) is undeclared there and stays unresolved.
#
# Most uapi headers are self-contained.  The few that are not are retried
# behind the includes of HDR_PRELUDES, a rung at a time, and a header no rung
# compiles (xen/'s need headers that are not uapi) leaves its symbols
# unresolved.  So does a symbol two headers evaluate differently, in its 32 bits
# or in the 64 of a constant that needs them, since nothing says which one the
# shim follows.
#
# This reads the headers the Tier-2 tree installed, like the text lookup, so it
# runs only when TRINITY_LINUS_SRC is set: the default run pays nothing for it.
# ---------------------------------------------------------------------------
HDR_PRELUDES=("" "linux/types.h" "stdint.h sys/socket.h linux/types.h")
HDR_OBS="$WORKDIR/hdr-obs.txt"
HDR_TABLE="$WORKDIR/hdr-table.txt"
HDR_DIR="$WORKDIR/hdr-probe"
HDR_VERIFIED=0
HDR_RAN=0
: > "$HDR_TABLE"

# write_hdr_probe PRELUDE HEADER SYMFILE: a program that includes the prelude
# and HEADER, in that order, and reports the value of each symbol in SYMFILE
# the way value_statements does.
write_hdr_probe() {
    local inc
    echo '#include <stdio.h>'
    for inc in $1; do echo "#include <$inc>"; done
    echo "#include <$2>"
    echo 'int main(void){'
    value_statements "$3"
    echo 'return 0;}'
}

# probe_hdr ID: evaluate hdr-probe/ID.syms against the header named in
# hdr-probe/ID.hdr and write "VALUE SYM HEADER WIDE" for each symbol it
# declares to hdr-probe/ID.tbl, WIDE being the 64 bits of a constant that
# needs them and - for any other.  The first rung of HDR_PRELUDES whose compile
# reports nothing but undeclared symbols decides; any other error is the header
# failing to compile there, and none of its symbols was evaluated.
probe_hdr() {
    local p="$HDR_DIR/$1" hdr prelude
    hdr=$(< "$p.hdr")
    for prelude in "${HDR_PRELUDES[@]}"; do
        write_hdr_probe "$prelude" "$hdr" "$p.syms" > "$p.c"
        LC_ALL=C gcc -w -fsyntax-only -fmax-errors=0 -I"$HDR_INSTALL/include" \
            "$p.c" 2> "$p.err"
        if grep 'error:' "$p.err" | grep -qvE "error: '[A-Za-z0-9_]+' undeclared"; then
            continue
        fi
        extract_bad_syms "$p.err" > "$p.bad"
        grep -vxFf "$p.bad" "$p.syms" > "$p.good"
        [ -s "$p.good" ] || return 0
        write_hdr_probe "$prelude" "$hdr" "$p.good" > "$p.c"
        if LC_ALL=C gcc -w -I"$HDR_INSTALL/include" -o "$p.bin" "$p.c" 2> "$p.err"; then
            "$p.bin" | awk -v h="$hdr" '
                $1 == "W" { wide[$2] = $3; next }
                { val[$2] = $1 }
                END {
                    for (s in val)
                        print val[s], s, h, (s in wide ? wide[s] : "-")
                }
            ' > "$p.tbl"
            return 0
        fi
    done
}

case "$TIER2_STATUS" in
ran*)
    if [ -s "$SYMS_BAD" ]; then
        HDR_RAN=1
        mkdir -p "$HDR_DIR"
        # "SYM FILE" for every installed header that names a symbol still
        # unresolved, in any role: only the compiler can tell a declaration
        # from a mention.
        if ! (set -o pipefail
              find "$HDR_INSTALL/include" -name '*.h' | sort | \
              SHIM_WANT="$SYMS_BAD" xargs perl -0777 -ne '
		BEGIN {
			open(my $w, "<", $ENV{SHIM_WANT}) or die "$ENV{SHIM_WANT}: $!";
			local $/ = "\n";
			chomp(my @s = <$w>);
			@want{@s} = ();
		}
		my %seen;
		$seen{$1} = 1 while /\b([A-Z][A-Z0-9_]+)\b/g;
		print "$_ $ARGV\n" for grep { exists $want{$_} } sort keys %seen;' \
              > "$HDR_OBS"); then
            echo "FAIL: $NAME: Tier-2 header scan of $HDR_INSTALL/include failed"
            exit 1
        fi
        # One id per header, in path order, with its path and its symbols.
        awk -v dir="$HDR_DIR" -v root="$HDR_INSTALL/include/" '
            {
                h = substr($2, length(root) + 1)
                if (!(h in id)) {
                    id[h] = sprintf("%04d", ++n)
                    print h > (dir "/" id[h] ".hdr")
                    print id[h] > (dir "/ids")
                }
                print $1 > (dir "/" id[h] ".syms")
            }
        ' "$HDR_OBS"
        if [ -s "$HDR_DIR/ids" ]; then
            njobs=$(nproc 2>/dev/null || echo 4)
            while read -r id; do
                probe_hdr "$id" &
                while [ "$(jobs -rp | wc -l)" -ge "$njobs" ]; do wait -n; done
            done < "$HDR_DIR/ids"
            wait
        fi
        # "VALUE SYM HEADER": the header that sorts first among those that
        # agree on the value, and on its 64 bits where it has them.  Those go
        # to the wide table.
        find "$HDR_DIR" -name '*.tbl' -exec cat {} + | sort -k3,3 -k2,2 | \
            awk -v wide_out="$WIDE_TABLE" '
            !($2 in val) { val[$2] = $1; src[$2] = $3; wid[$2] = $4; next }
            val[$2] != $1 || wid[$2] != $4 { bad[$2] }
            END {
                for (s in val) {
                    if (s in bad)
                        continue
                    print val[s], s, src[s]
                    if (wid[s] != "-")
                        print s, wid[s] >> wide_out
                }
            }
        ' | sort -k2 > "$HDR_TABLE"

        # A symbol evaluated here leaves the unresolved set.
        cut -d' ' -f2 "$HDR_TABLE" | sort -u > "$WORKDIR/syms-hdr.txt"
        comm -23 "$SYMS_BAD" "$WORKDIR/syms-hdr.txt" > "$WORKDIR/syms-bad-hdr.txt"
        cp "$WORKDIR/syms-bad-hdr.txt" "$SYMS_BAD"
        HDR_VERIFIED=$(wc -l < "$HDR_TABLE" | tr -d ' ')
    fi
    ;;
esac

# ---------------------------------------------------------------------------
# Unresolved-uapi reporting
# After both tiers, the text lookup and the per-header probe, a symbol still
# unresolved is either trinity's own or a constant no installed uapi header
# declares: newer or older than the tree, from a kernel-internal header, or a
# header no probe compiles.  Neither is a FAIL, because there is nothing to
# compare the second kind against.  It is also a large standing property of
# the tree, and a line per symbol would drown the FAIL lines, so it is
# reported as one count.
# UAPI_SHIM_VALUES_LIST=1 names the uapi-shaped symbols.
#
# "uapi-shaped" is ALL_CAPS with an underscore that no known-private prefix
# claims.  Everything else unresolved is only counted (not-uapi-shaped): the
# prefixes below, and names with no underscore, a few of which are real
# constants (CLOCKFD).  The prefixes are namespaces trinity owns:
#   TRINITY_ NR_ MAX_ MIN_ DEFAULT_ __NR_   bookkeeping names
#   HAVE_ USE_                              configure and per-syscall switches
#   TAINT_                                  kernel taint bit numbers
#   GROUP_ RET_                             syscall group and return enums
#   _FUZZ_ (anywhere)                       ioctl generator tunables
# ---------------------------------------------------------------------------
KNOWN_MISSING_RE='^(TRINITY_|NR_|MAX_|MIN_|DEFAULT_|__NR_|HAVE_|USE_|TAINT_|GROUP_|RET_)|_FUZZ_'
SYMS_UAPI_SHAPED="$WORKDIR/syms-uapi-shaped.txt"
total_unresolved=$(wc -l < "$SYMS_BAD" | tr -d ' ')
grep -E '_' "$SYMS_BAD" | grep -vE "$KNOWN_MISSING_RE" > "$SYMS_UAPI_SHAPED" || true
unresolved_uapi_count=$(wc -l < "$SYMS_UAPI_SHAPED" | tr -d ' ')
not_uapi_shaped_count=$((total_unresolved - unresolved_uapi_count))
if [ "$unresolved_uapi_count" -gt 0 ]; then
    echo "WARN: $NAME: $unresolved_uapi_count uapi-shaped symbol(s) unresolved by any probe," \
         "values unchecked ($not_uapi_shaped_count more are not uapi-shaped: a known-private" \
         "prefix or no underscore; UAPI_SHIM_VALUES_LIST=1 names the uapi-shaped ones)" >&2
    if [ -n "${UAPI_SHIM_VALUES_LIST:-}" ]; then
        sed "s/^/WARN: $NAME: unresolved uapi-shaped symbol: /" "$SYMS_UAPI_SHAPED" >&2
    fi
fi

harvested=$(wc -l < "$SYMS_ALL")
probed=$(wc -l < "$COMPILER_TABLE")

# ---------------------------------------------------------------------------
# Coverage ratchet: probed must not drop below the stored floor.
#
# The floor is a single integer in scripts/check-static/uapi-shim-probed-floor.baseline.
# It represents the minimum acceptable count of compiler-verified symbols.
#
# To legitimately lower the floor (e.g. after removing headers or dead shims):
#   1. Confirm the reduction is intentional (symbols removed, not just broken).
#   2. Edit the baseline file manually to the new minimum.
#   3. Add a comment in the same commit explaining the reason.
# Do NOT lower the floor to paper over a probe regression.
# ---------------------------------------------------------------------------
probed_floor=0
if [ -f "$PROBED_FLOOR_FILE" ]; then
    probed_floor=$(grep -oE '^[0-9]+' "$PROBED_FLOOR_FILE" | head -1 || true)
    probed_floor=${probed_floor:-0}
fi

if [ "$probed_floor" -eq 0 ]; then
    echo "FAIL: $NAME: probed floor is unseeded (uapi-shim-probed-floor.baseline contains 0)"
    echo "FAIL: $NAME: seed it with a real observed probed count before enabling the ratchet"
    exit 1
fi

tier1_floor=0
if [ -f "$TIER1_FLOOR_FILE" ]; then
    tier1_floor=$(grep -oE '^[0-9]+' "$TIER1_FLOOR_FILE" | head -1 || true)
    tier1_floor=${tier1_floor:-0}
fi

if [ "$tier1_floor" -eq 0 ]; then
    echo "FAIL: $NAME: tier-1 probed floor is unseeded (uapi-shim-tier1-probed-floor.baseline contains 0)"
    echo "FAIL: $NAME: seed it with a real observed Tier-1 probed count before enabling the ratchet"
    exit 1
fi

if [ "$probed_floor" -lt "$tier1_floor" ]; then
    echo "FAIL: $NAME: probed_floor ($probed_floor) < tier1_floor ($tier1_floor) — Tier-2 floor must be >= Tier-1 floor"
    exit 1
fi

text_floor=0
if [ -f "$TEXT_FLOOR_FILE" ]; then
    text_floor=$(grep -oE '^[0-9]+' "$TEXT_FLOOR_FILE" | head -1 || true)
    text_floor=${text_floor:-0}
fi

if [ "$text_floor" -eq 0 ]; then
    echo "FAIL: $NAME: text floor is unseeded (uapi-shim-text-floor.baseline contains 0 or is missing)"
    echo "FAIL: $NAME: seed it with a real observed text-verified count before enabling the ratchet"
    exit 1
fi

hdr_floor=0
if [ -f "$HDR_FLOOR_FILE" ]; then
    hdr_floor=$(grep -oE '^[0-9]+' "$HDR_FLOOR_FILE" | head -1 || true)
    hdr_floor=${hdr_floor:-0}
fi

if [ "$hdr_floor" -eq 0 ]; then
    echo "FAIL: $NAME: hdr floor is unseeded (uapi-shim-hdr-floor.baseline contains 0 or is missing)"
    echo "FAIL: $NAME: seed it with a real observed hdr-verified count before enabling the ratchet"
    exit 1
fi

# Tier-2 breakage states: the linus tree was present and Tier-2 was entered
# but failed to produce usable output.  These are not environment differences --
# they indicate a broken build environment or a regressed probe path.  Fail
# immediately so the breakage is visible rather than silently skipped.
case "$TIER2_STATUS" in
"skipped: headers_install failed"|"skipped: all batches fatal")
    echo "FAIL: $NAME: Tier-2 attempted but failed (tier2=$TIER2_STATUS)"
    exit 1
    ;;
esac

if [ "$probed" -eq 0 ]; then
    echo "FAIL: $NAME: coverage ratchet: probe binary produced no output (probed=0)"
    exit 1
fi
# Two-floor coverage ratchet:
#
#   not-needed   Tier-1 resolved all symbols; Tier-2 was never entered.
#                Enforce the Tier-1-only floor (TIER1_FLOOR_FILE) so that
#                fully-resolved runs are ratcheted even without a linus tree.
#
#   ran*         Tier-2 ran and augmented Tier-1 results.  Enforce the
#                Tier-2-inclusive floor (PROBED_FLOOR_FILE), and, when the
#                text lookup or the per-header probe had symbols to
#                resolve, the count each verified (TEXT_FLOOR_FILE,
#                HDR_FLOOR_FILE).
#
#   skipped: linus tree absent
#                Genuine environment difference; skip both floors.
case "$TIER2_STATUS" in
ran*)
    if [ "$probed" -lt "$probed_floor" ]; then
        echo "FAIL: $NAME: coverage ratchet: probed $probed < floor $probed_floor"
        exit 1
    fi
    if [ "$TEXT_RAN" -eq 1 ] && [ "$TEXT_VERIFIED" -lt "$text_floor" ]; then
        echo "FAIL: $NAME: coverage ratchet: text-verified $TEXT_VERIFIED < text_floor $text_floor"
        exit 1
    fi
    if [ "$HDR_RAN" -eq 1 ] && [ "$HDR_VERIFIED" -lt "$hdr_floor" ]; then
        echo "FAIL: $NAME: coverage ratchet: hdr-verified $HDR_VERIFIED < hdr_floor $hdr_floor"
        exit 1
    fi
    ;;
not-needed)
    if [ "$probed" -lt "$tier1_floor" ]; then
        echo "FAIL: $NAME: coverage ratchet: probed $probed < tier1_floor $tier1_floor"
        exit 1
    fi
    ;;
"skipped: linus tree absent")
    echo "  $NAME: coverage ratchet skipped (tier2=$TIER2_STATUS; probed $probed is Tier-1 only)" >&2
    ;;
*)
    echo "FAIL: $NAME: unknown TIER2_STATUS '$TIER2_STATUS'"
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# Step 5: Compare trinity values against compiler values
# For each compiler-resolvable symbol, every occurrence in the harvest must
# carry the compiler's authoritative value, for each symbol read from header
# text (Step 4c) the value that text gives, and for each one a header was
# compiled for (Step 4d) the value that compile gives.
#
# Normalisation: both sides are converted to signed 32-bit integer to match
# what the probe C code does ((int)SYM via printf("%d",...)).  This means:
#   0x80000000 == -2147483648 (32-bit sign-extension)
#   0xffffffffffffffff == -1 (upper 32 bits masked, lower 32 signed)
#   02000000 (octal) == 524288 (octal parsed, decimal compared)
# That is deliberate: a 32-bit unsigned spelling is the same constant as the
# signed value the header gives it, and 0xffffffff has to match -1.
#
# A constant that needs more than 32 bits is the exception.  value_statements
# gives such a symbol a "W SYM HEX" line, and its shim is compared on all 64
# bits (two's complement), where the int32 view would see nothing but the low
# half: CLONE_NNP and CLONE_AUTOREAP are both 0 there.
#
# Performance: a single awk pass over both files avoids O(N*M) shell overhead.
# ---------------------------------------------------------------------------
MISMATCH_FILE="$WORKDIR/mismatches.txt"

awk -v harvest_file="$HARVEST" -v wide_file="$WIDE_TABLE" \
    -v text_file="$TEXT_TABLE" -v hdr_file="$HDR_TABLE" '
# Return numeric value of a single hex digit character (0-9, a-f, A-F)
function hd(c) {
    return (c >= "0" && c <= "9") ? (c + 0) : (index("0123456789abcdef", tolower(c)) - 1)
}
# Parse a hex, octal or decimal literal (a decimal one may be negative) as a
# 64-bit value, wrapping modulo 2^64 like the compiler, left in P_HI and P_LO.
# The halves stay below 2^32, so that every step is exact in an awk double,
# which a decimal above 2^53 would not be.
function parse64(s,   neg, radix, i, carry) {
    neg = (s ~ /^-/)
    if (neg) s = substr(s, 2)
    if (s ~ /^0[xX]/) { radix = 16; s = substr(s, 3) }
    else if (s ~ /^0[0-7]+$/) { radix = 8; s = substr(s, 2) }
    else radix = 10
    P_HI = 0; P_LO = 0
    for (i = 1; i <= length(s); i++) {
        P_LO = P_LO * radix + hd(substr(s, i, 1))
        carry = int(P_LO / 4294967296)
        P_LO -= carry * 4294967296
        P_HI = (P_HI * radix + carry) % 4294967296
    }
    if (neg) {
        P_LO = 4294967296 - P_LO
        P_HI = 4294967295 - P_HI
        if (P_LO == 4294967296) { P_LO = 0; P_HI = (P_HI + 1) % 4294967296 }
    }
}
# The low 32 bits of a literal, as a signed int: what (int) makes of it.
function int32(s,   v) {
    parse64(s)
    v = P_LO
    if (v >= 2147483648) v -= 4294967296
    return v
}
# Eight hex digits for a number below 2^32.
function hex8(x,   s, i) {
    s = ""
    for (i = 0; i < 8; i++) {
        s = substr("0123456789abcdef", x % 16 + 1, 1) s
        x = int(x / 16)
    }
    return s
}
BEGIN { fail = 0; checked = 0; checked_text = 0; checked_hdr = 0; checked_wide = 0 }
# Pass 1: load harvest into memory (SYM -> space-separated list of values),
# then the symbols that need 64 bits (SYM -> HEX).
# Use FILENAME == harvest_file rather than the FNR == NR idiom: if the harvest
# file is empty awk never emits a record for it, so when the first record of
# the compiler table arrives both FNR and NR are 1, causing that record to be
# misidentified as pass-1 data and loaded into harvest[] instead of checked.
FILENAME == harvest_file {
    sym = $1; val = $2
    harvest[sym] = (sym in harvest) ? harvest[sym] " " val : val
    next
}
FILENAME == wide_file { wide[$1] = $2; next }
# Pass 2: process the compiler table (format: DECIMAL_VALUE SYM), then the
# text and header tables (DECIMAL_VALUE SYM FILE), counting them apart.
{
    compiler_val = int($1)
    sym = $2
    if (!(sym in harvest)) next  # not a trinity shim -- skip
    if (FILENAME == text_file) {
        checked_text++
        source = "installed header " $3
    } else if (FILENAME == hdr_file) {
        checked_hdr++
        source = "compiled with installed header " $3
    } else {
        checked++
        source = "compiler"
    }
    n = split(harvest[sym], tvals)
    if (sym in wide) {
        checked_wide++
        for (i = 1; i <= n; i++) {
            tv = tvals[i]
            parse64(tv)
            have = hex8(P_HI) hex8(P_LO)
            if (have != wide[sym]) {
                fail++
                printf "FAIL: uapi-shim-values: %s shim wrong: have %s (=0x%s), want 0x%s (%s)\n",
                    sym, tv, have, wide[sym], source > "/dev/stderr"
            }
        }
        next
    }
    for (i = 1; i <= n; i++) {
        tv = tvals[i]
        trinity_val = int32(tv)
        if (trinity_val != compiler_val) {
            fail++
            printf "FAIL: uapi-shim-values: %s shim wrong: have %s (=%d), want %d (%s)\n",
                sym, tv, trinity_val, compiler_val, source > "/dev/stderr"
        }
    }
}
END { print fail, checked, checked_text, checked_hdr, checked_wide }
' "$HARVEST" "$WIDE_TABLE" "$COMPILER_TABLE" "$TEXT_TABLE" "$HDR_TABLE" > "$MISMATCH_FILE"

read fail checked checked_text checked_hdr checked_wide < "$MISMATCH_FILE"
fail=${fail:-0}
checked=${checked:-0}
checked_text=${checked_text:-0}
checked_hdr=${checked_hdr:-0}
checked_wide=${checked_wide:-0}

# ---------------------------------------------------------------------------
# Step 6: Baseline cross-check
# Each baseline entry pins a (symbol, expected-compiler-value) record.
# If the compiler now returns a different value, the baseline must be updated.
#
# A baseline symbol that no probe can resolve is skipped, not failed, as long
# as the tree still shims it.  The baseline pins recently added constants
# (XFRMA_IPTFS_* only exist in v6.14+ headers), so on an older build host a
# miss says how old the host is, not that the entry is wrong, and failing on
# it would make the gate's verdict depend on the machine rather than the tree.
# COMPILER_TABLE already holds the Tier-2 values, so an entry a linux-linus
# tree resolves is checked like any other.  Only harvested symbols are probed,
# so an entry missing from the harvest can never be resolved by any host and
# is stale.
# ---------------------------------------------------------------------------
baseline_fail=0
baseline_skipped=0

if [ -f "$BASELINE" ]; then
    while IFS= read -r bline; do
        bline="${bline%%#*}"
        [[ -z "${bline//[[:space:]]/}" ]] && continue
        bsym=$(awk '{print $1}' <<< "$bline")
        bval=$(awk '{print $2}' <<< "$bline")
        [ -z "$bsym" ] || [ -z "$bval" ] && continue

        compiler_dec=$(awk -v s="$bsym" '$2==s{print $1; exit}' "$COMPILER_TABLE")
        if [ -z "$compiler_dec" ]; then
            if grep -qxF "$bsym" "$SYMS_ALL"; then
                echo "SKIP: $NAME: baseline symbol $bsym not resolvable by compiler" \
                     "(tier2=$TIER2_STATUS); value not checked" >&2
                baseline_skipped=$((baseline_skipped + 1))
            else
                echo "FAIL: $NAME: baseline symbol $bsym has no integer #define in" \
                     "the tree, so it is never probed (stale or misspelled entry)" >&2
                baseline_fail=$((baseline_fail + 1))
            fi
            continue
        fi
        bval_dec=$(awk -v val="$bval" 'function hd(c){return (c>="0"&&c<="9")?(c+0):(index("0123456789abcdef",tolower(c))-1)} BEGIN{
            s=val
            if (s ~ /^0[xX]/) {
                s=substr(s,3); if(length(s)>8) s=substr(s,length(s)-7); v=0
                n=length(s); for(i=1;i<=n;i++){v=v*16+hd(substr(s,i,1))}
            } else if (s ~ /^0[0-7]+$/) {
                v=0; n=length(s); for(i=2;i<=n;i++)v=v*8+(substr(s,i,1)+0)
                v=v%4294967296
            } else { v=int(s)+0; if(v<0){v=(v%4294967296)+4294967296} }
            v=v%4294967296; if(v>=2147483648)v-=4294967296; print v}')
        if [ "$compiler_dec" != "$bval_dec" ]; then
            echo "FAIL: $NAME: baseline $bsym: compiler says $compiler_dec," \
                 "baseline says $bval (kernel headers changed? update the baseline)" >&2
            baseline_fail=$((baseline_fail + 1))
        fi
    done < "$BASELINE"
fi

total_fail=$((fail + baseline_fail))
if [ "$total_fail" -gt 0 ]; then
    echo "FAIL: $NAME: $total_fail wrong shim value(s) -- see stderr for details"
    exit 1
fi

# Invariant 1: every harvested symbol is either resolvable, read from header
# text, evaluated in its header or unresolved.  harvested = resolvable
# + text-verified + hdr-verified + total_unresolved; a mismatch indicates a
# bookkeeping bug.
#
# Note: the not-uapi-shaped class (names matching KNOWN_MISSING_RE, or with no
# underscore) is NOT a separate term here.  Those symbols failed the compiler
# probe and therefore live in SYMS_BAD, folded into total_unresolved.  They are
# only split out in the *reporting* step (unresolved-uapi count).
# So the identity is: harvested = resolvable + text-verified + hdr-verified
#                                 + (unresolved-uapi + not-uapi-shaped)
#                   = resolvable + text-verified + hdr-verified
#                                 + total_unresolved  ✓
if [ "$harvested" -ne $((probed + TEXT_VERIFIED + HDR_VERIFIED + total_unresolved)) ]; then
    echo "FAIL: $NAME: invariant broken: harvested $harvested != resolvable $probed + text-verified $TEXT_VERIFIED + hdr-verified $HDR_VERIFIED + unresolved $total_unresolved" >&2
    exit 1
fi

# Invariant 2: every resolvable symbol must have been verified, and so must
# every symbol read from text or evaluated in its header.
# verified (checked) < resolvable (probed) means symbols were silently skipped.
if [ "$checked" -ne "$probed" ]; then
    echo "FAIL: $NAME: invariant broken: verified $checked != resolvable $probed ($((probed - checked)) symbol(s) resolved but not verified)" >&2
    exit 1
fi
if [ "$checked_text" -ne "$TEXT_VERIFIED" ]; then
    echo "FAIL: $NAME: invariant broken: verified from text $checked_text != text-verified $TEXT_VERIFIED" >&2
    exit 1
fi
if [ "$checked_hdr" -ne "$HDR_VERIFIED" ]; then
    echo "FAIL: $NAME: invariant broken: verified from headers $checked_hdr != hdr-verified $HDR_VERIFIED" >&2
    exit 1
fi

case "$TIER1_STATUS" in
    ok) ;;
    *) echo "FAIL: $NAME: unknown TIER1_STATUS '$TIER1_STATUS'" >&2; exit 1 ;;
esac

echo "PASS: $NAME (harvested $harvested / resolvable $probed / verified $checked / text-verified $TEXT_VERIFIED / hdr-verified $HDR_VERIFIED / wide-checked $checked_wide / baseline-skipped $baseline_skipped / unresolved-uapi $unresolved_uapi_count / not-uapi-shaped $not_uapi_shaped_count / tier1=$TIER1_STATUS / tier2=$TIER2_STATUS / ratchet_floor=$probed_floor / tier1_floor=$tier1_floor / text_floor=$text_floor / hdr_floor=$hdr_floor)"
exit 0
