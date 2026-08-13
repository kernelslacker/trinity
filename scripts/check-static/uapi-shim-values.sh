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
# true.  A typo or miscounted enum position compiles clean, links clean, and
# silently encodes the wrong netlink attribute forever.
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
#   3. Compare  -- for every compiler-resolved symbol, every occurrence of
#                  that symbol in trinity's source must carry the compiler's
#                  value.  A mismatch is a FAIL.
#   4. Baseline -- scripts/check-static/uapi-shim-values.baseline pins
#                  specific symbol→value pairs.  Each baseline entry is an
#                  additional cross-check:
#                    * compiler can't resolve the symbol  →  FAIL
#                      (baseline claimed it was a uapi constant)
#                    * compiler value ≠ baseline value    →  FAIL
#                      (kernel headers changed; baseline needs updating)
#
# OVERLAP with netlink-xfrm-attr-shim.sh:
#   That gate checks that every XFRMA_ token *used* in the xfrm generators
#   has a #define fallback.  This gate checks that every such fallback carries
#   the *correct value*.  The two gates are complementary; neither is
#   redundant.

set -u

NAME="uapi-shim-values"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/uapi-shim-values.baseline"
PROBED_FLOOR_FILE="$ROOT/scripts/check-static/uapi-shim-probed-floor.baseline"
TIER1_FLOOR_FILE="$(dirname "$PROBED_FLOOR_FILE")/uapi-shim-tier1-probed-floor.baseline"

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
COMPILER_TABLE="$WORKDIR/compiler-table.txt"
trap 'rm -rf "$WORKDIR"' EXIT

# ---------------------------------------------------------------------------
# Step 1: Harvest
# Collect all "#define SYM <integer>" lines from the tree (excluding scripts/).
# Strip C block/line comments first so commented-out stale values are ignored.
# Decimal and hex values are both captured; stored as-is for normalization
# at comparison time.
# Output: "SYM VALUE" pairs, sorted and uniqued.
# ---------------------------------------------------------------------------
find "$ROOT" -path "$ROOT/scripts" -prune -o \
    \( -name '*.c' -o -name '*.h' \) -print 2>/dev/null | sort | \
  xargs perl -0777 -pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' 2>/dev/null | \
  grep -oE '#[[:space:]]*define[[:space:]]+[A-Z][A-Z0-9_]+[[:space:]]+(0[xX][0-9a-fA-F]+|[0-9]+)([[:space:]]|$)' | \
  sed 's/#[[:space:]]*define[[:space:]]*//' | \
  awk '{print $1, $2}' | sort -u > "$HARVEST"

if [ ! -s "$HARVEST" ]; then
    echo "PASS: $NAME (no shim defines found)"
    exit 0
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

# ---------------------------------------------------------------------------
# Step 4: Final compile and run
# Compile only the good symbols (those resolvable against uapi headers) into
# a final binary and run it to get the authoritative compiler values.
# This compilation should succeed cleanly.
# ---------------------------------------------------------------------------
{
    echo 'int main(void){'
    awk '{printf "printf(\"%%d %%s\\n\",(int)%s,\"%s\");\n", $1, $1}' "$SYMS_GOOD"
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
            awk '{printf "printf(\"%%d %%s\\n\",(int)%s,\"%s\");\n", $1, $1}' "$SYMS_GOOD"
            echo 'return 0;}'
        } > "$FINAL_C"
        gcc -w -include "$PCH_HDR" -o "$FINAL_BIN" "$FINAL_C" 2>"$FINAL_ERR" || true
    fi
fi

if [ ! -x "$FINAL_BIN" ]; then
    echo "WARN: $NAME: compiler probe binary could not be built; skipping value check"
    exit 0
fi

"$FINAL_BIN" > "$COMPILER_TABLE" 2>/dev/null

# ---------------------------------------------------------------------------
# Step 4b: Tier 2 fallback — linux-linus source tree (headers built into scratch tmpdir)
# For symbols that failed to resolve against installed system headers, attempt
# a second compile-probe using ~/src/linux-linus/include/uapi prepended.
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
# If ~/src/linux-linus does not exist the block is skipped silently.
# ---------------------------------------------------------------------------
LINUS_SRC="$HOME/src/linux-linus"
LINUS_UAPI="$LINUS_SRC/include/uapi"
HDR_INSTALL=""
SYMS_TIER2_GOOD="$WORKDIR/syms-tier2-good.txt"
TIER2_STATUS="not-needed"
BUILD_SCRATCH=""
touch "$SYMS_TIER2_GOOD"

if [ -d "$LINUS_UAPI" ] && [ -s "$SYMS_BAD" ]; then
    # Produce a sanitized uapi export via headers_install.  The raw source
    # tree's include/uapi pulls in kernel-internal headers (e.g. linux/compiler.h
    # via linux/if.h) that are not present under uapi/ and cause every
    # translation unit to die with a fatal error before a single symbol is
    # evaluated.  headers_install strips those internal dependencies.
    #
    # Cache the installed headers under XDG_CACHE_HOME keyed by the linus
    # revision so repeated runs skip the cold make invocation.
    LINUS_HASH=$(git -C "$LINUS_SRC" rev-parse --short HEAD 2>/dev/null || true)
    LINUS_HDR_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/trinity/linus-hdrs-${LINUS_HASH}"

    if [ -n "$LINUS_HASH" ] && [ -f "$LINUS_HDR_CACHE/include/linux/version.h" ]; then
        # Cache hit: reuse previously-built headers; skip make entirely.
        HDR_INSTALL="$LINUS_HDR_CACHE"
        trap 'rm -rf "$WORKDIR"' EXIT
    else
        HDR_INSTALL=$(mktemp -d /tmp/linus-hdrs-XXXXXX)
        BUILD_SCRATCH=$(mktemp -d /tmp/trinity-linus-build-XXXXXX)
        trap 'rm -rf "$WORKDIR" "$HDR_INSTALL" "$BUILD_SCRATCH"' EXIT
        HDR_SENTINEL="$WORKDIR/headers-install-sentinel"
        touch "$HDR_SENTINEL"
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
        # $WORKDIR and is removed by the existing EXIT trap.
        _litter=""
        for _dir in scripts include/generated usr; do
            _abs="$LINUS_SRC/$_dir"
            [ -d "$_abs" ] || continue
            _litter="${_litter}$(find "$_abs" -newer "$HDR_SENTINEL" 2>/dev/null)"
        done
        if [ -n "$_litter" ]; then
            _shown=$(printf '%s\n' "$_litter" | head -20 | tr '\n' ' ')
            echo "FAIL: $NAME: headers_install wrote into source tree: ${_shown}"
            exit 1
        fi
    fi
elif [ ! -d "$LINUS_UAPI" ]; then
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
            linux/netfilter/nf_tables_compat.h; do
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

    # Run batches serially so we can inspect the per-batch exit status and
    # error output.  A batch that exits non-zero with a 'fatal error:' line
    # (even alongside undeclared-identifier diagnostics) did not fully evaluate
    # its symbols; those symbols must remain unresolved rather than be silently
    # counted as resolved.
    TIER2_OK=0
    FATAL_SYMS="$WORKDIR/tier2-fatal-syms.txt"
    touch "$FATAL_SYMS"

    for batch in "$BATCH2_DIR"/batch-*; do
        [ -f "$batch" ] || continue
        bname=$(basename "$batch")
        {
            echo 'int main(void){'
            awk '{printf "printf(\"%%d %%s\\n\",(int)%s,\"%s\");\n", $1, $1}' "$batch"
            echo 'return 0;}'
        } > "$BATCH2_DIR/${bname}.c"
        gcc -w -fmax-errors=200 \
            -I"$LINUS_HDR_INC" \
            -include "$PCH_HDR2" \
            -o "$BATCH2_DIR/${bname}.out" "$BATCH2_DIR/${bname}.c" \
            2>"$BATCH2_DIR/${bname}.err"
        batch_exit=$?
        if [ $batch_exit -ne 0 ]; then
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
        LINUS_HASH=$(git -C "$LINUS_SRC" rev-parse --short HEAD 2>/dev/null || true)
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
                awk '{printf "printf(\"%%d %%s\\n\",(int)%s,\"%s\");\n", $1, $1}' "$SYMS_TIER2_GOOD"
                echo 'return 0;}'
            } > "$FINAL_C2"
            if gcc -w -I"$LINUS_HDR_INC" \
                   -include "$PCH_HDR2" \
                   -o "$FINAL_BIN2" "$FINAL_C2" 2>"$FINAL_ERR2"; then
                # Append Tier 2 authoritative values to the shared compiler table
                "$FINAL_BIN2" >> "$COMPILER_TABLE" 2>/dev/null
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Unresolved-uapi reporting
# After both tiers, any symbol still unresolved that carries a recognizable
# uapi-shaped prefix (ALL_CAPS with underscore, common in kernel headers) is
# reported as a WARN.  This is not a FAIL — trinity-private macros legitimately
# live in the unresolved set.  Known-private prefixes are excluded.
# ---------------------------------------------------------------------------
KNOWN_MISSING_RE='^(TRINITY_|NR_|MAX_|MIN_|DEFAULT_|__NR_)'
unresolved_uapi_count=0
if [ -s "$SYMS_BAD" ]; then
    unresolved_uapi=$(grep -E '_' "$SYMS_BAD" | grep -vE "$KNOWN_MISSING_RE" || true)
    if [ -n "$unresolved_uapi" ]; then
        unresolved_uapi_count=$(printf '%s\n' "$unresolved_uapi" | wc -l | tr -d ' ')
        printf '%s\n' "$unresolved_uapi" | \
            while IFS= read -r sym; do
                echo "WARN: $NAME: unresolved uapi-shaped symbol: $sym" >&2
            done
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

tier1_floor=0
if [ -f "$TIER1_FLOOR_FILE" ]; then
    tier1_floor=$(grep -oE '^[0-9]+' "$TIER1_FLOOR_FILE" | head -1 || true)
    tier1_floor=${tier1_floor:-0}
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
#                Tier-2-inclusive floor (PROBED_FLOOR_FILE).
#
#   skipped: linus tree absent
#                Genuine environment difference; skip both floors.
case "$TIER2_STATUS" in
ran*)
    if [ "$probed" -lt "$probed_floor" ]; then
        echo "FAIL: $NAME: coverage ratchet: probed $probed < floor $probed_floor"
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
esac

# ---------------------------------------------------------------------------
# Step 5: Compare trinity values against compiler values
# For each compiler-resolvable symbol, every occurrence in the harvest must
# carry the compiler's authoritative value.
#
# Normalisation: both sides are converted to signed 32-bit integer to match
# what the probe C code does ((int)SYM via printf("%d",...)).  This means:
#   0x80000000 == -2147483648 (32-bit sign-extension)
#   0xffffffffffffffff == -1 (upper 32 bits masked, lower 32 signed)
#   02000000 (octal) == 524288 (octal parsed, decimal compared)
#
# Performance: a single awk pass over both files avoids O(N*M) shell overhead.
# ---------------------------------------------------------------------------
MISMATCH_FILE="$WORKDIR/mismatches.txt"

# int32 normalisation: truncate to 32-bit signed to match C's (int) semantics.
# Handles hex (0x...), octal (0...), and decimal integers.
# For hex values longer than 8 digits, only the lower 32 bits are kept.
awk -v harvest_file="$HARVEST" '
# Return numeric value of a single hex digit character (0-9, a-f, A-F)
function hd(c) {
    return (c >= "0" && c <= "9") ? (c + 0) : (index("0123456789abcdef", tolower(c)) - 1)
}
# Parse hex, octal, or decimal string; return signed 32-bit int.
# For hex values wider than 32 bits, mask to lower 32 bits first.
function int32(s,   v, i, c, n) {
    if (s ~ /^0[xX]/) {
        s = substr(s, 3)                          # strip 0x/0X
        if (length(s) > 8) s = substr(s, length(s) - 7)  # keep lower 32 bits
        v = 0
        n = length(s)
        for (i = 1; i <= n; i++) { c = substr(s, i, 1); v = v * 16 + hd(c) }
    } else if (s ~ /^0[0-7]+$/) {
        # octal literal
        v = 0
        n = length(s)
        for (i = 2; i <= n; i++) v = v * 8 + (substr(s, i, 1) + 0)
        v = v % 4294967296
    } else {
        # decimal (may carry sign from -1, etc.)
        v = int(s) + 0
        if (v < 0) v = (v % 4294967296) + 4294967296
    }
    # sign-extend to 32-bit signed
    v = v % 4294967296
    if (v >= 2147483648) v -= 4294967296
    return v
}
BEGIN { fail = 0; checked = 0 }
# Pass 1: load harvest into memory (SYM -> space-separated list of values).
# Use FILENAME == harvest_file rather than the FNR == NR idiom: if the harvest
# file is empty awk never emits a record for it, so when the first record of
# the compiler table arrives both FNR and NR are 1, causing that record to be
# misidentified as pass-1 data and loaded into harvest[] instead of checked.
FILENAME == harvest_file {
    sym = $1; val = $2
    harvest[sym] = (sym in harvest) ? harvest[sym] " " val : val
    next
}
# Pass 2: process compiler table (format: DECIMAL_VALUE SYM)
{
    compiler_val = int($1)
    sym = $2
    if (!(sym in harvest)) next  # not a trinity shim -- skip
    checked++
    n = split(harvest[sym], tvals)
    for (i = 1; i <= n; i++) {
        tv = tvals[i]
        trinity_val = int32(tv)
        if (trinity_val != compiler_val) {
            fail++
            printf "FAIL: uapi-shim-values: %s shim wrong: have %s (=%d), want %d (compiler)\n",
                sym, tv, trinity_val, compiler_val > "/dev/stderr"
        }
    }
}
END { print fail, checked }
' "$HARVEST" "$COMPILER_TABLE" > "$MISMATCH_FILE"

read fail checked < "$MISMATCH_FILE"
fail=${fail:-0}
checked=${checked:-0}

# ---------------------------------------------------------------------------
# Step 6: Baseline cross-check
# Each baseline entry pins a (symbol, expected-compiler-value) record.
# If the compiler now returns a different value, the baseline must be updated.
# A symbol in the baseline that the compiler can't resolve is also a failure
# (it may have been added without a corresponding uapi header constant).
# ---------------------------------------------------------------------------
baseline_fail=0

if [ -f "$BASELINE" ]; then
    while IFS= read -r bline; do
        bline="${bline%%#*}"
        [[ -z "${bline//[[:space:]]/}" ]] && continue
        bsym=$(awk '{print $1}' <<< "$bline")
        bval=$(awk '{print $2}' <<< "$bline")
        [ -z "$bsym" ] || [ -z "$bval" ] && continue

        compiler_dec=$(awk -v s="$bsym" '$2==s{print $1; exit}' "$COMPILER_TABLE")
        if [ -z "$compiler_dec" ]; then
            echo "FAIL: $NAME: baseline symbol $bsym not resolvable by compiler" \
                 "(not in any uapi header -- baseline may be stale)" >&2
            baseline_fail=$((baseline_fail + 1))
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

# Invariant 1: every harvested symbol is either resolvable or unresolved.
# harvested = resolvable + total_unresolved; a mismatch indicates a bookkeeping bug.
#
# Note: the "known-private" class (TRINITY_*, NR_*, MAX_*, etc. -- symbols that
# match KNOWN_MISSING_RE) is NOT a separate term here.  Those symbols failed the
# compiler probe and therefore live in SYMS_BAD, folded into total_unresolved.
# They are only excluded from the *reporting* step (unresolved-uapi warnings).
# So the identity is: harvested = resolvable + (unresolved-uapi + known-private)
#                   = resolvable + total_unresolved  ✓
total_unresolved=$(wc -l < "$SYMS_BAD" | tr -d ' ')
if [ "$harvested" -ne $((probed + total_unresolved)) ]; then
    echo "FAIL: $NAME: invariant broken: harvested $harvested != resolvable $probed + unresolved $total_unresolved" >&2
    exit 1
fi

# Invariant 2: every resolvable symbol must have been verified.
# verified (checked) < resolvable (probed) means symbols were silently skipped.
if [ "$checked" -ne "$probed" ]; then
    echo "FAIL: $NAME: invariant broken: verified $checked != resolvable $probed ($((probed - checked)) symbol(s) resolved but not verified)" >&2
    exit 1
fi

echo "PASS: $NAME (harvested $harvested / resolvable $probed / verified $checked / unresolved-uapi $unresolved_uapi_count / tier2=$TIER2_STATUS / ratchet_floor=$probed_floor / tier1_floor=$tier1_floor)"
exit 0
