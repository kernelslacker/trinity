#!/bin/bash
#
# dead-arm-config: warn about childop files that are config-dead on the
# fuzz target because a required kernel or header feature is absent.
#
# Counterpart to dead-arm-detect (which catches selector-dead arms from
# rnd_modulo_u32 dispatch).  A config-dead arm either compiles to a stub
# when an __has_include() guard is false, or returns LATCH_UNSUPPORTED
# every invocation because the kernel feature is disabled.
#
# CONFIG SOURCES (probed in order)
#   1. trinity config.h ($REPO_ROOT/config.h, from ./configure) -- USE_*
#      defines for headers/features trinity probes at build time.
#   2. fuzz-target kernel config (CONFIG_* style) -- for features trinity
#      does not gate at configure time (e.g. runtime-latched childops).
#      Location: FUZZ_KCONFIG env, else ~/.config/trinity/fuzz-kconfig
#      (a symlink to the active target kernel .config is fine).
#      If absent or unreadable, kernel-config checks are skipped.
#
# MAPPING TABLE
# Each entry: childop-file<TAB>config-source<TAB>check-symbol<TAB>display-name
#
# (empty -- no childops are currently config-dead on the fuzz target)
#
# SEVERITY: WARN (exit 0) -- baseline not yet established on fuzz host.

set -u

NAME="dead-arm-config"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

# ---- Locate config sources ----

TRINITY_CONFIG="$ROOT/config.h"

# Fuzz-target kernel config: prefer FUZZ_KCONFIG env, then default location.
_FUZZ_KCONFIG_DEFAULT="$HOME/.config/trinity/fuzz-kconfig"
FUZZ_KCONFIG="${FUZZ_KCONFIG:-$_FUZZ_KCONFIG_DEFAULT}"
KCONFIG=""
if [ -n "$FUZZ_KCONFIG" ] && [ -e "$FUZZ_KCONFIG" ] && [ ! -r "$FUZZ_KCONFIG" ]; then
	# File exists but we cannot read it (e.g. backing mount not active).
	echo "$NAME: kconfig $FUZZ_KCONFIG not readable (skipping kernel-config checks)" >&2
elif [ -f "$FUZZ_KCONFIG" ]; then
	KCONFIG="$FUZZ_KCONFIG"
else
	echo "  $NAME: skipped: fuzz-target kconfig not found" \
	     "(set FUZZ_KCONFIG= or place config at $FUZZ_KCONFIG)" >&2
fi

trinity_has() { grep -q "^#define $1 " "$TRINITY_CONFIG" 2>/dev/null; }
kernel_has()  { grep -qE "^$1=(y|m)" "$KCONFIG" 2>/dev/null; }

# ---- Mapping table (tab-separated) ----
# Format: file<TAB>source<TAB>symbol<TAB>display-name
MAPPING=$(cat <<'EOF'
EOF
)

# Count real mapping entries (non-comment, non-blank) so an empty table
# reports as dormant rather than silently passing.
map_entries=$(printf '%s\n' "$MAPPING" | grep -cvE '^[[:space:]]*#|^[[:space:]]*$')

# ---- Walk mapping and check each entry ----

checked=0
warn_count=0
skip_count=0
malformed_count=0
malformed_rows=""

while IFS=$'\t' read -r cfile src sym display; do
	[ -n "$cfile" ] || continue
	# skip comment rows; map_entries grep also excludes them so the partition holds
	[[ "$cfile" == \#* ]] && continue

	case "$src" in
	trinity)
		if ! [ -f "$TRINITY_CONFIG" ]; then
			echo "  $NAME: $cfile: skipping ($sym check requires config.h -- run ./configure)" >&2
			skip_count=$((skip_count + 1))
			continue
		fi
		trinity_has "$sym" && { checked=$((checked + 1)); continue; }
		;;
	kernel)
		if [ -z "$KCONFIG" ]; then
			echo "  $NAME: $cfile: skipping ($display: fuzz-target kconfig not found)" >&2
			skip_count=$((skip_count + 1))
			continue
		fi
		kernel_has "$sym" && { checked=$((checked + 1)); continue; }
		;;
	*)
		echo "  $NAME: unknown source '$src' for $cfile -- fix mapping" >&2
		malformed_count=$((malformed_count + 1))
		malformed_rows="${malformed_rows:+$malformed_rows, }$cfile"
		continue
		;;
	esac

	echo "WARN: $NAME: $cfile: arm dead ($display disabled)"
	warn_count=$((warn_count + 1))

done <<< "$MAPPING"

# ---- Partition assertion ----
# Every real table row must land in exactly one counter bucket.
_total=$((checked + warn_count + skip_count + malformed_count))
if [ "$_total" -ne "$map_entries" ]; then
	echo "FAIL: $NAME: partition check failed: checked=$checked warn=$warn_count" \
	     "skip=$skip_count malformed=$malformed_count total=$_total expected=$map_entries"
	exit 1
fi

# ---- Malformed entries → hard FAIL ----
if [ "$malformed_count" -gt 0 ]; then
	echo "FAIL: $NAME: $malformed_count malformed mapping entry/entries" \
	     "(unknown source field): $malformed_rows"
	exit 1
fi

# ---- Summary ----

if [ "$warn_count" -gt 0 ]; then
	{
		echo ""
		echo "  $NAME: $warn_count childop file(s) are config-dead on this target."
		echo "  A config-dead arm compiles to a stub or returns LATCH_UNSUPPORTED"
		echo "  every invocation; it contributes zero useful fuzz surface."
		echo "  Resolution: enable the kernel/build option, or remove the childop"
		echo "  from the rotation until the config is present on the fuzz target."
		[ "$skip_count" -gt 0 ] && \
		echo "  ($skip_count mapping entry/entries skipped -- config source not readable)"
	} >&2
	echo "WARN: $NAME: $warn_count config-dead arm(s) (exit 0; WARN gate)"
	exit 0
fi

if [ "$skip_count" -gt 0 ]; then
	echo "WARN: $NAME: 0 config-dead arms detected; $skip_count entry/entries skipped" \
	     "(config source not readable -- results incomplete)"
	exit 0
fi

if [ "$map_entries" -eq 0 ]; then
	echo "WARN: $NAME: empty mapping table -- no entries to check; gate has no detection power"
	exit 0
fi

echo "PASS: $NAME: all mapped childop arms have required config enabled"
exit 0
