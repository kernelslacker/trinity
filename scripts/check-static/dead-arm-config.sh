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
#      Location: FUZZ_KCONFIG env, else ~/.config/trinity/fuzz-kconfig.
#      If absent the kernel-source checks are skipped and noted.
#
# MAPPING TABLE
# Each entry: childop-file | config-source | check-symbol | display-name
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
if [ -f "$FUZZ_KCONFIG" ]; then
	KCONFIG="$FUZZ_KCONFIG"
else
	echo "  $NAME: skipped: fuzz-target kconfig not found" \
	     "(set FUZZ_KCONFIG= or place config at $FUZZ_KCONFIG)" >&2
fi

trinity_has() { grep -q "^#define $1 " "$TRINITY_CONFIG" 2>/dev/null; }
kernel_has()  { grep -qE "^$1=(y|m)" "$KCONFIG" 2>/dev/null; }

# ---- Mapping table (tab-separated) ----
# Format: file | source | symbol | display-name
MAPPING=$(cat <<'EOF'
EOF
)

# Count real mapping entries (non-comment, non-blank) so an empty table
# reports as dormant rather than silently passing.
map_entries=$(printf '%s\n' "$MAPPING" | grep -cvE '^[[:space:]]*#|^[[:space:]]*$')

# ---- Walk mapping and check each entry ----

warn_count=0
skip_count=0

while IFS=$'\t' read -r cfile src sym display; do
	[ -n "$cfile" ] || continue

	case "$src" in
	trinity)
		if ! [ -f "$TRINITY_CONFIG" ]; then
			echo "  $NAME: $cfile: skipping ($sym check requires config.h -- run ./configure)" >&2
			skip_count=$((skip_count + 1))
			continue
		fi
		trinity_has "$sym" && continue
		;;
	kernel)
		if [ -z "$KCONFIG" ]; then
			echo "  $NAME: $cfile: skipping ($display: fuzz-target kconfig not found)" >&2
			skip_count=$((skip_count + 1))
			continue
		fi
		kernel_has "$sym" && continue
		;;
	*)
		echo "  $NAME: unknown source '$src' for $cfile -- fix mapping" >&2
		continue
		;;
	esac

	echo "WARN: $NAME: $cfile: arm dead ($display disabled)"
	warn_count=$((warn_count + 1))

done <<< "$MAPPING"

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
