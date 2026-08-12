#!/bin/bash
#
# dead-arm-config: warn about childop files that are config-dead on the
# current build target because a required kernel or header feature is
# absent.
#
# Counterpart to dead-arm-detect (which catches selector-dead arms from
# rnd_modulo_u32 dispatch).  A config-dead arm either compiles to a stub
# when an __has_include() guard is false, or returns LATCH_UNSUPPORTED
# every invocation because the kernel feature is disabled.
#
# CONFIG SOURCES (probed in order)
#   1. trinity config.h ($REPO_ROOT/config.h, from ./configure) -- USE_*
#      defines for headers/features trinity probes at build time.
#   2. kernel .config (/boot/config-$(uname -r) or /proc/config.gz) --
#      for features trinity does not gate at configure time (e.g. THP
#      is runtime-latched via CHILDOP_LATCH_UNSUPPORTED, no USE_* exists).
#
# MAPPING TABLE
# Each entry: childop-file | config-source | check-symbol | display-name
#
#   afxdp-churn / afxdp-churn-attach
#     Guard:  #if __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>)
#     Source: trinity (USE_XDP written by: check_header linux/if_xdp.h USE_XDP)
#
#   thp-split-ref-race
#     Guard:  none -- runtime CHILDOP_LATCH_UNSUPPORTED when smaps shows
#             no AnonHugePages after MADV_HUGEPAGE probe
#     Source: kernel (no USE_* in config.h; probe /boot/config-$(uname -r))
#     LIMIT:  skipped if kernel .config is not readable
#
#   xfrm-churn
#     Guard:  none -- XFRM netlink fails at runtime when CONFIG_XFRM_USER=n
#     Source: kernel (only specific enum probes in trinity config.h;
#             no blanket USE_XFRM)
#     LIMIT:  skipped if kernel .config is not readable
#
# SEVERITY: WARN (exit 0) -- baseline not yet established on fuzz host.

set -u

NAME="dead-arm-config"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

# ---- Locate config sources ----

TRINITY_CONFIG="$ROOT/config.h"

KCONFIG=""
KCONFIG_CMD=""
KVER="$(uname -r 2>/dev/null || true)"
if [ -n "$KVER" ] && [ -f "/boot/config-$KVER" ]; then
	KCONFIG="/boot/config-$KVER"
	KCONFIG_CMD="grep"
elif [ -f "/proc/config.gz" ]; then
	KCONFIG="/proc/config.gz"
	KCONFIG_CMD="zgrep"
fi

trinity_has() { grep -q "^#define $1 " "$TRINITY_CONFIG" 2>/dev/null; }
kernel_has()  { $KCONFIG_CMD -qE "^$1=(y|m)" "$KCONFIG" 2>/dev/null; }

# ---- Mapping table (tab-separated) ----
# Format: file | source | symbol | display-name
MAPPING=$(cat <<'EOF'
childops/net/afxdp-churn.c	trinity	USE_XDP	CONFIG_XDP_SOCKETS
childops/net/afxdp-churn-attach.c	trinity	USE_XDP	CONFIG_XDP_SOCKETS
childops/mm/thp-split-ref-race.c	kernel	CONFIG_TRANSPARENT_HUGEPAGE	CONFIG_TRANSPARENT_HUGEPAGE
childops/net/xfrm/xfrm-churn.c	kernel	CONFIG_XFRM_USER	CONFIG_XFRM_USER
EOF
)

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
		if [ -z "$KCONFIG_CMD" ]; then
			echo "  $NAME: $cfile: skipping ($display: no readable kernel .config;" \
			     "need /boot/config-$(uname -r 2>/dev/null) or /proc/config.gz)" >&2
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
		echo "  from the rotation until the config is present on the fuzz host."
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

echo "PASS: $NAME: all mapped childop arms have required config enabled"
exit 0
