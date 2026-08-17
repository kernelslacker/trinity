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
# Known config-dead childops (cfile, source, CONFIG_ symbol, display name).
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
if [ -n "$FUZZ_KCONFIG" ] && [ -L "$FUZZ_KCONFIG" ] && [ ! -e "$FUZZ_KCONFIG" ]; then
	# Dangling symlink: the symlink itself exists but its target is gone
	# (e.g. backing mount unmounted).  [ -e ] follows the link and returns
	# false when the target is missing, so the normal [ -e ] && [ ! -r ]
	# guard cannot fire for this case.
	echo "WARN: $NAME: kconfig $FUZZ_KCONFIG is a dangling symlink" \
	     "(mount gone?); skipping kernel-config checks" >&2
elif [ -n "$FUZZ_KCONFIG" ] && [ -e "$FUZZ_KCONFIG" ] && [ ! -r "$FUZZ_KCONFIG" ]; then
	# File exists but we cannot read it (e.g. backing mount not active).
	echo "$NAME: kconfig $FUZZ_KCONFIG not readable (skipping kernel-config checks)" >&2
elif [ -f "$FUZZ_KCONFIG" ]; then
	# Content validation: a readable but near-empty file is not authoritative.
	# A real fuzz-target .config has thousands of CONFIG_ lines; require at
	# least 100 to guard against truncated, stale, or zombie-mount files.
	_cfg_count=$(grep -c '^CONFIG_' "$FUZZ_KCONFIG" 2>/dev/null || true)
	_cfg_count=${_cfg_count:-0}
	if [ "$_cfg_count" -lt 100 ]; then
		echo "WARN: $NAME: kconfig $FUZZ_KCONFIG contains only $_cfg_count CONFIG_" \
		     "line(s) (expected >=100; truncated or stale file?);" \
		     "skipping kernel-config checks" >&2
	else
		KCONFIG="$FUZZ_KCONFIG"
	fi
else
	echo "  $NAME: skipped: fuzz-target kconfig not found" \
	     "(set FUZZ_KCONFIG= or place config at $FUZZ_KCONFIG)" >&2
fi

trinity_has() { grep -q "^#define $1 " "$TRINITY_CONFIG" 2>/dev/null; }
kernel_has()  { grep -qE "^$1=(y|m)" "$KCONFIG" 2>/dev/null; }

# ---- Mapping table (tab-separated) ----
# Format: file<TAB>source<TAB>symbol<TAB>display-name
MAPPING=$(cat <<'EOF'
# NOTE: config rows only for CONFIG_*-gated arms; runtime-dead arms need a separate probe.
childops/misc/fault-injector.c	kernel	CONFIG_FAULT_INJECTION	fault injection
childops/fs/ublk-lifecycle.c	kernel	CONFIG_BLK_DEV_UBLK	ublk
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

# Pre-validate mapping: every real row must have exactly 4 tab-separated fields.
# awk -F'\t' does not collapse adjacent tabs, so empty interior fields (which
# IFS=$'\t' read would silently shift away) are correctly detected here.  This
# also subsumes the former >=5-field check added in
# fe7dc0433804 ("dead-arm-config: reject 5+ field rows in mapping walk").
_map_bad=$(printf '%s\n' "$MAPPING" | \
	awk -F'\t' '
		/^[[:space:]]*#/ { next }
		/^[[:space:]]*$/ { next }
		NF != 4 || $1=="" || $2=="" || $3=="" || $4=="" {
			printf "  %s: malformed row (NF=%d, expected 4 non-empty tab-separated fields): %s\n", name, NF, $0
		}
	' name="$NAME")
if [ -n "$_map_bad" ]; then
	printf '%s\n' "$_map_bad" >&2
	echo "FAIL: $NAME: mapping table has rows with wrong field count (expected exactly 4 tab-separated fields)"
	exit 1
fi

while IFS=$'\t' read -r cfile src sym display; do
	[ -n "$cfile" ] || continue
	# skip comment rows; regex matches map_entries grep so the partition holds
	[[ "$cfile" =~ ^[[:space:]]*# ]] && continue

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
	     "(unknown config-source field): $malformed_rows"
	exit 1
fi

# ---- Ioctl-group config check ----
# Parse ioctls/*.c files for *_devs[] arrays, map each device-class string
# to its gating CONFIG_ symbol, and warn when an entire group is dead.
#
# "dead" means the symbol is neither CONFIG_X=y nor CONFIG_X=m (absent and
# explicitly-not-set are treated identically -- both mean the feature is off).
#
# A group is WARN when ALL nodes are dead; partially-dead groups (some nodes
# live, some dead) get a separate INFO line on stderr.

# Devnode class string → CONFIG_SYMBOL<TAB>display_name
# Keys are the literal strings that appear in ioctls/*.c devs[] arrays.
IOCTL_NODE_MAP=$(cat <<'IOCTL_NODE_MAP_EOF'
uinput	INPUT_UINPUT	uinput
video4linux	MEDIA_SUPPORT	video4linux
cec	MEDIA_CEC_SUPPORT	cec
sound	SOUND	sound/ALSA
alsa	SOUND	sound/ALSA
vhost-net	VHOST_MENU	vhost
vhost-vsock	VHOST_MENU	vhost
vhost-vdpa	VHOST_MENU	vhost
device-mapper	MD	device-mapper
mtd	MTD	mtd
pps	PPS	pps
rfkill	RFKILL	rfkill
isgx	X86_SGX	sgx
firewire	FIREWIRE	firewire
watchdog	WATCHDOG	watchdog
mei	INTEL_MEI	intel-mei
sr	BLK_DEV_SR	cdrom
nbd	BLK_DEV_NBD	nbd
vmci	VMWARE_VMCI	vmci
ptp	PTP_1588_CLOCK	ptp
mcelog	X86_MCELOG_LEGACY	mcelog
IOCTL_NODE_MAP_EOF
)

# Per-file node overrides: filename<TAB>devnode_class<TAB>CONFIG_SYMBOL<TAB>display_name
# Needed when a devnode class string is shared across files with different
# feature gates (e.g. joystick.c uses the generic "input" class but gates on
# INPUT_JOYDEV, not INPUT).
IOCTL_FILE_OVERRIDE=$(cat <<'IOCTL_FILE_OVERRIDE_EOF'
joystick.c	input	INPUT_JOYDEV	joystick
IOCTL_FILE_OVERRIDE_EOF
)

# Pre-load the kconfig live-set once so individual node lookups are O(1).
# Calling kernel_has() for each devnode (potentially 50+ files × 3 nodes)
# would re-invoke grep on the kconfig file per symbol, which is
# prohibitively slow on networked or remote mounts (~0.2s/call).
declare -A _ioctl_kcfg_live
if [ -n "$KCONFIG" ]; then
	while IFS= read -r _kcfg_line; do
		_kcfg_key="${_kcfg_line%%=*}"
		# Dup guard required by baseline-associative-dup-guard; kconfig
		# entries are unique in practice but guard defensively.
		[[ -v _ioctl_kcfg_live["$_kcfg_key"] ]] && continue
		_ioctl_kcfg_live["$_kcfg_key"]=1
	done < <(grep -E "^CONFIG_[A-Z0-9_]+=(y|m)" "$KCONFIG" 2>/dev/null)
fi
ioctl_sym_live() { [ "${_ioctl_kcfg_live["CONFIG_$1"]+_}" ]; }

ioctl_warn_count=0
ioctl_info_count=0
ioctl_skip_announced=0
ioctl_unmapped_total=0
_all_unmapped_nodes=""

for _cfile in "$ROOT"/ioctls/*.c; do
	[ -f "$_cfile" ] || continue
	_fname=$(basename "$_cfile")

	# Skip files that don't define an ioctl_group struct — they may have
	# *_devs[] arrays for other purposes (e.g. efault_cache.c uses
	# efault_optout_devs[], which is not an ioctl group).
	grep -q "static const struct ioctl_group" "$_cfile" || continue

	# Extract all devnode class strings from *_devs[] arrays in this file.
	# Handles both 'char *const' and 'char * const' spellings.
	# Note: the declaration line and the closing '};' line are included in
	# the scan so that single-line arrays and strings on the closing brace
	# are not silently dropped.
	_devnodes=$(awk '
		/static const char[ ]*\*[ ]*const[ ]+[a-z][a-z0-9_]*_devs\[/ { in_devs=1 }
		in_devs {
			line = $0
			while (match(line, /"[^"]+"/) > 0) {
				print substr(line, RSTART+1, RLENGTH-2)
				line = substr(line, RSTART+RLENGTH)
			}
			if (/\};/) in_devs=0
		}
	' "$_cfile" 2>/dev/null)

	[ -n "$_devnodes" ] || continue

	if [ -z "$KCONFIG" ]; then
		if [ "$ioctl_skip_announced" -eq 0 ]; then
			echo "  $NAME: ioctl-group checks skipped (fuzz-target kconfig not found)" >&2
			ioctl_skip_announced=1
		fi
		continue
	fi

	_node_dead=0
	_node_live=0
	_node_unmapped=0
	_dead_displays=""
	_unmapped_nodes=""

	while IFS= read -r _node; do
		[ -n "$_node" ] || continue

		# Look up in per-file override table first.
		_sym=""
		_display=""
		while IFS=$'\t' read -r _of_file _of_node _of_sym _of_display; do
			[ "$_of_file" = "$_fname" ] && [ "$_of_node" = "$_node" ] || continue
			_sym="$_of_sym"
			_display="$_of_display"
			break
		done <<< "$IOCTL_FILE_OVERRIDE"

		# Fall back to generic node map.
		if [ -z "$_sym" ]; then
			while IFS=$'\t' read -r _nm_node _nm_sym _nm_display; do
				[ "$_nm_node" = "$_node" ] || continue
				_sym="$_nm_sym"
				_display="$_nm_display"
				break
			done <<< "$IOCTL_NODE_MAP"
		fi

		if [ -z "$_sym" ]; then
			# Not in our map: treat as live for the dead-group calculation
			# (unknown ≠ definitively dead), but accumulate for the
			# unmapped-node WARN so the map cannot silently rot.
			_node_live=$((_node_live + 1))
			_node_unmapped=$((_node_unmapped + 1))
			case ",$_unmapped_nodes," in
			*",${_node},"*) ;;
			*) _unmapped_nodes="${_unmapped_nodes:+$_unmapped_nodes, }$_node" ;;
			esac
			continue
		fi

		if ioctl_sym_live "$_sym"; then
			_node_live=$((_node_live + 1))
		else
			_node_dead=$((_node_dead + 1))
			# Accumulate unique display names for the WARN/INFO line.
			case ",$_dead_displays," in
			*",${_display},"*) ;;
			*) _dead_displays="${_dead_displays:+$_dead_displays, }$_display" ;;
			esac
		fi
	done <<< "$_devnodes"

	ioctl_unmapped_total=$((ioctl_unmapped_total + _node_unmapped))
	if [ -n "$_unmapped_nodes" ]; then
		_all_unmapped_nodes="${_all_unmapped_nodes:+$_all_unmapped_nodes, }$_unmapped_nodes"
	fi

	if [ "$_node_dead" -eq 0 ]; then
		continue  # all mapped nodes live
	elif [ "$_node_live" -eq 0 ]; then
		# Fully dead group.
		echo "WARN: $NAME: ioctls/$_fname: ioctl group dead ($_dead_displays disabled)"
		ioctl_warn_count=$((ioctl_warn_count + 1))
	else
		# Partially dead group: some nodes live, some dead.
		echo "INFO: $NAME: ioctls/$_fname: ioctl group partially dead" \
		     "($_dead_displays disabled; some nodes still live)" >&2
		ioctl_info_count=$((ioctl_info_count + 1))
	fi
done

# Unmapped devnode WARN: emitted regardless of kconfig availability so
# the map cannot silently rot as new ioctls/*.c files are added.
if [ "$ioctl_unmapped_total" -gt 0 ]; then
	# Build a capped display list (max 20 names + "and N more" suffix).
	_unmapped_list=$(printf '%s' "$_all_unmapped_nodes" | tr ',' '\n' | sed '/^[[:space:]]*$/d')
	_unmapped_count=$(printf '%s\n' "$_unmapped_list" | wc -l)
	_cap=20
	if [ "$_unmapped_count" -gt "$_cap" ]; then
		_extra=$((_unmapped_count - _cap))
		_unmapped_cap=$(printf '%s\n' "$_unmapped_list" | head -"$_cap" | tr '\n' ',' | sed 's/,[[:space:]]*$//')
		_unmapped_cap="$_unmapped_cap (and $_extra more)"
	else
		_unmapped_cap=$(printf '%s\n' "$_unmapped_list" | tr '\n' ',' | sed 's/,[[:space:]]*$//')
	fi
	echo "WARN: $NAME: $ioctl_unmapped_total devnode string(s) in *_devs[] arrays" \
	     "have no entry in IOCTL_NODE_MAP: $_unmapped_cap" \
	     "(map may be stale; add entries or verify)"
fi

# Ioctl-group summary (separate counter from childop table).
if [ "$ioctl_warn_count" -gt 0 ]; then
	{
		echo ""
		echo "  $NAME: $ioctl_warn_count ioctl group(s) are config-dead on this target."
		echo "  A dead ioctl group contributes zero coverage; its /dev nodes will"
		echo "  never open successfully on this kernel configuration."
		echo "  Resolution: enable the gating kernel option on the fuzz target."
		[ "$ioctl_info_count" -gt 0 ] && \
		echo "  ($ioctl_info_count partially-dead group(s) -- see INFO lines above)"
	} >&2
fi

# ---- Summary ----

if [ "$warn_count" -gt 0 ] || [ "$ioctl_warn_count" -gt 0 ]; then
	_total_warn=$((warn_count + ioctl_warn_count))
	{
		[ "$warn_count" -gt 0 ] && {
			echo ""
			echo "  $NAME: $warn_count childop file(s) are config-dead on this target."
			echo "  A config-dead arm compiles to a stub or returns LATCH_UNSUPPORTED"
			echo "  every invocation; it contributes zero useful fuzz surface."
			echo "  Resolution: enable the kernel/build option, or remove the childop"
			echo "  from the rotation until the config is present on the fuzz target."
			[ "$skip_count" -gt 0 ] && \
			echo "  ($skip_count mapping entry/entries skipped -- config source not readable)"
		}
	} >&2
	echo "WARN: $NAME: $warn_count config-dead childop arm(s), $ioctl_warn_count dead ioctl group(s) (exit 0; WARN gate)"
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
