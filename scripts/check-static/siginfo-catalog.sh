#!/bin/bash
#
# siginfo-catalog: every si_code the fuzzer can draw for siginfo_t
# must have a matching union_variant entry in the catalog.
#
# Background: struct_catalog/signal.c registers siginfo_t via a
# discriminated union keyed on si_code.  siginfo_t_si_code_vocab[] is
# the pool of si_code values the fuzzer may emit; siginfo_t_variants[]
# is the sanitiser-side lookup table that supplies the effective field
# set for each si_code.  A variant discriminator can be either a single
# .discrim_value = SI_* or a .discrim_values = <name> pointing at a
# _discrim_values[] array of SI_* tokens.
#
# When an si_code appears in siginfo_t_si_code_vocab[] but no matching
# variant exists in siginfo_t_variants[], the sanitiser falls through
# to the empty shared prefix.  The fuzzer then has no schema for the
# si_code-specific payload and reverts to blind width-guessing --
# exactly the coverage regression the catalog was meant to retire.
#
# This check greps both tables and warns / fails on any vocab entry
# with no matching variant discriminator.  Pre-existing known gaps
# are grandfathered via a .baseline file in the same directory; the
# baseline should shrink over time, never grow.  A new si_code wired
# into siginfo_t_si_code_vocab[] without a variant fails the check.

set -u

NAME="siginfo-catalog"
ROOT="${REPO_ROOT:-$(pwd)}"
SRC="$ROOT/struct_catalog/signal.c"
BASELINE="$ROOT/scripts/check-static/siginfo-catalog.baseline"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$SRC" ] || fail "cannot read $SRC"

# Slurp the siginfo_t_si_code_vocab[] initializer body.
vocab_block=$(awk '
	/^(static[[:space:]]+)?const[[:space:]]+unsigned[[:space:]]+long[[:space:]]+siginfo_t_si_code_vocab\[.*\][[:space:]]*=[[:space:]]*\{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$SRC")

[ -n "$vocab_block" ] || fail "siginfo_t_si_code_vocab[] not found in ${SRC#"$ROOT"/}"

vocab=$(printf '%s\n' "$vocab_block" \
	| grep -oE 'SI_[A-Z0-9_]+' \
	| sort -u)

[ -n "$vocab" ] || fail "siginfo_t_si_code_vocab[] body contained no SI_* tokens"

# Slurp the siginfo_t_variants[] initializer body.
variants_block=$(awk '
	/^(static[[:space:]]+)?const[[:space:]]+struct[[:space:]]+union_variant[[:space:]]+siginfo_t_variants\[.*\][[:space:]]*=[[:space:]]*\{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$SRC")

[ -n "$variants_block" ] || fail "siginfo_t_variants[] not found in ${SRC#"$ROOT"/}"

# Direct discriminator: inline .discrim_value = SI_*
direct=$(printf '%s\n' "$variants_block" \
	| grep -oE '\.discrim_value[[:space:]]*=[[:space:]]*[^,]*SI_[A-Z0-9_]+' \
	| grep -oE 'SI_[A-Z0-9_]+' \
	| sort -u)

# Indirect discriminators: .discrim_values = <name>, where <name> is a
# sibling _discrim_values[] array declared in the same source file.
array_names=$(printf '%s\n' "$variants_block" \
	| grep -oE '\.discrim_values[[:space:]]*=[[:space:]]*[A-Za-z_][A-Za-z0-9_]*' \
	| awk '{ print $NF }' \
	| sort -u)

indirect=""
for arr in $array_names; do
	arr_block=$(awk -v name="$arr" '
		$0 ~ ("^(static[[:space:]]+)?const[[:space:]]+unsigned[[:space:]]+long[[:space:]]+" name "\\[.*\\][[:space:]]*=[[:space:]]*\\{") {
			in_block = 1
			next
		}
		in_block && /^\};/ { in_block = 0; exit }
		in_block { print }
	' "$SRC")
	if [ -z "$arr_block" ]; then
		fail "referenced discriminator array $arr not found in ${SRC#"$ROOT"/}"
	fi
	arr_tokens=$(printf '%s\n' "$arr_block" \
		| grep -oE 'SI_[A-Z0-9_]+')
	indirect=$(printf '%s\n%s\n' "$indirect" "$arr_tokens")
done

variants=$(printf '%s\n%s\n' "$direct" "$indirect" \
	| grep -oE 'SI_[A-Z0-9_]+' \
	| sort -u)

[ -n "$variants" ] || fail "siginfo_t_variants[] carried no SI_* discriminators"

# Gaps: si_codes present in the vocab but not covered by any variant.
gaps=$(comm -23 <(printf '%s\n' "$vocab") <(printf '%s\n' "$variants"))

# Load the grandfathered baseline (one SI_* token per line, comments/blanks
# ignored).  A gap already present in the baseline is expected debt; a gap
# NOT in the baseline is a new regression.
declare -A GRANDFATHERED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue;; esac
		GRANDFATHERED["$entry"]=1
	done < <(sed -e 's/#.*$//' -e 's/[[:space:]]//g' "$BASELINE")
fi

new_gaps=()
grand_gaps=()
if [ -n "$gaps" ]; then
	while IFS= read -r code; do
		[ -z "$code" ] && continue
		if [ -n "${GRANDFATHERED[$code]+x}" ]; then
			grand_gaps+=("$code")
		else
			new_gaps+=("$code")
		fi
	done <<< "$gaps"
fi

# Stale baseline entries: listed in .baseline but no longer a gap
# (either the variant was added or the code was dropped from
# siginfo_t_si_code_vocab[]).  Non-fatal advisory so the same commit
# that closes a gap can also prune the baseline entry without ordering
# games.
stale_baseline=()
for entry in "${!GRANDFATHERED[@]}"; do
	if ! printf '%s\n' "$gaps" | grep -qxF "$entry"; then
		stale_baseline+=("$entry")
	fi
done

vocab_count=$(printf '%s\n' "$vocab" | wc -l)
variants_count=$(printf '%s\n' "$variants" | wc -l)
covered=$((vocab_count - ${#new_gaps[@]} - ${#grand_gaps[@]}))

if [ "${#new_gaps[@]}" -gt 0 ]; then
	{
		echo "  $NAME: ${#new_gaps[@]} siginfo_t_si_code_vocab[] entry/entries have no siginfo_t_variants[] variant:"
		for e in "${new_gaps[@]}"; do echo "    $e"; done
		echo "  fix: add a union_variant to siginfo_t_variants[] in struct_catalog/signal.c"
		echo "       (see SI_QUEUE / SI_USER-SI_TKILL for reference shape),"
		echo "       OR (only if variant work is deferred) append the token to"
		echo "       scripts/check-static/siginfo-catalog.baseline"
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale_baseline[@]} baseline entry/entries no longer match an uncovered code (consider pruning):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "${#new_gaps[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_gaps[@]} new gap(s) of $vocab_count code(s)"
	exit 1
fi

echo "PASS: $NAME (codes=$vocab_count, variants=$variants_count, covered=$covered, grandfathered=${#grand_gaps[@]})"
exit 0
