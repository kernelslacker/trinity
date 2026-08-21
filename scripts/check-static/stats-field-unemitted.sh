#!/bin/bash
#
# stats-field-unemitted: detect fields declared in stats/subsys/*.h or in
# struct stats_s (include/stats.h) that have no corresponding reference in
# the required emitter path.
#
# Background: every field in a stats/subsys/*.h struct is either:
#   (a) wired to an output path -- referenced directly via struct member
#       access in stats/json/, stats/dump/, or stats/subsys/*.c descriptor
#       tables (STAT_FIELD*() macro), or in a stats/*/ reporter -- or
#   (b) intentionally internal bookkeeping (e.g. window-start snapshots,
#       internal scheduling state, forward-carved placeholders).
#
# Historically a recurring bug is an author adding the field and wiring the
# producer (the atomic add-fetch in a childop or strategy file) but omitting
# the consumer (the STAT_FIELD_SUB entry or the JSON printf).  The result is
# a counter that accrues silently and is invisible to any operator reading
# --stats-json or a periodic dump.
#
# Two populations are scanned:
#
#   Population A -- stats/subsys/*.h structs:
#     Emission check: any .c file under stats/ (text dump, JSON, descriptors).
#     Baseline: scripts/check-static/stats-field-unemitted.baseline
#     (UNEMITTED:stats/subsys/<hdr>:<field>)
#
#   Population B -- struct stats_s in include/stats.h:
#     Emission check: stats/json/*.c ONLY.  A field present in the text dump
#     (stats/dump/) but absent from stats/json/ is a JSON-export gap.
#     Baseline: scripts/check-static/stats-field-unemitted.baseline
#     (UNEMITTED:include/stats.h:<field>)
#
# Detection heuristic: for every struct field, search the relevant emitter
# scope for any of three reference patterns:
#
#   1. Direct member access:  .fieldname  or  ->fieldname
#      (struct dereference in an emitter translation unit)
#   2. STAT_FIELD* macro:     STAT_FIELD_SUB(subsys, fieldname) and variants;
#      the second argument is the field name exposed to the category iterator
#   3. Quoted field key:      "fieldname" appearing in stat_row() / printf()
#      calls in stats/ emitters
#
# A field matched by none of the three patterns in any stats/ .c file is
# classified "unemitted".  Fields listed in the baseline are grandfathered.
# The baseline should shrink over time as fields are wired to emitters or
# confirmed as legitimate internal state; it must never grow.
#
# Population A emitter search covers all .c files under stats/ (stats/subsys/
# *.c for descriptor tables, stats/json/ for JSON emitters, stats/dump/ for
# text dump emitters, stats/periodic/ / stats/childop/ / stats/kcov/ /
# stats/network/ / stats/categories/ for periodic and shutdown reporters).
# Population B emitter search is restricted to stats/json/*.c -- a reference
# in a text-dump path (stats/dump/) does NOT satisfy the JSON-export
# requirement for include/stats.h fields.
# Producers outside stats/ (e.g. childops/*.c, random_syscall/*.c,
# strategy/*.c) bump fields but do not emit them; they are excluded from the
# search so a field with a live producer but no consumer is correctly flagged.
#
# A single baseline file of grandfathered fields lives alongside this script
# as stats-field-unemitted.baseline (format: UNEMITTED:<header>:<field>).
# Entries for Population A use UNEMITTED:stats/subsys/<hdr>:<field>.
# Entries for Population B use UNEMITTED:include/stats.h:<field>.
# The baseline should shrink over time, never grow.

set -u

NAME="stats-field-unemitted"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/stats-field-unemitted.baseline"
SUBSYS_DIR="$ROOT/stats/subsys"
STATS_DIR="$ROOT/stats"
STATS_H="$ROOT/include/stats.h"

declare -A GRANDFATHERED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		GRANDFATHERED["$entry"]=1
	done < <(sed -e 's/[[:space:]]#.*$//' -e 's/[[:space:]]*$//' "$BASELINE")
fi

# Build temporary files
EMITTED_FILE="$(mktemp)"
JSON_EMITTED_FILE="$(mktemp)"
FIELDS_FILE="$(mktemp)"
trap 'rm -f "$EMITTED_FILE" "$JSON_EMITTED_FILE" "$FIELDS_FILE" 2>/dev/null' EXIT

# Phase 1a: extract every "emitted" field name from ALL stats/ .c files
# (Population A emitter scope).  Three patterns are recognised:
#   (a) direct member access: the token following . or -> is the field name
#   (b) STAT_FIELD* macro second argument: STAT_FIELD_SUB(subsys, FIELDNAME)
#   (c) quoted key: stat_row() / printf() calls embed the field name as a
#       string literal -- extract any "identifier" appearing quoted
#
# The union of pattern matches is stored one field name per line, de-duped.
find "$STATS_DIR" -name '*.c' | LC_ALL=C sort | \
	xargs awk '
	{
		line = $0

		# (a) Direct member access: .fieldname or ->fieldname
		rest = line
		while (match(rest, /(\.|->)[a-zA-Z_][a-zA-Z0-9_]*/)) {
			tok = substr(rest, RSTART, RLENGTH)
			# strip leading . or ->
			if (substr(tok, 1, 2) == "->")
				tok = substr(tok, 3)
			else
				tok = substr(tok, 2)
			print tok
			rest = substr(rest, RSTART + RLENGTH)
		}

		# (b) STAT_FIELD* macro: extract second argument
		rest = line
		while (match(rest, /STAT_FIELD[_A-Z0-9]*[[:space:]]*\([^,)]+,[[:space:]]*/)) {
			tail = substr(rest, RSTART + RLENGTH)
			if (match(tail, /^[a-zA-Z_][a-zA-Z0-9_]*/))
				print substr(tail, 1, RLENGTH)
			rest = tail
		}

		# (c) Quoted key: "fieldname"
		rest = line
		while (match(rest, /"[a-zA-Z_][a-zA-Z0-9_]*"/)) {
			print substr(rest, RSTART + 1, RLENGTH - 2)
			rest = substr(rest, RSTART + RLENGTH)
		}
	}
	' | LC_ALL=C sort -u > "$EMITTED_FILE"

# Phase 1b: extract field names from stats/json/*.c ONLY (Population B
# emitter scope).  Same three patterns as Phase 1a; a field absent from this
# set is a JSON-export gap even if present in the text-dump emitters.
find "$STATS_DIR/json" -name '*.c' | LC_ALL=C sort | \
	xargs awk '
	{
		line = $0

		# (a) Direct member access: .fieldname or ->fieldname
		rest = line
		while (match(rest, /(\.|->)[a-zA-Z_][a-zA-Z0-9_]*/)) {
			tok = substr(rest, RSTART, RLENGTH)
			# strip leading . or ->
			if (substr(tok, 1, 2) == "->") tok = substr(tok, 3)
			else tok = substr(tok, 2)
			print tok
			rest = substr(rest, RSTART + RLENGTH)
		}

		# (b) STAT_FIELD* macro: extract second argument
		rest = line
		while (match(rest, /STAT_FIELD[_A-Z0-9]*[[:space:]]*\([^,)]+,[[:space:]]*/)) {
			tail = substr(rest, RSTART + RLENGTH)
			if (match(tail, /^[a-zA-Z_][a-zA-Z0-9_]*/))
				print substr(tail, 1, RLENGTH)
			rest = tail
		}

		# (c) Quoted key: "fieldname"
		rest = line
		while (match(rest, /"[a-zA-Z_][a-zA-Z0-9_]*"/)) {
			print substr(rest, RSTART + 1, RLENGTH - 2)
			rest = substr(rest, RSTART + RLENGTH)
		}
	}
	' | LC_ALL=C sort -u > "$JSON_EMITTED_FILE"

# Phase 2: extract every struct field name from stats/subsys/*.h AND from
# struct stats_s in include/stats.h.
# Approach: track struct-body brace depth; for each field declaration line
# (a line inside a struct body that contains a semicolon), strip any trailing
# array subscripts then extract the last identifier before the semicolon.
# Block and line comments are stripped.  Multi-dimensional array subscripts
# (e.g. foo[A][B]) are handled by stripping repeated [...] suffixes.
find "$SUBSYS_DIR" -maxdepth 1 -name '*.h' | LC_ALL=C sort | \
	xargs awk -v root="$ROOT/" '
	function strip_comments(s,    i, end_idx, tail) {
		if (in_block) {
			i = index(s, "*/")
			if (i == 0) return ""
			s = substr(s, i + 2)
			in_block = 0
		}
		while ((i = index(s, "/*")) > 0) {
			tail = substr(s, i + 2)
			end_idx = index(tail, "*/")
			if (end_idx == 0) {
				in_block = 1
				s = substr(s, 1, i - 1)
				break
			}
			s = substr(s, 1, i - 1) " " substr(tail, end_idx + 2)
		}
		sub(/\/\/.*$/, "", s)
		return s
	}
	BEGIN { in_block = 0; in_struct = 0; depth = 0 }
	FNR == 1 {
		in_block = 0; in_struct = 0; depth = 0
		rel = FILENAME
		sub(root, "", rel)
	}
	{
		line = strip_comments($0)

		# Detect struct opening: "struct name {" on a single line.
		# A typedef forward-declaration ("struct name;") has no { and is
		# skipped.  Nested struct member declarations ("struct name field;")
		# also have no { and are skipped.
		if (!in_struct && match(line, /struct[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\{/)) {
			in_struct = 1
			depth = 1
			# Count any additional braces on the remainder of this line.
			tail = substr(line, RSTART + RLENGTH - 1)  # starts at the {
			for (i = 2; i <= length(tail); i++) {
				c = substr(tail, i, 1)
				if (c == "{") depth++
				else if (c == "}") {
					depth--
					if (depth == 0) { in_struct = 0; break }
				}
			}
			next
		}

		if (!in_struct) next

		# Track brace depth.  Record depth before this line is processed
		# so we can distinguish a closing-brace line (prev==1 -> becomes 0)
		# from a field line deep inside an inner block.
		prev_depth = depth
		for (i = 1; i <= length(line); i++) {
			c = substr(line, i, 1)
			if (c == "{") depth++
			else if (c == "}") {
				depth--
				if (depth == 0) { in_struct = 0; break }
			}
		}

		# Skip the closing-brace line itself (prev_depth == 1 means we were
		# at the outermost struct level before this line closed it).
		if (!in_struct && prev_depth <= 1) next

		# Only field declaration lines have a semicolon.
		if (index(line, ";") == 0) next

		# Extract field name: strip trailing array subscripts, then take
		# the last identifier before the semicolon.
		semi = index(line, ";")
		before_semi = substr(line, 1, semi - 1)
		# Remove all trailing array subscripts (handles multi-dim arrays)
		sub(/([[:space:]]*\[[^\]]*\])+[[:space:]]*$/, "", before_semi)
		# Match the last identifier (possibly followed by spaces)
		if (!match(before_semi, /[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*$/))
			next
		fname = substr(before_semi, RSTART, RLENGTH)
		sub(/[[:space:]]*$/, "", fname)

		# Skip C type keywords and common storage/qualifier tokens that
		# can appear as the last token in a partial type expression.
		if (fname == "struct" || fname == "union" || fname == "enum" ||
		    fname == "unsigned" || fname == "signed" || fname == "long" ||
		    fname == "short" || fname == "int" || fname == "char" ||
		    fname == "void" || fname == "const" || fname == "volatile" ||
		    fname == "restrict" || fname == "inline" || fname == "extern" ||
		    fname == "static" || fname == "typedef" ||
		    fname == "uint8_t" || fname == "uint16_t" ||
		    fname == "uint32_t" || fname == "uint64_t" ||
		    fname == "int8_t" || fname == "int16_t" ||
		    fname == "int32_t" || fname == "int64_t" ||
		    fname == "size_t" || fname == "ssize_t" ||
		    fname == "bool" || fname == "atomic_t" ||
		    fname == "atomic_long_t" || fname == "atomic_uint_t")
			next

		print rel "\t" fname
	}
	' > "$FIELDS_FILE"

# Population B: struct stats_s fields from include/stats.h.
# Only fields declared at the outermost struct level (depth == 1) are
# extracted; nested anonymous-struct or union bodies are skipped.
# The source tag is "include/stats.h" so Phase 3 can apply the stricter
# JSON-only emission check to these entries.
awk -v hpath="include/stats.h" '
	function strip_comments(s,    i, end_idx, tail) {
		if (in_block) {
			i = index(s, "*/")
			if (i == 0) return ""
			s = substr(s, i + 2)
			in_block = 0
		}
		while ((i = index(s, "/*")) > 0) {
			tail = substr(s, i + 2)
			end_idx = index(tail, "*/")
			if (end_idx == 0) {
				in_block = 1
				s = substr(s, 1, i - 1)
				break
			}
			s = substr(s, 1, i - 1) " " substr(tail, end_idx + 2)
		}
		sub(/\/\/.*$/, "", s)
		return s
	}
	BEGIN { in_block = 0; in_struct = 0; depth = 0 }
	{
		line = strip_comments($0)

		# Enter struct stats_s only.
		if (!in_struct && match(line, /struct[[:space:]]+stats_s[[:space:]]*\{/)) {
			in_struct = 1
			depth = 1
			tail = substr(line, RSTART + RLENGTH - 1)
			for (i = 2; i <= length(tail); i++) {
				c = substr(tail, i, 1)
				if (c == "{") depth++
				else if (c == "}") {
					depth--
					if (depth == 0) { in_struct = 0; break }
				}
			}
			next
		}

		if (!in_struct) next

		prev_depth = depth
		for (i = 1; i <= length(line); i++) {
			c = substr(line, i, 1)
			if (c == "{") depth++
			else if (c == "}") {
				depth--
				if (depth == 0) { in_struct = 0; break }
			}
		}

		# Skip closing-brace line and lines inside nested blocks.
		if (!in_struct && prev_depth <= 1) next
		if (depth > 1) next

		if (index(line, ";") == 0) next

		semi = index(line, ";")
		before_semi = substr(line, 1, semi - 1)
		sub(/([[:space:]]*\[[^\]]*\])+[[:space:]]*$/, "", before_semi)
		if (!match(before_semi, /[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*$/))
			next
		fname = substr(before_semi, RSTART, RLENGTH)
		sub(/[[:space:]]*$/, "", fname)

		if (fname == "struct" || fname == "union" || fname == "enum" ||
		    fname == "unsigned" || fname == "signed" || fname == "long" ||
		    fname == "short" || fname == "int" || fname == "char" ||
		    fname == "void" || fname == "const" || fname == "volatile" ||
		    fname == "restrict" || fname == "inline" || fname == "extern" ||
		    fname == "static" || fname == "typedef" ||
		    fname == "uint8_t" || fname == "uint16_t" ||
		    fname == "uint32_t" || fname == "uint64_t" ||
		    fname == "int8_t" || fname == "int16_t" ||
		    fname == "int32_t" || fname == "int64_t" ||
		    fname == "size_t" || fname == "ssize_t" ||
		    fname == "bool" || fname == "atomic_t" ||
		    fname == "atomic_long_t" || fname == "atomic_uint_t")
			next

		print hpath "\t" fname
	}
' "$STATS_H" >> "$FIELDS_FILE"

# Phase 3: for each (header, field) pair, check if the field name appears
# in the required emitter set.
#   - Fields from include/stats.h are checked against JSON_EMITTED_FILE
#     (stats/json/*.c only): a text-dump reference does not satisfy the
#     JSON-export requirement.
#   - Fields from stats/subsys/*.h are checked against EMITTED_FILE
#     (all stats/*.c): the existing Population A semantics.
# Collect unemitted fields and compare to baseline.
new_unbaselined=()
declare -A SEEN_UNEMITTED=()

while IFS=$'\t' read -r hpath fname; do
	if [ "$hpath" = "include/stats.h" ]; then
		emit_file="$JSON_EMITTED_FILE"
	else
		emit_file="$EMITTED_FILE"
	fi
	if ! grep -Fxq "$fname" "$emit_file"; then
		gf_key="UNEMITTED:${hpath}:${fname}"
		# Deduplicate (same field might appear in multiple struct bodies
		# within the same header)
		[ -n "${SEEN_UNEMITTED[$gf_key]+x}" ] && continue
		SEEN_UNEMITTED["$gf_key"]=1
		if [ -z "${GRANDFATHERED[$gf_key]+x}" ]; then
			new_unbaselined+=("$gf_key")
		fi
	fi
done < "$FIELDS_FILE"

# Stale baseline detection: listed entries no longer have unemitted fields
# (either wired to an emitter or the field was removed).  Stale entries must
# be pruned so the baseline stays accurate; a stale entry causes FAIL.
stale_baseline=()
for gf_entry in "${!GRANDFATHERED[@]}"; do
	if [ -z "${SEEN_UNEMITTED[$gf_entry]+x}" ]; then
		stale_baseline+=("$gf_entry")
	fi
done

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	{
		echo "  ${#new_unbaselined[@]} unemitted field(s) not in baseline:"
		for e in "${new_unbaselined[@]}"; do echo "    $e"; done
		echo ""
		echo "  Fields from stats/subsys/*.h must be referenced by any emitter"
		echo "  in stats/ (member access, STAT_FIELD* macro, or quoted key)."
		echo "  Fields from include/stats.h (struct stats_s) must be referenced"
		echo "  in stats/json/*.c -- a text-dump reference is not sufficient."
		echo ""
		echo "  fix (subsys/*.h): add STAT_FIELD_SUB(subsys, field) in the"
		echo "       matching stats/subsys/<subsys>.c descriptor table, or"
		echo "       emit directly from stats/json/ / stats/dump/."
		echo "  fix (include/stats.h): emit the field from stats/json/*.c."
		echo "  fix (either): if the field is intentional internal state"
		echo "       (window-start snapshot, scheduler state, placeholder),"
		echo "       add it to scripts/check-static/stats-field-unemitted.baseline"
		echo "       with a brief reason.  The baseline should shrink over time,"
		echo "       never grow."
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  ${#stale_baseline[@]} baseline entry/entries are stale"
		echo "  (the field is now emitted or was removed):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
		echo "  fix: remove the listed entries from"
		echo "       scripts/check-static/stats-field-unemitted.baseline"
	} >&2
	echo "FAIL: $NAME: ${#stale_baseline[@]} stale baseline entry/entries"
	exit 1
fi

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_unbaselined[@]} unemitted field(s) not in baseline"
	exit 1
fi

unemitted_n=${#SEEN_UNEMITTED[@]}
grandfathered_n=${#GRANDFATHERED[@]}
echo "PASS: $NAME (unemitted=${unemitted_n} grandfathered=${grandfathered_n})"
exit 0
