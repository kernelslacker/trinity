#!/bin/bash
#
# post-double-publish: a `.post` handler must not call both register_*
# and publish_* on the same object.
#
# A syscall's return path already registers freshly-created objects
# (the syscallentry machinery calls add_object via the rettype/objtype
# table on a successful return).  A `.post` handler that calls a
# register_* helper AND a publish_* helper enrolls the same fd / id
# twice: once on the return path, once in the post handler.  The
# symptom shows up downstream as inflation of the per-provider gauge
# (e.g. the fd_hash count drifts upward across a fuzz run) and as
# duplicate entries that destroy_object can free twice on teardown.
#
# Either pattern alone is legal: register_* in a post handler is the
# normal way to record an out-band id (sysv key, pkey, timerid, ...),
# and publish_* in a non-post helper is the normal way to surface a
# child-local object into the per-child pool.  The bug shape is the
# combination inside a function whose name starts with post_.
#
# The check walks every C source under syscalls/ and childops/,
# extracts the body of every post_* function by tracking brace depth,
# and flags any body that contains both a register_<token>( callsite
# and a publish_<token>( callsite.

set -u

NAME="post-double-publish"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

# Awk walks each file once.  When it sees a line that opens a post_*
# function definition (post_<name>( at top level, with or without a
# leading `static`, returning void), it starts accumulating the body
# and counting braces.  When the brace count returns to zero the body
# is complete; if it mentioned both register_<token>( and
# publish_<token>( the handler is reported.
#
# Brace counting is line-granular -- adequate for the trinity coding
# style where `{` opens at end of line and `}` closes at column 0.
# A function-pointer table entry that happens to mention `register_`
# or `publish_` does not get scanned because table entries live
# outside any post_* function body.
find_post_handlers() {
	awk '
		function flush(    body_str) {
			if (!in_fn)
				return
			body_str = body
			if (body_str ~ /[^a-zA-Z0-9_]register_[a-zA-Z0-9_]+[[:space:]]*\(/ &&
			    body_str ~ /[^a-zA-Z0-9_]publish_[a-zA-Z0-9_]+[[:space:]]*\(/) {
				print FILENAME ":" start_line ":" fn_name
			}
			in_fn = 0
			seen_open = 0
			depth = 0
			body = ""
		}
		# Open a new post_* function body.  Only match a top-level
		# definition: the signature must start at column 0 and the
		# function name must begin with post_.
		!in_fn && /^(static[[:space:]]+)?void[[:space:]]+post_[a-zA-Z0-9_]+[[:space:]]*\(/ {
			match($0, /post_[a-zA-Z0-9_]+/)
			fn_name = substr($0, RSTART, RLENGTH)
			start_line = FNR
			in_fn = 1
			depth = 0
			seen_open = 0
			body = $0
			n = gsub(/\{/, "{", $0)
			m = gsub(/\}/, "}", $0)
			depth = n - m
			if (depth > 0)
				seen_open = 1
			if (seen_open && depth == 0)
				flush()
			next
		}
		in_fn {
			body = body "\n" $0
			line = $0
			n = gsub(/\{/, "{", line)
			m = gsub(/\}/, "}", line)
			depth += n - m
			if (depth > 0)
				seen_open = 1
			if (seen_open && depth == 0)
				flush()
		}
		END { flush() }
	' "$@"
}

# Build the file list.  syscalls/ has arch subdirectories
# (syscalls/x86/, syscalls/arm/, ...) so we want a recursive walk.
# childops/ is flat today but treat it the same way for symmetry.
mapfile -t SRCFILES < <(find syscalls childops \( -name '*.c' \) -type f \
		-not -path '*/.git/*' -print | sort)

if [ "${#SRCFILES[@]}" -eq 0 ]; then
	echo "FAIL: $NAME: no source files found under syscalls/ or childops/"
	exit 1
fi

find_post_handlers "${SRCFILES[@]}" > "$hits_tmp"

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: post handler(s) that call both register_* and publish_*:"
		while IFS=':' read -r file line fn; do
			echo "    $file:$line: $fn()"
		done < "$hits_tmp"
		echo "  fix: the syscall return path already adds the freshly-created"
		echo "       object via the rettype/objtype table; drop the duplicate"
		echo "       register_*/publish_* call from the post handler, or move"
		echo "       the publish to a non-post helper."
	} >&2
	echo "FAIL: $NAME: $n post handler(s) double-publish"
	exit 1
fi

echo "PASS: $NAME: 0 post handlers call both register_* and publish_*"
exit 0
