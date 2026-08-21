#!/bin/bash
#
# strip-c-comments-selftest: verify that strip_c_comments() does not enter
# block- or line-comment state when /* or // appears inside a string literal
# or char literal.
#
# Background
# ----------
# strip_c_comments() in lib.sh strips C block comments (/* ... */) and line
# comments (//) before other gate scripts grep the result.  Without string-
# and char-literal state tracking, a /* inside "..." opens the block-comment
# state, and every line up to the next */ (or end-of-file if there is none)
# is silently dropped from the stripped output.  This makes the gate fail-
# open: patterns on those lines are invisible to all subsequent checks.
#
# Two cases are asserted here:
#
#   Case 1 — block-comment opener in string literal
#     const char *s = "a /* b";
#     if (getppid() == 1) { ... }
#   The getppid() == 1 line must survive stripping and therefore must be
#   flagged by getppid-one-literal.sh.  Before the fix, in_block was set by
#   the /* inside the string and never cleared, so line 2 was dropped.
#
#   Case 2 — line-comment opener in string literal
#     const char *url = "http://example.com";
#     if (getppid() == 1) { ... }
#   The // inside the string must not be treated as a line-comment opener;
#   the rest of the string and the remainder of that line must be preserved.
#   The getppid() == 1 line that follows must also survive.

set -u

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

NAME="strip-c-comments-selftest"

fail=0
pass=0

run_case() {
	local label="$1"
	local fixture="$2"
	local pattern="$3"

	local tmp
	tmp="$(mktemp /tmp/strip-c-selftest-XXXXXX.c)"
	printf '%s\n' "$fixture" > "$tmp"

	local stripped
	stripped="$(strip_c_comments "$tmp")"
	rm -f "$tmp"

	if echo "$stripped" | grep -qE "$pattern"; then
		pass=$((pass + 1))
	else
		echo "  $NAME: FAIL case '$label': pattern '$pattern' not found in stripped output" >&2
		echo "  stripped output was:" >&2
		echo "$stripped" | sed 's/^/    /' >&2
		fail=$((fail + 1))
	fi
}

# Case 1: /* inside a double-quoted string must not open block-comment state.
# The getppid() == 1 on the following line must remain visible after stripping.
run_case "block-opener-in-string-literal" \
	'void f(void) {
    const char *s = "a /* b";
    if (getppid() == 1) { bad(); }
}' \
	'getppid\(\)[[:space:]]*==[[:space:]]*1'

# Case 2: // inside a double-quoted string must not be treated as a line
# comment.  The rest of the string content and the getppid() line that follows
# must both survive stripping.
run_case "line-comment-opener-in-string-literal" \
	'void g(void) {
    const char *url = "http://example.com";
    if (getppid() == 1) { bad(); }
}' \
	'getppid\(\)[[:space:]]*==[[:space:]]*1'

# Case 3: /* inside a single-quoted char sequence must not open block-comment
# state.  Verify the line following it is preserved.
run_case "block-opener-in-char-literal" \
	"void h(void) {
    char a = '/';
    char b = '*';
    if (getppid() == 1) { bad(); }
}" \
	'getppid\(\)[[:space:]]*==[[:space:]]*1'

# Case 4: a real block comment (outside any literal) must still be stripped.
run_case "real-block-comment-is-stripped" \
	'void k(void) {
    /* getppid() == 1 inside a real comment */
    int x = 1;
}' \
	'^[[:space:]]*int x = 1;'

# Case 4b: the getppid pattern inside the real comment must NOT appear.
{
	tmp="$(mktemp /tmp/strip-c-selftest-XXXXXX.c)"
	printf 'void k(void) {\n    /* getppid() == 1 inside comment */\n    int x = 1;\n}\n' > "$tmp"
	stripped="$(strip_c_comments "$tmp")"
	rm -f "$tmp"
	if echo "$stripped" | grep -qE 'getppid\(\)'; then
		echo "  $NAME: FAIL case 'real-block-comment-not-visible': getppid() leaked from stripped comment" >&2
		fail=$((fail + 1))
	else
		pass=$((pass + 1))
	fi
}

total=$((pass + fail))

if [ "$fail" -gt 0 ]; then
	echo "FAIL: $NAME ($fail/$total assertions failed)"
	exit 1
fi

echo "PASS: $NAME ($pass/$total assertions)"
exit 0
