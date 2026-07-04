#!/bin/bash
#
# signal-handler-async-unsafe: forbid async-signal-UNSAFE libc calls
# inside known signal handlers.
#
# POSIX 2024 §2.4.3 lists the small, finite set of libc entry points
# that are safe to call from a signal handler.  Anything outside that
# set (snprintf, malloc, fopen, syslog, strerror, exit, ...) is unsafe:
# the call can deadlock or corrupt state if the signal arrived while
# another thread (or the interrupted thread itself) was already inside
# malloc / stdio / locale / syslog and holding the relevant lock.
#
# child_fault_handler was recently caught calling snprintf() at two
# sites; the fix (route via sigsafe_* helpers + a single write()) just
# landed.  This check stops that class of regression by greping the
# body of each known signal handler in health/signals.c for an unsafe-libc
# denylist and failing the build if anything matches.
#
# Handler discovery: scrape sa_sigaction=<fn> and sa_handler=<fn>
# assignments in health/signals.c.  Body extraction: find "void <fn>(" and
# brace-count from the first '{' to the matching '}'.  Hits are
# filtered through the same comment-line filter no-libc-rand.sh uses
# (leading /*, *, //) to suppress false positives in doc comments.
#
# Allowlist is by construction -- the denylist deliberately omits the
# async-signal-safe primitives the existing handlers rely on:
#   write, _exit, kill, raise, signal, sigaction, sigprocmask,
#   pthread_sigmask, time, clock_gettime, getpid, umask, open, close,
#   dup2, read, fcntl, ... (full set in POSIX 2024 §2.4.3)
# and the trinity-internal sigsafe_* helpers in health/signals.c (no libc
# state touched -- byte stores into a caller-owned stack buffer).
#
# If this check ever fires, either (a) a real bug was introduced, or
# (b) handler discovery picked up something that is not actually
# installed as a handler -- inspect the handler list printed on FAIL.

set -u

NAME="signal-handler-async-unsafe"
ROOT="${REPO_ROOT:-$(pwd)}"
TARGET="health/signals.c"

# Async-signal-UNSAFE libc functions.  Token list mirrors no-libc-rand.sh:
# match the name on a word boundary followed by '(' so unrelated symbols
# (exit_reason, free_list, malloc_zone_t, fopen_path, ...) do not trip.
# Conservative subset of the actual POSIX-unsafe surface -- false
# positives here are easy to fix; misses cost a deadlock in production.
DENYLIST='\b(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|asprintf|vasprintf|dprintf|vdprintf|malloc|calloc|realloc|free|reallocarray|posix_memalign|aligned_alloc|fopen|fclose|fread|fwrite|fgets|fputs|fgetc|fputc|getline|getdelim|getc|putc|fflush|fseek|ftell|setvbuf|setbuf|strerror|perror|syslog|openlog|closelog|exit|atexit|on_exit)[[:space:]]*\('

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

if [ ! -f "$TARGET" ]; then
	echo "FAIL: $NAME: $TARGET not found"
	exit 1
fi

# Discover handler names: every function name assigned to either
# sa_sigaction or sa_handler in health/signals.c.  SIG_DFL / SIG_IGN are
# kernel sentinels, not functions, and are filtered out.
handlers="$(
	{
		grep -hE 'sa_sigaction[[:space:]]*=' "$TARGET" \
			| sed -E 's/.*sa_sigaction[[:space:]]*=[[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/'
		grep -hE 'sa_handler[[:space:]]*=' "$TARGET" \
			| sed -E 's/.*sa_handler[[:space:]]*=[[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/'
	} | sort -u | grep -vE '^(SIG_DFL|SIG_IGN)$'
)"

if [ -z "$handlers" ]; then
	echo "FAIL: $NAME: no signal handlers discovered in $TARGET"
	exit 1
fi

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

# For each handler, emit "file|line|fn|content" for every line in the
# function body.  Body extraction: regex-match "void <fn>(" (handles
# multi-line signatures where attributes sit on the prior line), then
# brace-count from the first '{' to the matching '}'.  Pipe-delimited
# so a ':' inside source content does not corrupt downstream splitting.
for fn in $handlers; do
	awk -v fn="$fn" -v file="$TARGET" '
		!found && $0 ~ ("(^|[[:space:]])void[[:space:]]+" fn "[[:space:]]*\\(") {
			found = 1; started = 0; depth = 0
		}
		found {
			line = $0
			n = length(line)
			for (i = 1; i <= n; i++) {
				c = substr(line, i, 1)
				if (c == "{") {
					if (!started) { started = 1; depth = 1 }
					else depth++
				} else if (c == "}") {
					if (started) {
						depth--
						if (depth == 0) {
							print file "|" NR "|" fn "|" $0
							found = 0; started = 0
							next
						}
					}
				}
			}
			if (started) print file "|" NR "|" fn "|" $0
		}
	' "$TARGET"
done | grep -E "$DENYLIST" | \
while IFS='|' read -r path lineno fnname content; do
	# Trim leading whitespace.
	trimmed="${content#"${content%%[![:space:]]*}"}"

	# Skip comment-only lines (block-comment continuation, banner
	# opener, line comment).  Same filter as no-libc-rand.sh.
	case "$trimmed" in
		\**)    continue ;;
		/\**)   continue ;;
		//*)    continue ;;
	esac

	# Extract the offending call name for the FAIL message.
	call="$(printf '%s\n' "$trimmed" | grep -oE "$DENYLIST" | head -n1 \
		| sed -E 's/[[:space:]]*\($//')"

	echo "$path:$lineno: $fnname: $call"
done > "$hits_tmp"

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: async-signal-unsafe libc call(s) inside signal handler(s):"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: emit diagnostics via the sigsafe_* helpers + write()"
		echo "       (see health/signals.c::write_siginfo_safely for the pattern)."
		echo "       POSIX 2024 §2.4.3 lists the small set of safe libc"
		echo "       calls; nothing outside that set is safe in a handler."
	} >&2
	while IFS= read -r hit; do
		echo "FAIL: $NAME: $hit"
	done < "$hits_tmp"
	exit 1
fi

echo "PASS: $NAME"
exit 0
