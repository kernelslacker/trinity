#!/bin/bash
#
# sfg-phase-order-invariants: enforce the six phase-order rules the
# socket-family-grammar walk relies on for every `struct sfg_phase_order`
# initializer in the tree.
#
# net/proto/ipv4.c documents the invariants the run_grammar_chain walk
# assumes: SOCKET first; BIND before LISTEN; LISTEN before ACCEPT;
# DATA only after ACCEPT (STREAM triplets); PRE_CFG precedes BIND;
# POST_CFG follows BIND.  The framework-default order in
# net/socket-family-grammar-core.c and every family opt-in table are
# authored by hand, so a reordered entry compiles cleanly and only
# manifests at fuzz-host runtime -- exactly the class of regression
# check-static exists to catch pre-flight.
#
# This check parses every `struct sfg_phase_order` initializer (both
# single-instance objects and array tables), splits on SFG_PHASE_END
# to yield each ordering, and asserts:
#
#   1. First non-END step is SFG_PHASE_SOCKET.
#   2. If BIND and LISTEN both appear, BIND index < LISTEN index.
#   3. If LISTEN and ACCEPT both appear, LISTEN index < ACCEPT index.
#   4. If DATA appears, ACCEPT must also appear and precede it.
#   5. If PRE_CFG and BIND both appear, PRE_CFG index < BIND index.
#   6. If POST_CFG and BIND both appear, POST_CFG index > BIND index.
#
# Rules 2-6 are guarded by "if both phases appear" so tables that use
# a disjoint phase vocabulary (e.g. AF_ALG's SFG_PHASE_ALG_* set,
# which shares only SOCKET with the base grammar) satisfy them
# vacuously.  Rule 1 is universal -- every ordering in the tree
# starts at SOCKET regardless of family, because the socket() call is
# what produces the fd the rest of the walk operates on.

set -u

NAME="sfg-phase-order-invariants"
ROOT="${REPO_ROOT:-$(pwd)}"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

cd "$ROOT" || fail "cannot cd to $ROOT"

# Collect the source files that mention struct sfg_phase_order.  A
# grep -l over .c/.h files is the source of truth -- the tables live
# next to their grammar, so hardcoding paths would rot the moment a
# new family lands.
files=$(grep -rl --include='*.c' --include='*.h' \
	'struct sfg_phase_order' . 2>/dev/null \
	| grep -v '^\./scripts/' | sort -u)

[ -n "$files" ] || fail "no source files reference struct sfg_phase_order"

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

python3 - "$hits_tmp" $files <<'PY'
import re
import sys

hits_path = sys.argv[1]
files = sys.argv[2:]

# Regex matches both the array form
#   static const struct sfg_phase_order NAME[] = {
# and the single-instance form
#   static const struct sfg_phase_order NAME = {
# with any storage-class / const / attribute preamble.
DECL_RE = re.compile(
	r'\bstruct\s+sfg_phase_order\b[^;{]*=\s*\{'
)
PHASE_TOK_RE = re.compile(r'\bSFG_PHASE_[A-Z0-9_]+\b')

# Positional invariants — encoded as (name, predicate) pairs so a
# failure names the rule that fired.
def invariants(seq):
	def idx(tok):
		return seq.index(tok) if tok in seq else -1
	socket_i  = idx('SFG_PHASE_SOCKET')
	bind_i    = idx('SFG_PHASE_BIND')
	listen_i  = idx('SFG_PHASE_LISTEN')
	accept_i  = idx('SFG_PHASE_ACCEPT')
	data_i    = idx('SFG_PHASE_DATA')
	pre_i     = idx('SFG_PHASE_PRE_CFG')
	post_i    = idx('SFG_PHASE_POST_CFG')

	violations = []
	# 1. SOCKET first.
	if not seq or seq[0] != 'SFG_PHASE_SOCKET':
		violations.append(
			'rule 1 (SOCKET first): first step is %s'
			% (seq[0] if seq else '<empty>'))
	# 2. BIND before LISTEN.
	if bind_i >= 0 and listen_i >= 0 and not (bind_i < listen_i):
		violations.append(
			'rule 2 (BIND before LISTEN): BIND@%d LISTEN@%d'
			% (bind_i, listen_i))
	# 3. LISTEN before ACCEPT.
	if listen_i >= 0 and accept_i >= 0 and not (listen_i < accept_i):
		violations.append(
			'rule 3 (LISTEN before ACCEPT): LISTEN@%d ACCEPT@%d'
			% (listen_i, accept_i))
	# 4. DATA only after ACCEPT.
	if data_i >= 0:
		if accept_i < 0:
			violations.append(
				'rule 4 (DATA needs ACCEPT): DATA@%d, no ACCEPT'
				% data_i)
		elif not (accept_i < data_i):
			violations.append(
				'rule 4 (ACCEPT before DATA): ACCEPT@%d DATA@%d'
				% (accept_i, data_i))
	# 5. PRE_CFG precedes BIND.
	if pre_i >= 0 and bind_i >= 0 and not (pre_i < bind_i):
		violations.append(
			'rule 5 (PRE_CFG before BIND): PRE_CFG@%d BIND@%d'
			% (pre_i, bind_i))
	# 6. POST_CFG follows BIND.
	if post_i >= 0 and bind_i >= 0 and not (post_i > bind_i):
		violations.append(
			'rule 6 (POST_CFG after BIND): POST_CFG@%d BIND@%d'
			% (post_i, bind_i))
	return violations

total_orderings = 0
hits = []

for path in files:
	try:
		with open(path, 'r', encoding='utf-8', errors='replace') as fh:
			src = fh.read()
	except OSError as e:
		print('FAIL: %s: cannot read %s: %s' % (
			'sfg-phase-order-invariants', path, e),
			file=sys.stderr)
		sys.exit(1)

	# Strip /* ... */ block comments and // line comments so a
	# commented-out example never contributes phase tokens.  Keep
	# newlines so line-number reporting stays close to reality.
	src_nc = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'),
			src, flags=re.DOTALL)
	src_nc = re.sub(r'//[^\n]*', '', src_nc)

	for m in DECL_RE.finditer(src_nc):
		start = m.end() - 1  # index of the opening '{'
		# Walk forward to the matching top-level '};' — the
		# outer initializer terminator.
		depth = 0
		i = start
		end = None
		while i < len(src_nc):
			c = src_nc[i]
			if c == '{':
				depth += 1
			elif c == '}':
				depth -= 1
				if depth == 0:
					# expect ';' shortly after
					end = i + 1
					break
			i += 1
		if end is None:
			hits.append('%s: unterminated struct sfg_phase_order '
				    'initializer starting near offset %d'
				    % (path, start))
			continue

		block = src_nc[start:end]
		block_line = src_nc.count('\n', 0, start) + 1

		# Split into orderings on SFG_PHASE_END.  Each preceding
		# run of SFG_PHASE_* tokens (minus the END sentinel) is
		# one ordering.
		toks = PHASE_TOK_RE.findall(block)
		if not toks:
			hits.append('%s:%d: struct sfg_phase_order '
				    'initializer contains no SFG_PHASE_* '
				    'tokens' % (path, block_line))
			continue

		current = []
		orderings = []
		for t in toks:
			if t == 'SFG_PHASE_END':
				orderings.append(current)
				current = []
			else:
				current.append(t)
		# Trailing tokens with no END: report as its own
		# malformed-entry hit.
		if current:
			hits.append('%s:%d: struct sfg_phase_order entry '
				    'missing SFG_PHASE_END sentinel: %s'
				    % (path, block_line, ' '.join(current)))

		for entry_idx, seq in enumerate(orderings):
			total_orderings += 1
			if not seq:
				hits.append('%s:%d: entry #%d is empty '
					    '(SFG_PHASE_END with no prior '
					    'steps)' % (path, block_line,
					    entry_idx))
				continue
			for v in invariants(seq):
				hits.append('%s:%d: entry #%d: %s; order: %s'
					    % (path, block_line, entry_idx, v,
					       ' '.join(seq)))

with open(hits_path, 'w') as out:
	for h in hits:
		out.write(h + '\n')
	out.write('__TOTAL__ %d\n' % total_orderings)
PY

total=$(awk '/^__TOTAL__ / { print $2 }' "$hits_tmp")
hit_lines=$(grep -v '^__TOTAL__ ' "$hits_tmp" || true)
n=0
[ -n "$hit_lines" ] && n=$(printf '%s\n' "$hit_lines" | grep -c '^')

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: phase-order invariant violation(s):"
		printf '%s\n' "$hit_lines" | sed 's/^/    /'
		echo "  fix: reorder the offending entry so that:"
		echo "    - SFG_PHASE_SOCKET appears first"
		echo "    - SFG_PHASE_PRE_CFG (if present) precedes SFG_PHASE_BIND"
		echo "    - SFG_PHASE_POST_CFG (if present) follows SFG_PHASE_BIND"
		echo "    - SFG_PHASE_BIND precedes SFG_PHASE_LISTEN"
		echo "    - SFG_PHASE_LISTEN precedes SFG_PHASE_ACCEPT"
		echo "    - SFG_PHASE_DATA follows SFG_PHASE_ACCEPT"
		echo "  See net/proto/ipv4.c above inet_tcp_orders[] for the"
		echo "  authoritative statement of these invariants."
	} >&2
	echo "FAIL: $NAME: $n violation(s) across $total ordering(s)"
	exit 1
fi

[ "${total:-0}" -gt 0 ] || fail "parsed 0 orderings — regex or file list is stale"

echo "PASS: $NAME: $total ordering(s) satisfy all six invariants"
exit 0
