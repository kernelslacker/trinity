#!/bin/bash
# stats-group-has-producer: every group in struct stats_s must be written
# by something outside stats/.
#
# The complement of check-stats-reachable, which asks whether a field is
# EMITTED.  This asks whether it is PRODUCED.  A group with a descriptor row
# and no writer renders as an all-zero object forever, and a consumer cannot
# tell "the workload ran and found nothing" from "the workload was deleted" --
# which is exactly what thirty-six groups did after the childop strip.
#
# Writers are counted in three forms, because a group can be bumped through
# any of them:
#   shm->stats.<group>.<field>
#   offsetof(struct stats_s, <group>.<field>)   (computed-pointer writers)
#   parent_stats.<group>.<field>
set -uo pipefail

NAME="stats-group-has-producer"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

_groups() {
	python3 - "$1" <<'PYEOF'
import re,sys
s=open(sys.argv[1]).read()
i=s.index('struct stats_s {')
d=0;j=i
while j<len(s):
    if s[j]=='{': d+=1
    elif s[j]=='}':
        d-=1
        if d==0: break
    j+=1
for _t,n in re.findall(r'\bstruct\s+(\w+_stats)\s+(\w+)\s*(?:__attribute__\(\(aligned\(64\)\)\))?\s*;', s[i:j]):
    print(n)
PYEOF
}

_has_writer() {
	grep -rlE "shm->stats\.$1\b|offsetof\(struct stats_s, *$1\.|parent_stats\.$1\b" \
		--include=*.c --include=*.h . 2>/dev/null \
		| grep -v '^\./stats/\|^\./include/stats' | head -1
}

# Self-test: the detector must accept the offsetof form.  A plain
# "shm->stats.X." grep reports the live procfs_writer group as dead, because
# it records through a computed pointer built from offsetof().
if ! grep -rq 'offsetof(struct stats_s, *procfs_writer\.' --include=*.c childops/ 2>/dev/null; then
	echo "SKIP: $NAME: offsetof self-test fixture is gone (procfs_writer)"
else
	if [ -z "$(_has_writer procfs_writer)" ]; then
		echo "FAIL: $NAME: self-test: offsetof-form writer not detected (detector broken)"
		exit 1
	fi
fi

groups="$(_groups include/stats.h)"
[ -n "$groups" ] || { echo "FAIL: $NAME: no groups parsed from struct stats_s"; exit 1; }

dead=""
n=0
for g in $groups; do
	n=$((n + 1))
	[ -n "$(_has_writer "$g")" ] || dead="$dead $g"
done

if [ -n "$dead" ]; then
	{
		echo "  $NAME: stats_s group(s) with no writer outside stats/:"
		for g in $dead; do echo "    $g"; done
		echo "  fix: delete the group, its descriptor and its storage, or"
		echo "       point it at the code that is supposed to fill it."
	} >&2
	echo "FAIL: $NAME: $(echo $dead | wc -w) producerless group(s) of $n"
	exit 1
fi

echo "PASS: $NAME ($n group(s), all produced)"
exit 0
