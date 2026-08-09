#!/bin/bash
#
# Suite entry for the commit-message hash reachability gate.  The real
# logic lives in scripts/commit-msg-hash-resolves.sh (also runnable
# standalone for manual audits with an explicit range).  Invoked here
# with no range so it defaults to origin/master..HEAD -- the unpushed
# commits, the natural pre-push scope.  Pre-existing dangling citations
# are grandfathered via commit-msg-hash-resolves.baseline; only NEW
# unreachable citations fail the suite.
set -u
ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
exec bash "$ROOT/scripts/commit-msg-hash-resolves.sh"
