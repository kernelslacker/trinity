#pragma once

/*
 * Self-cgroup: at startup, place trinity into its own cgroup v2 sub-cgroup
 * with a memory.max cap, so a runaway allocation triggers a scoped OOM
 * kill of trinity instead of a host-wide global OOM that takes down the
 * surrounding shell/tmux/ssh.  Cgroup v2 process membership is inherited
 * on plain fork(), so children land in the same cgroup with no extra
 * plumbing.  Failures degrade gracefully: trinity continues without the
 * safety net rather than refusing to start.
 */
void self_cgroup_setup(void);
void self_cgroup_cleanup(void);
