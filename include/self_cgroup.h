#pragma once

/*
 * Self-cgroup: at startup, place trinity into its own cgroup v2 sub-cgroup
 * with a memory.max cap, so a runaway allocation triggers a scoped OOM
 * kill of trinity instead of a host-wide global OOM that takes down the
 * surrounding shell/tmux/ssh.  Cgroup v2 process membership is inherited
 * on plain fork(), so children land in the same cgroup with no extra
 * plumbing.  Failures degrade gracefully: trinity continues without the
 * safety net rather than refusing to start.
 *
 * Setup also arms an inotify watch on the new cgroup's memory.events
 * file so the parent can apply proactive back-pressure on memory.high
 * bumps (fork-rate throttle) and shed the youngest children on
 * memory.max bumps, ahead of the kernel-side OOM eviction.  Polled from
 * the parent's main_loop via self_cgroup_events_check().  When no
 * sub-cgroup was created (wrapper-detected, mkdir denied, etc.) the
 * watcher is a no-op.
 */
void self_cgroup_setup(void);
void self_cgroup_cleanup(void);
void self_cgroup_events_check(void);

/*
 * Per-spawn fork delay applied by the parent before each fork().  Set
 * by self_cgroup_events_check() in response to memory.high bumps and
 * decayed back to 0 after a quiet streak.  Read once per spawn from
 * spawn_child(); 0 means no throttle (the common case).
 */
extern unsigned int fork_throttle_us;
