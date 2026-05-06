#pragma once

#include "child.h"
#include "list.h"
#include "object-types.h"
#include "syscall.h"
#include "types.h"

struct epollobj;

void setup_fd_providers(void);

bool open_fds(void);

void process_fds_param(char *optarg, bool enable);

struct fd_provider {
        struct list_head list;
	const char *name;
	enum objecttype objtype;
        int (*init)(void);
        int (*get)(void);
	int (*open)(void);
	void (*child_ops)(void);	/* optional: called periodically in child context */
	bool enabled;
	bool initialized;
	/*
	 * Set by providers whose fds back a kernel ->poll handler that can
	 * block indefinitely waiting on an external actor (FUSE userspace
	 * daemon, userfaultfd consumer, KVM vCPU thread, io_uring CQ
	 * producer, exiting task referenced by pidfd).  arm_epoll() and the
	 * epoll_ctl/poll/ppoll/select sanitisers refuse to populate watch
	 * sets with these fds: ep_item_poll runs the target ->poll
	 * synchronously inside EPOLL_CTL_ADD/MOD, ep_send_events, and
	 * __ep_eventpoll_poll, and a blocked ->poll wedges the calling task
	 * into TASK_UNINTERRUPTIBLE — SIGKILL and the watchdog cannot
	 * recover it, defer-slot-reuse pins the slot, and throughput
	 * collapses across the fleet.  The tagged fds remain available for
	 * direct read/write/recv/ioctl fuzzing — they are only barred from
	 * watch-set membership.  Defaults to false; providers opt in
	 * explicitly.
	 */
	bool poll_can_block;
};

void register_fd_provider(const struct fd_provider *prov);
void dump_fd_provider_names(void);
void run_fd_provider_child_ops(void);

bool check_if_fd(struct syscallrecord *rec);

/*
 * Return true if fd belongs to a registered fd_provider whose
 * poll_can_block tag is set.  Used by the epoll/select/poll sanitisers
 * (and arm_epoll) to refuse blocking-poll fds in watch sets.  Returns
 * false for untracked fds (no entry in the fd hash) and for fds whose
 * provider did not opt in.
 */
bool fd_poll_can_block(int fd);

int get_random_fd(void);
int get_new_random_fd(void);
int get_typed_fd(enum argtype type);
int get_child_live_fd(struct childdata *child);
void try_regenerate_fd(enum objecttype type);

/* Defined in fds/epoll.c — child-side lazy arm.  See block comment
 * above arm_epoll() for why arming must not run in parent context. */
void arm_epoll_if_needed(struct epollobj *eo);

#define REG_FD_PROV(_struct) \
	static void __attribute__((constructor)) register_##_struct(void) { \
		register_fd_provider(&_struct); \
	}
