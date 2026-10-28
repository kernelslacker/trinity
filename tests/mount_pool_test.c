/*
 * Self-check for the pools of real mount ids the statmount and listmount
 * sanitisers draw from: the mount syscalls take only unique ids, refusing
 * any at or below MNT_UNIQUE_ID_OFFSET (copy_mnt_id_req()), so the ids
 * they draw have to be ones a real call answers for.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "kernel/mount.h"	/* struct mnt_id_req, struct statmount */
#include "kernel/stat.h"	/* struct statx, STATX_MNT_ID_UNIQUE */
#include "kernel/unistd.h"	/* SYS_statmount, SYS_listmount */
#include "sanitise.h"		/* get_writable_address, writable_pool_init */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_statmount, syscall_listmount */
#include "utils.h"		/* waitpid_eintr, ARRAY_SIZE */

void mount_pool_self_check(void);

extern bool fake_random_fd_empty;	/* fake_stubs.c */

/* Sanitised calls per case: statmount draws from its pool six times in
 * ten, listmount half the time. */
#define POOL_DRAWS	200

/* What a child running a case exits with when the kernel has no unique
 * mount ids to judge by. */
#define NO_UNIQUE_IDS	77

/*
 * Run @drawn_ids_answer in a child: each sanitised call leaves buffers with
 * deferred free, which this binary's allocator never tracked, so the child
 * takes them with it.  A call by fd draws its fd from an empty pool.
 */
static void run_case(const char *name, bool (*drawn_ids_answer)(void))
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		struct statx stx;

		if (syscall(SYS_statx, AT_FDCWD, "/", 0, STATX_MNT_ID_UNIQUE,
			    &stx) != 0 || !(stx.stx_mask & STATX_MNT_ID_UNIQUE))
			_exit(NO_UNIQUE_IDS);
		fake_random_fd_empty = true;
		_exit(drawn_ids_answer() ? 0 : 1);
	}
	if (pid < 0 || waitpid_eintr(pid, &status, 0) != pid ||
	    !WIFEXITED(status))
		BUG("mount pool: a case did not run");
	if (WEXITSTATUS(status) == NO_UNIQUE_IDS) {
		printf("(no unique mount ids, skipping %s) ", name);
		return;
	}
	if (WEXITSTATUS(status) != 0) {
		fprintf(stderr, "mount pool: %s: no mount id it drew named a mount\n",
			name);
		BUG("mount pool: the sanitiser drew no real mount");
	}
}

#ifdef SYS_statmount
/* Whether some id statmount's sanitiser draws names a mount statmount()
 * answers for. */
static bool statmount_ids_answer(void)
{
	static struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < POOL_DRAWS; i++) {
		struct mnt_id_req req = {
			.size = MNT_ID_REQ_SIZE_VER0,
			.param = STATMOUNT_SB_BASIC,
		};
		struct statmount sm;

		memset(&rec, 0, sizeof(rec));
		syscall_statmount.sanitise(&rec);
		req.mnt_id = ((const struct mnt_id_req *) rec.a1)->mnt_id;
		if (syscall(SYS_statmount, &req, &sm, sizeof(sm), 0) == 0)
			return true;
	}
	return false;
}
#endif

#ifdef SYS_listmount
/* Whether some parent id listmount's sanitiser draws, other than
 * LSMT_ROOT, names a mount listmount() lists under.  The sanitiser takes
 * its id buffer from the writable pool. */
static bool listmount_ids_answer(void)
{
	static struct syscallrecord rec;
	unsigned int i;

	if (get_writable_address(sizeof(unsigned long)) == NULL)
		writable_pool_init();
	for (i = 0; i < POOL_DRAWS; i++) {
		struct mnt_id_req req = { .size = MNT_ID_REQ_SIZE_VER0 };
		__u64 ids[4];

		memset(&rec, 0, sizeof(rec));
		syscall_listmount.sanitise(&rec);
		if (rec.a1 == 0)
			continue;
		req.mnt_id = ((const struct mnt_id_req *) rec.a1)->mnt_id;
		if (req.mnt_id != LSMT_ROOT &&
		    syscall(SYS_listmount, &req, ids, ARRAY_SIZE(ids), 0) >= 0)
			return true;
	}
	return false;
}
#endif

void mount_pool_self_check(void)
{
#ifdef SYS_statmount
	run_case("statmount", statmount_ids_answer);
#endif
#ifdef SYS_listmount
	run_case("listmount", listmount_ids_answer);
#endif
}
