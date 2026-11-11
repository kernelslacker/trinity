/*
 * prctl's sanitiser hands a PR_SET_SECCOMP draw a generated program in
 * arg3, which its post handler frees.  A test that runs the sanitiser
 * without the post handler frees it here.
 */
#pragma once

#include <stdlib.h>
#include <sys/prctl.h>
#include <linux/filter.h>

#include "syscall.h"	/* struct syscallrecord */

static inline void free_prctl_seccomp_program(const struct syscallrecord *rec)
{
#if defined(USE_SECCOMP) && defined(USE_BPF)
	struct sock_fprog *bpf = (struct sock_fprog *) rec->a3;

	if (rec->a1 != PR_SET_SECCOMP || bpf == NULL)
		return;
	free(bpf->filter);
	free(bpf);
#else
	(void) rec;
#endif
}
