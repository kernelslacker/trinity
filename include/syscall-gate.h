#pragma once

/*
 * Honor -x at raw syscall(__NR_X, ...) sites in childops / fds that
 * bypass the syscall-table picker.  The syscall-table gate that -x
 * relies on only covers picks driven through random_syscall(); any
 * childop or fd-provider that issues syscall(__NR_X, ...) directly
 * for setup or teardown reaches the kernel unaltered, so an excluded
 * syscall stays observable in the test set unless every direct
 * issue site consults the exclusion mask first.
 *
 * Route those sites through trinity_raw_syscall() below.  When -x is
 * not in use (the common case) syscall_nr_is_excluded() returns on a
 * single do_exclude_syscall load and the macro compiles down to a
 * branch-predicted call to libc syscall(); when -x is in use the
 * excluded entry's ACTIVE flag is checked once per call and the
 * syscall is suppressed before it reaches the kernel.
 *
 * The wrapper deliberately fakes ENOSYS on a suppression so existing
 * childops fall into their already-present "kernel doesn't support
 * this" branch (iouring_recipes latches iouring_enosys on ENOSYS, for
 * instance) instead of needing new bespoke handling.  Real ENOSYS
 * returns from the kernel are indistinguishable from -x suppressions,
 * which is the desired semantics: a childop that cannot do its work
 * without an excluded syscall has nothing useful to fuzz this
 * iteration.
 */

#include <errno.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <unistd.h>

bool syscall_nr_is_excluded(int nr);

#define trinity_raw_syscall(nr, ...) \
	__extension__ ({ \
		long _trsr; \
		if (syscall_nr_is_excluded((int)(nr))) { \
			errno = ENOSYS; \
			_trsr = -1L; \
		} else { \
			_trsr = syscall((nr), ##__VA_ARGS__); \
		} \
		_trsr; \
	})
