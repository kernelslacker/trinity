#pragma once

/*
 * errno-classify.h -- canonical errno-set classifiers for the
 * "feature unsupported" semantic that recurs across childops, fds/
 * providers, and recipe-runner gates.
 *
 * Two typed helpers model the two dominant "unsupported" clusters:
 *
 *   is_syscall_unsupported() -- cap-gate cluster.  The syscall path
 *     is not reachable at all: kernel built without the option, the
 *     opcode is unknown, the caller lacks the capability, or the
 *     setsockopt name is not defined for this socket type.  Use on
 *     the first call in a probe sequence where you would latch the
 *     whole op off and never retry.
 *
 *   is_proto_family_unsupported() -- family-gate cluster.  socket(),
 *     bind() or connect() rejected the address family / protocol /
 *     socket type.  Use at the socket-creation site.
 *
 * EINVAL is deliberately excluded.  Per-feature latches that key on
 * EINVAL (a specific mode bit, a specific cipher, an XDP zerocopy
 * flag) carry information a wide helper would erase.  Callers that
 * need EINVAL must spell it out:
 *
 *     if (is_syscall_unsupported(errno) || errno == EINVAL)
 */

#include <errno.h>
#include <stdbool.h>

#ifndef ENOTSUP
#define ENOTSUP EOPNOTSUPP
#endif

static inline bool is_syscall_unsupported(int err)
{
	return err == ENOSYS || err == EOPNOTSUPP || err == ENOTSUP ||
	       err == ENOPROTOOPT || err == EPERM;
}

static inline bool is_proto_family_unsupported(int err)
{
	return err == EAFNOSUPPORT || err == EPROTONOSUPPORT ||
	       err == ESOCKTNOSUPPORT;
}
