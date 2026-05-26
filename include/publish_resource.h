#pragma once

#include "object-types.h"

/*
 * publish_resource() — single typed entry point for surfacing a freshly
 * minted kernel handle (fd, aio context, key serial, pid, sysv id, ...)
 * into the per-child OBJ_LOCAL pool of the requested type.
 *
 * Post handlers and the post-handler-shaped childops sites currently
 * open-code the three-line pattern
 *
 *     obj = alloc_object();
 *     obj-><typed-union-field> = id;
 *     [obj-><other-field>      = flags;]
 *     add_object(obj, OBJ_LOCAL, OBJ_<TYPE>);
 *
 * across ~70 producers, each one stamping the union member by hand
 * for the matching OBJ_<TYPE>.  The shape of the stamp varies — some
 * carry only the fd, some carry a flags word, some carry a bpf
 * subtype, a memfd name pointer, a pidfd's owning pid, ... — but the
 * routing decision is the same enum switch every time.
 *
 * Centralising the switch behind one call lets producers stop
 * hand-rolling the publish path and lets diagnostic / audit tooling
 * grep one symbol (`publish_resource(`) instead of chasing the
 * scattered alloc_object()/add_object() pairs.  The wrapper is
 * additive — existing producers keep working unchanged; per-consumer
 * migrations land as separate follow-up commits, one site at a time.
 */

/*
 * Optional secondary metadata.  All fields default to zero / NULL;
 * callers fill only the ones their object type actually consumes.
 *
 * Field-to-pool mapping (NULL meta == every field zero):
 *
 *   flags       — eventfd/inotify/userfaultfd/fanotify/memfd/
 *                 memfd_secret/perf primary flags word
 *   aux         — fanotify event_f_flags (secondary flags),
 *                 timerfd clockid, kvm_system api_version
 *   subtype     — bpf map_type / prog_type / attach_type
 *   extra_int   — eventfd count, pidfd owning pid
 *   name        — memfd display name.  The wrapper stores the pointer
 *                 as-is; the caller (or the per-pool destroy callback)
 *                 retains lifetime ownership.  No strdup happens here.
 *
 * Pools whose per-object struct carries fields the unified shape
 * cannot cleanly hold (mmap's strdup'd name + ptr + size + prot +
 * flags + type tuple, sockinfo's inherited triplet, watch_queue's
 * peer_fd, pipe's reader bool, epoll's create1/pool_idx, the kvm_vm
 * / kvm_vcpu parent-fd graph) intentionally fall through to the
 * "id only" path: publish_resource() stamps the primary handle and
 * returns the obj pointer so the caller can patch any remaining
 * pool-specific fields before the obj escapes the publish site.
 */
struct resource_meta {
	unsigned int flags;
	unsigned int aux;
	unsigned int subtype;
	int extra_int;
	char *name;
};

struct object;

/*
 * Publish @id into the OBJ_LOCAL pool for @type, with optional
 * @meta secondary state.
 *
 * @id is interpreted by the per-type stamp:
 *   - FD pools           — (int)@id is the kernel fd
 *   - OBJ_AIO_CTX        — @id is the io_setup context cookie
 *   - OBJ_KEY_SERIAL     — (int32_t)@id is the keyring serial
 *   - OBJ_PKEY           — (int)@id is the protection-key index
 *   - OBJ_TIMERID        — (int32_t)@id is the POSIX timer id
 *   - OBJ_PID            — (pid_t)@id is the owning pid
 *   - OBJ_SYSV_SEM/MSG   — (int)@id is the sem/msq id
 *
 * Returns the published object on success so callers that need to
 * patch a not-covered field can chase it.  Returns NULL on
 * alloc_object() failure or when @type is not routed by the wrapper
 * (mmap, sockinfo, watch_queue, pipe, epoll, kvm_vm, kvm_vcpu,
 * futex/sysv_shm — these carry pool-specific allocations or
 * inherited state that the unified shape cannot represent).  On
 * failure the caller still owns @id; the wrapper performs no
 * cleanup of the kernel handle.
 */
struct object *publish_resource(enum objecttype type, unsigned long id,
				const struct resource_meta *meta);
