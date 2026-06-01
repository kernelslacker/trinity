#pragma once

#include <stddef.h>

struct syscallrecord;

/*
 * Post-handler shape shared by shmget/msgget/semget.  On the ordinary
 * failure path (ret < 0, e.g. EEXIST / ENOSPC / EACCES with errno set)
 * the helper returns silently.  Otherwise it validates that retval fits
 * in 0..INT_MAX -- a value outside that range is the footprint of a
 * wild write into the syscallrecord retval slot (or a torn read of a
 * concurrent update), and silently truncating to (int) would feed
 * register_fn a fabricated id that the per-pool destructor would later
 * IPC_RMID against an unrelated object on the host.  On out-of-range
 * retval the helper logs through the @name-tagged oracle line and
 * bumps the corrupt-ptr counter.  On a valid id it calls
 * @register_fn((int)id) to publish the id into the per-child OBJ_LOCAL
 * pool for the matching type.
 */
void post_ipc_get(struct syscallrecord *rec,
		  void (*register_fn)(int id),
		  const char *name);

/*
 * Allocate the IPC_STAT / IPC_INFO out-buffer snap shared by the
 * shmctl/msgctl sanitisers, stamp it with the magic cookie + inner-buf
 * pointer + size, hang it off rec->post_state, and register it in the
 * post-state ownership table.  The dense small-chunk profile of the
 * IPC info structs (struct shminfo / shm_info / msginfo / msqid_ds all
 * cluster in the same heap size class) makes rec->post_state a hot
 * target for sibling-stomp writes; the snap layout and gating
 * sequence is private to ipc-common.c.  Commands that take no
 * out-buffer (IPC_RMID / SHM_LOCK / SHM_UNLOCK) skip the call and
 * leave rec->post_state at zero; post_ipcctl_buf_free no-ops on the
 * NULL snap.
 */
void ipcctl_post_state_alloc(struct syscallrecord *rec,
			     void *buf, size_t buf_size);

/*
 * Post-handler shape shared by shmctl/msgctl IPC_STAT / IPC_INFO paths.
 * Walks the snap hung off rec->post_state, gates on heap-shape, magic
 * cookie, and ownership-table membership, then releases the inner IPC
 * buffer + the snap itself through deferred-free.  On any gate fail
 * the snap + inner buf leak rather than getting fed to free() with a
 * sibling-redirected pointer.  @name is the per-syscall log prefix
 * embedded in the outputerr() lines on reject.
 */
void post_ipcctl_buf_free(struct syscallrecord *rec, const char *name);
