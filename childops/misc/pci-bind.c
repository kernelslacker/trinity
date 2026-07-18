/*
 * pci_bind - drive bind/unbind churn on a conservative hardcoded
 * allowlist of PCI drivers whose teardown path is by-design safe to
 * poke from a fuzzer.
 *
 * Driver probe/remove is one of the least-exercised classes of code in
 * the kernel: production workloads bind once at boot and keep devices
 * bound for the box's lifetime, and a syscall-only fuzzer never touches
 * the driver core attach/detach machinery at all.  The result is a long
 * tail of probe/remove bugs -- refcount mistakes in failure paths,
 * dangling pointers in teardown, double-frees on rebind, PM state
 * desync -- that nobody else finds.
 *
 * Phase 1 deliberately stays inside a tiny hand-curated allowlist:
 *
 *   - pci-pf-stub: the upstream "placeholder driver for unbound PFs",
 *     designed to be a bind/unbind target for testing harnesses.
 *   - vfio-pci / vfio_pci: the userspace driver interface.  Anything
 *     bound here was already detached from the kernel driver that
 *     normally owns it; bind/unbind on this surface is exactly what
 *     VFIO consumers do at startup.
 *
 * No other driver is touched.  Active NIC drivers (e1000/mlx5_core/etc),
 * root-storage drivers (nvme/ahci/virtio_blk/etc), GPU drivers
 * (i915/amdgpu/nouveau) -- none of these are in the allowlist, so the
 * worst-case outcome of any single invocation is a kernel `.store()`
 * handler running on a device that was already safe to detach.
 *
 * Phase 2 (separate change) will replace the static allowlist with a
 * runtime active-device detector (default route NIC, root block device
 * backing, IOMMU group co-residents) plus a broader denylist, opening
 * the surface to every PCI driver that the host's running services do
 * not currently depend on.  Phase 1 ships first so the wire-up itself
 * has run long enough to be confidently clean before the broader
 * surface lands.
 *
 * Per invocation: pick a random driver from the available subset of
 * the allowlist, enumerate the BDFs currently bound to it, pick one,
 * write it to `unbind` then write it back to `bind`.  No sleep between
 * -- let the kernel side race naturally between detach and reattach.
 * If the host has none of the allowlist drivers loaded, or the picked
 * driver has no bound devices, the invocation is a no-op success.
 *
 * Init-latch (one-shot per process): probe /sys/bus/pci/drivers/ once.
 * If the directory doesn't exist (no CONFIG_PCI) or none of the
 * allowlist drivers are present, latch the op disabled for the rest of
 * process lifetime.
 *
 * Listed in dormant_op_disabled[] -- promoted by the canary queue
 * after it produces edges without self-crashing.  Excluded from
 * alt_op_rotation[] by entry in alt-op-rotation.denylist (device
 * lifecycle race; same shape as ublk_lifecycle / blkdev_lifecycle).
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "child.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#define PCI_BIND_BUS_DIR	"/sys/bus/pci/drivers"
#define PCI_BIND_BDF_LEN	13U	/* "0000:bb:dd.f" + NUL */
#define PCI_BIND_DEVS_MAX	256U	/* per-driver enum cap */

/*
 * Conservative Phase 1 allowlist.  See file banner for rationale.
 * Both spellings of the VFIO driver appear in shipping kernel
 * configs (the underscore form is what /sys exposes when the module
 * name has not been aliased; the dash form is the upstream-canonical
 * spelling) -- list both and let the probe filter to whichever the
 * running kernel actually publishes.
 */
static const char * const pci_bind_safe_drivers[] = {
	"pci-pf-stub",
	"vfio-pci",
	"vfio_pci",
};

#define NR_PCI_BIND_DRIVERS	ARRAY_SIZE(pci_bind_safe_drivers)

_Static_assert(NR_PCI_BIND_DRIVERS <= 8,
	"pci_bind_avail_mask must hold one bit per driver");

/*
 * Per-process latches.  Set on the first probe and never cleared:
 * the set of installed drivers does not change across the trinity
 * process's lifetime (driver modules can in theory be loaded after
 * trinity start, but the workload trinity targets is "kernel with
 * all drivers already up").
 */
static bool pci_bind_probed;
static bool pci_bind_unsupported;
static uint8_t pci_bind_avail_mask;

/*
 * Cheap syntactic check that a dirent name looks like a PCI BDF
 * symlink (kernel format: "0000:bb:dd.f").  Cheap-and-strict: we
 * only need to filter the driver dir's "bind", "unbind", "uevent",
 * "module" etc. siblings out of the bound-device enumeration.  The
 * real parser runs on the kernel side when we write the string.
 */
static bool is_bdf_name(const char *name)
{
	unsigned int i;

	if (strlen(name) != 12U)
		return false;
	for (i = 0; i < 4U; i++)
		if (!isxdigit((unsigned char)name[i]))
			return false;
	if (name[4] != ':')
		return false;
	for (i = 5U; i < 7U; i++)
		if (!isxdigit((unsigned char)name[i]))
			return false;
	if (name[7] != ':')
		return false;
	for (i = 8U; i < 10U; i++)
		if (!isxdigit((unsigned char)name[i]))
			return false;
	if (name[10] != '.')
		return false;
	return isxdigit((unsigned char)name[11]) != 0;
}

/*
 * One-shot startup probe.  Stat /sys/bus/pci/drivers/ and then each
 * allowlist driver dir; build the avail_mask of drivers actually
 * present on the host.  Latch unsupported if nothing matched.
 *
 * No log emitted from here: init_child() (child.c) redirects child
 * stdio to /dev/null so a child-context output() vanishes silently.
 * The available-driver count is exposed via pci_bind_drivers_available
 * in shm->stats, which the parent's periodic stat_row dump surfaces
 * for the operator.
 */
static void pci_bind_probe(struct childdata *child)
{
	char path[160];
	struct stat st;
	unsigned int i;
	unsigned int found = 0;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	pci_bind_probed = true;

	if (stat(PCI_BIND_BUS_DIR, &st) < 0 || !S_ISDIR(st.st_mode)) {
		pci_bind_unsupported = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return;
	}

	for (i = 0; i < NR_PCI_BIND_DRIVERS; i++) {
		(void)snprintf(path, sizeof(path), "%s/%s",
			       PCI_BIND_BUS_DIR, pci_bind_safe_drivers[i]);
		if (stat(path, &st) < 0 || !S_ISDIR(st.st_mode))
			continue;
		pci_bind_avail_mask |= (uint8_t)(1U << i);
		found++;
	}

	__atomic_store_n(&shm->stats.pci_bind.drivers_available,
			 found, __ATOMIC_RELAXED);

	if (pci_bind_avail_mask == 0U) {
		pci_bind_unsupported = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_UNSUPPORTED,
					 __ATOMIC_RELAXED);
	}
}

/*
 * Pick a random driver index whose bit is set in pci_bind_avail_mask.
 * Caller has already confirmed the mask is non-zero.  Linear scan from
 * a random start so a host with only one available driver still rotates
 * trivially through that single driver.
 */
static unsigned int pci_bind_pick_driver(void)
{
	unsigned int start = rnd_modulo_u32(NR_PCI_BIND_DRIVERS);
	unsigned int i;

	for (i = 0; i < NR_PCI_BIND_DRIVERS; i++) {
		unsigned int idx = (start + i) % NR_PCI_BIND_DRIVERS;

		if (pci_bind_avail_mask & (uint8_t)(1U << idx))
			return idx;
	}
	return 0;	/* unreachable: caller checked the mask */
}

/*
 * Enumerate bound-device symlinks inside /sys/bus/pci/drivers/<drv>/
 * and copy up to PCI_BIND_DEVS_MAX BDF strings into devs[].  Returns
 * the count; 0 means the driver has no currently-bound devices (or
 * the dir vanished between the probe and now).
 *
 * One retry on a top-level ENOENT: opendir can race a concurrent
 * driver module-unload that removed the dir between the probe and
 * here.  No retry on per-entry ENOENT because readdir doesn't report
 * one and stat-ing each name would be overhead the bind/unbind
 * write itself will surface as ENODEV anyway.
 */
static unsigned int pci_bind_collect_devs(const char *drv,
					  char devs[][PCI_BIND_BDF_LEN])
{
	char dirpath[160];
	DIR *d;
	struct dirent *de;
	unsigned int count = 0;
	int retried = 0;

	(void)snprintf(dirpath, sizeof(dirpath), "%s/%s",
		       PCI_BIND_BUS_DIR, drv);

retry:
	d = opendir(dirpath);
	if (d == NULL) {
		if (errno == ENOENT && retried++ == 0)
			goto retry;
		return 0;
	}

	while ((de = readdir(d)) != NULL && count < PCI_BIND_DEVS_MAX) {
		if (!is_bdf_name(de->d_name))
			continue;
		/* is_bdf_name() above already validated the 12-char BDF
		 * shape so this fits PCI_BIND_BDF_LEN exactly.  Explicit
		 * precision keeps -Wformat-truncation quiet without
		 * relying on snprintf's silent clamp. */
		(void)snprintf(devs[count], PCI_BIND_BDF_LEN, "%.*s",
			       PCI_BIND_BDF_LEN - 1, de->d_name);
		count++;
	}
	closedir(d);
	return count;
}

/*
 * Open /sys/bus/pci/drivers/<drv>/<attr> O_WRONLY and write @bdf.
 * Returns true when the kernel-side .store() handler actually ran
 * (write succeeded OR write returned EINVAL/ENODEV -- both mean the
 * handler executed; the latter means the BDF was already detached or
 * matched a different driver, which is the expected racy outcome).
 * Returns false on infrastructure failures (open failed, EACCES from
 * a non-root run).  *errno_out is the errno seen on the failing call,
 * or 0 on clean success.
 */
static bool pci_bind_write_bdf(const char *drv, const char *attr,
			       const char *bdf, int *errno_out)
{
	char path[192];
	int fd;
	ssize_t w;
	size_t len;

	*errno_out = 0;
	(void)snprintf(path, sizeof(path), "%s/%s/%s",
		       PCI_BIND_BUS_DIR, drv, attr);

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		*errno_out = errno;
		return false;
	}

	len = strlen(bdf);
	w = write(fd, bdf, len);
	if (w < 0)
		*errno_out = errno;
	close(fd);

	if (w >= 0)
		return true;
	return (*errno_out == EINVAL || *errno_out == ENODEV);
}

bool pci_bind(struct childdata *child)
{
	char devs[PCI_BIND_DEVS_MAX][PCI_BIND_BDF_LEN];
	unsigned int n_devs, pick, drv_idx;
	const char *drv;
	const char *bdf;
	int err_unbind = 0;
	int err_bind = 0;
	bool ran_unbind;
	bool ran_bind;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.pci_bind.runs, 1, __ATOMIC_RELAXED);

	if (!pci_bind_probed)
		pci_bind_probe(child);
	if (pci_bind_unsupported)
		return true;

	drv_idx = pci_bind_pick_driver();
	drv = pci_bind_safe_drivers[drv_idx];

	n_devs = pci_bind_collect_devs(drv, devs);
	if (n_devs == 0U) {
		__atomic_add_fetch(&shm->stats.pci_bind.no_devices, 1,
				   __ATOMIC_RELAXED);
		return true;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	pick = rnd_modulo_u32(n_devs);
	bdf = devs[pick];

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	ran_unbind = pci_bind_write_bdf(drv, "unbind", bdf, &err_unbind);
	ran_bind  = pci_bind_write_bdf(drv, "bind",   bdf, &err_bind);

	if (ran_unbind && err_unbind == 0)
		__atomic_add_fetch(&shm->stats.pci_bind.unbind_ok, 1,
				   __ATOMIC_RELAXED);
	else if (ran_unbind)
		__atomic_add_fetch(&shm->stats.pci_bind.unbind_enodev, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.pci_bind.unbind_failed, 1,
				   __ATOMIC_RELAXED);

	if (ran_bind && err_bind == 0)
		__atomic_add_fetch(&shm->stats.pci_bind.bind_ok, 1,
				   __ATOMIC_RELAXED);
	else if (ran_bind)
		__atomic_add_fetch(&shm->stats.pci_bind.bind_enodev, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.pci_bind.bind_failed, 1,
				   __ATOMIC_RELAXED);

	return true;
}
