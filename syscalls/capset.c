/*
 * SYSCALL_DEFINE2(capset, cap_user_header_t, header, const cap_user_data_t, data)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <linux/capability.h>
#include <sys/time.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static const unsigned int cap_versions[] = {
	_LINUX_CAPABILITY_VERSION_1,
	_LINUX_CAPABILITY_VERSION_2,
	_LINUX_CAPABILITY_VERSION_3,
};

/*
 * Fill header with valid version and pid.
 * Fill data with random capability bitmasks.
 * v3 uses two __user_cap_data_struct entries (64-bit capability sets).
 */
static void sanitise_capset(struct syscallrecord *rec)
{
	struct __user_cap_header_struct *hdr;
	struct __user_cap_data_struct *data;
	unsigned int version;

	hdr = (struct __user_cap_header_struct *) get_writable_struct(sizeof(*hdr));
	if (!hdr)
		return;
	version = RAND_ARRAY(cap_versions);
	hdr->version = version;
	hdr->pid = get_pid();
	rec->a1 = (unsigned long) hdr;

	/* v1 uses 1 data struct, v2/v3 use 2. */
	if (version == _LINUX_CAPABILITY_VERSION_1) {
		data = (struct __user_cap_data_struct *) get_writable_struct(sizeof(*data));
		if (!data)
			return;
		data->effective = rand32();
		data->permitted = rand32();
		data->inheritable = rand32();
	} else {
		data = (struct __user_cap_data_struct *) get_writable_struct(2 * sizeof(*data));
		if (!data)
			return;
		data[0].effective = rand32();
		data[0].permitted = rand32();
		data[0].inheritable = rand32();
		data[1].effective = rand32();
		data[1].permitted = rand32();
		data[1].inheritable = rand32();
	}
	rec->a2 = (unsigned long) data;
}

/*
 * Oracle (drop-only): after capset() succeeds, inspect the new effective
 * cap set the syscall just installed.  If a chosen cap is NOT in the new
 * effective set, then a syscall gated on that cap MUST fail with EPERM.
 * If it succeeds anyway, the kernel's permission check disagrees with
 * its own stored cap state — exactly the silent-priv-escalation shape
 * that crash sanitisers miss.
 *
 * settimeofday(NULL, NULL) is the chosen probe: the kernel runs the
 * CAP_SYS_TIME LSM hook unconditionally before doing anything, so with
 * the cap it returns 0 and without it returns -EPERM.  No side effects
 * either way.
 *
 * We can only check the drop direction because Trinity isn't root and
 * never had the cap to begin with — gain checks would always show
 * "still EPERM" and tell us nothing.  A future enhancement is the full
 * cap-matrix oracle that walks every CAP_* after every cap-related
 * syscall and verifies its effective state matches our model.
 */
static void post_capset(struct syscallrecord *rec)
{
	struct __user_cap_header_struct *hdr;
	struct __user_cap_data_struct *data;

	if ((long) rec->retval != 0)
		return;
	if (!ONE_IN(20))
		return;

	hdr = (struct __user_cap_header_struct *) rec->a1;
	data = (struct __user_cap_data_struct *) rec->a2;
	if (!hdr || !data)
		return;

	/* Cluster-1/2/3 guard: reject pid-scribbled rec->a1/a2. */
	if (looks_like_corrupted_ptr(hdr) || looks_like_corrupted_ptr(data)) {
		outputerr("post_capset: rejected suspicious header=%p data=%p (pid-scribbled?)\n",
			  hdr, data);
		shm->stats.post_handler_corrupt_ptr++;
		return;
	}

	/* CAP_SYS_TIME == 25 lives in data[0] for v1/v2/v3. */
	if ((data[0].effective & (1u << CAP_SYS_TIME)) != 0)
		return;

	if (settimeofday(NULL, NULL) == 0) {
		output(0, "cred oracle: capset cleared CAP_SYS_TIME from effective "
		       "set but settimeofday(NULL, NULL) succeeded\n");
		__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
	/* EPERM (or any other failure) means the kernel agrees with itself. */
}

struct syscallentry syscall_capset = {
	.name = "capset",
	.num_args = 2,
	.argname = { [0] = "header", [1] = "data" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.sanitise = sanitise_capset,
	.post = post_capset,
};
