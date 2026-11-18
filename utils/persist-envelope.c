/*
 * Shared persistence envelope.  See include/persist-envelope.h for the
 * motivation and format.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "persist-envelope.h"
#include "trinity.h"

/*
 * Cached generation for this process.  Seeded on the first call from
 * CLOCK_REALTIME so wall-clock monotonicity across runs comes for
 * free.  Children inherit the seeded value via COW after fork, so
 * mid-run children saving via the snapshot path stamp the same
 * generation as the parent.
 */
static uint64_t cached_generation;
static bool cached_generation_valid;

static uint64_t persist_envelope_current_generation(void)
{
	struct timespec ts;

	if (cached_generation_valid)
		return cached_generation;

	if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
		cached_generation = (uint64_t)ts.tv_sec * 1000000000ULL +
				    (uint64_t)ts.tv_nsec;
	} else {
		/* Best-effort fallback: the pid.  Nothing reads the
		 * generation back; it only records which run wrote a
		 * file, so a pid repeated across runs costs nothing. */
		cached_generation = (uint64_t)getpid();
	}
	cached_generation_valid = true;
	return cached_generation;
}

static void fill_kernel_identity(uint8_t *out, size_t len)
{
	struct utsname u;
	int n;

	memset(out, 0, len);
	if (uname(&u) != 0)
		return;
	/* release + " " + version, truncated to fit -- matches the
	 * granularity of the per-component kernel_release + kernel_version
	 * check the file parsers already do. */
	n = snprintf((char *)out, len, "%s %s", u.release, u.version);
	if (n < 0) {
		memset(out, 0, len);
		return;
	}
	/* snprintf NUL-terminates within len; nothing more to do. */
}

void persist_envelope_init(struct trinity_persist_envelope *env,
			   enum trinity_persist_component component,
			   uint32_t schema_version,
			   uint32_t payload_len,
			   uint32_t checksum)
{
	memset(env, 0, sizeof(*env));
	env->magic = TRINITY_PERSIST_MAGIC;
	env->component_id = (uint32_t)component;
	env->schema_version = schema_version;
	env->generation = persist_envelope_current_generation();
	fill_kernel_identity(env->kernel_identity,
			     TRINITY_PERSIST_KERNEL_IDENTITY_LEN);
	env->checksum = checksum;
	env->payload_len = payload_len;
}

bool persist_envelope_validate(const struct trinity_persist_envelope *env,
			       enum trinity_persist_component expected,
			       const char *path)
{
	uint8_t cur_identity[TRINITY_PERSIST_KERNEL_IDENTITY_LEN];

	if (env->magic != TRINITY_PERSIST_MAGIC) {
		output(0, "persist-envelope: magic 0x%016llx != expected 0x%016llx at %s -- cold start\n",
		       (unsigned long long)env->magic,
		       (unsigned long long)TRINITY_PERSIST_MAGIC, path);
		return false;
	}
	if (env->component_id != (uint32_t)expected) {
		output(0, "persist-envelope: component_id %u != expected %u at %s (mis-pointed path?) -- cold start\n",
		       env->component_id, (unsigned int)expected, path);
		return false;
	}

	fill_kernel_identity(cur_identity, TRINITY_PERSIST_KERNEL_IDENTITY_LEN);
	if (memcmp(env->kernel_identity, cur_identity,
		   TRINITY_PERSIST_KERNEL_IDENTITY_LEN) != 0) {
		output(0, "persist-envelope: kernel identity mismatch at %s -- cold start\n",
		       path);
		return false;
	}

	return true;
}
