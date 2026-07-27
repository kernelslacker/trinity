/*
 * Shared persistence envelope + generation manifest.  See
 * include/persist-envelope.h for the motivation and format.
 */

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "fd.h"
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

uint64_t persist_envelope_current_generation(void)
{
	struct timespec ts;

	if (cached_generation_valid)
		return cached_generation;

	if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
		cached_generation = (uint64_t)ts.tv_sec * 1000000000ULL +
				    (uint64_t)ts.tv_nsec;
	} else {
		/* Best-effort fallback: pid + a coarse time.  Collisions
		 * across runs are possible but the load-side manifest
		 * check still catches inter-component mismatches. */
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

const char *persist_manifest_default_path(void)
{
	static char pathbuf[PATH_MAX];
	const char *xdg = getenv("XDG_CACHE_HOME");
	const char *home = getenv("HOME");
	char dir[PATH_MAX];
	int ret;

	if (xdg && xdg[0] == '/')
		ret = snprintf(dir, sizeof(dir), "%s/trinity", xdg);
	else if (home && home[0] == '/')
		ret = snprintf(dir, sizeof(dir), "%s/.cache/trinity", home);
	else
		return NULL;
	if (ret < 0 || (size_t)ret >= sizeof(dir))
		return NULL;

	/* mkdir -p the trinity cache dir on demand.  EEXIST is fine. */
	if (mkdir(dir, 0755) != 0 && errno != EEXIST)
		return NULL;

	ret = snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir,
		       TRINITY_PERSIST_MANIFEST_NAME);
	if (ret < 0 || (size_t)ret >= sizeof(pathbuf))
		return NULL;
	return pathbuf;
}

/*
 * Read and validate the shared manifest.  On success fills *gen_out
 * with the manifest generation and *components_out with the flat
 * component list (caller-owned, freed by the caller); returns true.
 * On any failure returns false and leaves outputs untouched.
 */
static bool read_manifest(uint64_t *gen_out,
			  uint32_t **components_out,
			  uint32_t *nr_components_out)
{
	const char *path = persist_manifest_default_path();
	struct trinity_persist_manifest_header hdr;
	uint32_t *comps;
	size_t comps_bytes;
	ssize_t n;
	int fd;

	if (path == NULL)
		return false;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	n = read_all(fd, &hdr, sizeof(hdr));
	if (n != (ssize_t)sizeof(hdr)) {
		(void)close(fd);
		return false;
	}
	if (hdr.magic != TRINITY_PERSIST_MANIFEST_MAGIC) {
		(void)close(fd);
		return false;
	}
	/* Sanity clamp -- a corrupt nr_components could ask for a huge
	 * allocation.  Four real components today, cap at 64 for
	 * headroom. */
	if (hdr.nr_components == 0 || hdr.nr_components > 64) {
		(void)close(fd);
		return false;
	}

	comps_bytes = (size_t)hdr.nr_components * sizeof(uint32_t);
	comps = malloc(comps_bytes);
	if (comps == NULL) {
		(void)close(fd);
		return false;
	}
	n = read_all(fd, comps, comps_bytes);
	(void)close(fd);
	if (n != (ssize_t)comps_bytes) {
		free(comps);
		return false;
	}

	*gen_out = hdr.generation;
	*components_out = comps;
	*nr_components_out = hdr.nr_components;
	return true;
}

bool persist_envelope_check_generation(const struct trinity_persist_envelope *env,
				       enum trinity_persist_component expected,
				       const char *path)
{
	uint64_t manifest_gen;
	uint32_t *comps = NULL;
	uint32_t nr_comps = 0;
	uint32_t i;
	bool component_listed = false;

	if (!read_manifest(&manifest_gen, &comps, &nr_comps)) {
		/* No manifest (or unreadable): fall back to per-file
		 * validation.  Pre-manifest saves still load. */
		return true;
	}

	if (env->generation != manifest_gen) {
		output(0, "persist-envelope: generation %llu != manifest generation %llu at %s (torn warm-start) -- cold start\n",
		       (unsigned long long)env->generation,
		       (unsigned long long)manifest_gen, path);
		free(comps);
		return false;
	}

	for (i = 0; i < nr_comps; i++) {
		if (comps[i] == (uint32_t)expected) {
			component_listed = true;
			break;
		}
	}
	free(comps);

	if (!component_listed) {
		output(0, "persist-envelope: component %u absent from manifest at %s (torn warm-start) -- cold start\n",
		       (unsigned int)expected, path);
		return false;
	}

	return true;
}

bool persist_write_generation_manifest(uint64_t generation,
				       const enum trinity_persist_component *components,
				       uint32_t nr_components)
{
	const char *path = persist_manifest_default_path();
	struct trinity_persist_manifest_header hdr;
	uint32_t comp_ids[64];
	char tmppath[PATH_MAX];
	uint32_t i;
	int fd;
	int ret;

	if (path == NULL)
		return false;
	if (nr_components == 0 || nr_components > (uint32_t)(sizeof(comp_ids) /
							     sizeof(comp_ids[0])))
		return false;

	for (i = 0; i < nr_components; i++)
		comp_ids[i] = (uint32_t)components[i];

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = TRINITY_PERSIST_MANIFEST_MAGIC;
	hdr.generation = generation;
	hdr.nr_components = nr_components;

	/* Per-pid tmp so a shutdown save from two operators cannot
	 * O_TRUNC the same tmp file and interleave writes. */
	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		       path, (int)getpid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath))
		return false;

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return false;
	if (fchmod(fd, 0644) != 0) {
		(void)close(fd);
		(void)unlink(tmppath);
		return false;
	}

	if (write_all(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
		goto fail;
	if (write_all(fd, comp_ids, nr_components * sizeof(uint32_t)) !=
	    (ssize_t)(nr_components * sizeof(uint32_t)))
		goto fail;
	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		(void)unlink(tmppath);
		return false;
	}
	if (rename(tmppath, path) != 0) {
		(void)unlink(tmppath);
		return false;
	}
	return true;

fail:
	(void)close(fd);
	(void)unlink(tmppath);
	return false;
}
