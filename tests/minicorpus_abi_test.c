/*
 * Self-check for the minicorpus ABI split (persist/minicorpus-*.c).  On
 * biarch the 32- and 64-bit syscalls at one nr share a ring, so replay
 * may only take entries saved under the record's ABI, and the warm-start
 * loader must judge each entry by the table it was saved from.
 */

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arch.h"		/* biarch, ARCH_IS_BIARCH */
#include "blob_corpus.h"
#include "debug.h"		/* BUG */
#include "minicorpus.h"
#include "persist-envelope.h"
#include "persist/minicorpus-internal.h"
#include "shm.h"
#include "strategy.h"		/* PLATEAU_HYPOTHESIS_* */
#include "syscall.h"
#include "tables.h"		/* syscalls_{32,64}bit, max_nr_{32,64}bit_syscalls */
#include "utils-proc.h"		/* crc32 */

/* Owned by persist/minicorpus-accounting.c in production. */
bool this_replay_source_tracked;
unsigned int this_replay_source_nr;
unsigned int this_replay_source_slot;
unsigned int this_replay_source_age;

/* One nr per case.  Each table's syscall there is named after its
 * argtypes. */
enum {
	NR_SHARED,	/* replay-safe in both tables */
	NR_PID64,	/* ARG_PID only in the 64-bit table */
	NR_PID32,	/* ARG_PID only in the 32-bit table */
	NR_HOLE32,	/* no 32-bit syscall */
	NR_ABI_END,
};

static struct syscallentry range_range = {
	.name = "range_range",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE },
};

static struct syscallentry fd_range = {
	.name = "fd_range",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_RANGE },
};

static struct syscallentry range_only = {
	.name = "range_only",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
};

static struct syscallentry pid_only = {
	.name = "pid_only",
	.num_args = 1,
	.argtype = { [0] = ARG_PID },
};

/* [do32][nr]: the tables get_syscall_entry() reads while the test runs. */
static const struct syscalltable abi_table[2][NR_ABI_END] = {
	[0] = {
		[NR_SHARED] = { .entry = &range_range },
		[NR_PID64] = { .entry = &pid_only },
		[NR_PID32] = { .entry = &range_only },
		[NR_HOLE32] = { .entry = &range_only },
	},
	[1] = {
		[NR_SHARED] = { .entry = &fd_range },
		[NR_PID64] = { .entry = &range_only },
		[NR_PID32] = { .entry = &pid_only },
	},
};

/* The mutator chain (persist/minicorpus-splice.c) is not linked: replay
 * hands back the picked entry's args unchanged, so they name it. */
void minicorpus_mutate_args(unsigned long args[6], struct syscallentry *entry)
{
	(void) args;
	(void) entry;
}

/* args/pools/blob_corpus.c is not linked; no blob stash is pending. */
void blob_corpus_promote_pending(void)
{
}

/* utils/persist-envelope.c is not linked: it would consult the
 * generation manifest under the user's cache directory. */
void persist_envelope_init(struct trinity_persist_envelope *env,
			   enum trinity_persist_component component,
			   uint32_t schema_version,
			   uint32_t payload_len,
			   uint32_t checksum)
{
	memset(env, 0, sizeof(*env));
	env->magic = TRINITY_PERSIST_MAGIC;
	env->component_id = component;
	env->schema_version = schema_version;
	env->payload_len = payload_len;
	env->checksum = checksum;
}

bool persist_envelope_validate(const struct trinity_persist_envelope *env,
			       enum trinity_persist_component expected,
			       const char *path)
{
	(void) path;
	return env->magic == TRINITY_PERSIST_MAGIC &&
	       env->component_id == (uint32_t) expected;
}

bool persist_envelope_check_generation(const struct trinity_persist_envelope *env,
				       enum trinity_persist_component expected,
				       const char *path)
{
	(void) env;
	(void) expected;
	(void) path;
	return true;
}

/* utils/utils.c is not linked (its kill_pid() would clash with
 * fake_parent.c's); the bitwise CRC-32 gives the same sums. */
uint32_t crc32(const void *buf, size_t len)
{
	const uint8_t *p = buf;
	uint32_t crc = 0xffffffffU;
	size_t i;
	unsigned int k;

	for (i = 0; i < len; i++) {
		crc ^= p[i];
		for (k = 0; k < 8; k++)
			crc = (crc & 1) ? (0xedb88320U ^ (crc >> 1)) : (crc >> 1);
	}
	return crc ^ 0xffffffffU;
}

static void put_entry(unsigned int nr, bool do32, unsigned long a1,
		      unsigned long a2)
{
	struct corpus_ring *ring = &minicorpus_shm->rings[nr];
	struct corpus_entry *e = &ring->entries[ring->head % CORPUS_RING_SIZE];

	memset(e, 0, sizeof(*e));
	e->args[0] = a1;
	e->args[1] = a2;
	e->num_args = 2;
	e->do32bit = do32;
	ring->head++;
	if (ring->count < CORPUS_RING_SIZE)
		ring->count++;
}

static void check_entry(unsigned int nr, unsigned int slot, bool do32,
			unsigned long a1, unsigned long a2)
{
	const struct corpus_entry *e = &minicorpus_shm->rings[nr].entries[slot];

	if (e->do32bit != do32 || e->num_args != 2 ||
	    e->args[0] != a1 || e->args[1] != a2)
		BUG("minicorpus abi: a loaded entry has the wrong ABI or args");
}

static unsigned int load(const char *path, unsigned int *discarded)
{
	unsigned int loaded;

	memset(minicorpus_shm, 0, sizeof(*minicorpus_shm));
	minicorpus_load_file(path, &loaded, discarded);
	return loaded;
}

#define TAG64		0x6400UL
#define TAG32		0x3200UL
#define REPLAY_TRIES	1000U

/* Every replay that runs must hand back an entry of the record's ABI,
 * and a skipped pick must not leave a source tracked for the commit. */
static void replay_takes_own_abi(bool do32, bool burst)
{
	struct syscallrecord rec;
	unsigned int i, hits = 0;

	memset(&rec, 0, sizeof(rec));
	rec.nr = NR_SHARED;
	rec.do32bit = do32;
	__atomic_store_n(&shm->plateau_current_hypothesis,
			 burst ? (int) PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT :
				 (int) PLATEAU_HYPOTHESIS_NONE,
			 __ATOMIC_RELAXED);

	for (i = 0; i < REPLAY_TRIES; i++) {
		this_replay_source_tracked = false;
		if (!minicorpus_replay(&rec)) {
			if (this_replay_source_tracked)
				BUG("minicorpus abi: a skipped replay tracked a source");
			continue;
		}
		if ((rec.a2 & ~0xffUL) != (do32 ? TAG32 : TAG64))
			BUG("minicorpus abi: replay took the other ABI's entry");
		hits++;
	}
	if (hits == 0)
		BUG("minicorpus abi: replay never took its own ABI's entry");

	__atomic_store_n(&shm->plateau_current_hypothesis,
			 (int) PLATEAU_HYPOTHESIS_NONE, __ATOMIC_RELAXED);
}

/* Save both ABIs' calls at one nr, alternating, deeper than the
 * K-newest window the burst path picks from.  The tag rides in a2, the
 * RANGE slot in both tables (the 32-bit a1 is an fd, zeroed on save). */
static void replay_filters_by_abi(void)
{
	struct syscallrecord rec;
	unsigned int i;

	memset(minicorpus_shm, 0, sizeof(*minicorpus_shm));
	memset(&rec, 0, sizeof(rec));
	rec.nr = NR_SHARED;
	for (i = 0; i < 16; i++) {
		rec.do32bit = (i & 1) != 0;
		rec.a1 = i;
		rec.a2 = (rec.do32bit ? TAG32 : TAG64) | i;
		minicorpus_save_with_reason(&rec, CORPUS_SAVE_REASON_PC);
	}
	if (minicorpus_shm->rings[NR_SHARED].count != 16)
		BUG("minicorpus abi: the ring did not take every save");

	replay_takes_own_abi(false, false);
	replay_takes_own_abi(true, false);
	replay_takes_own_abi(false, true);
	replay_takes_own_abi(true, true);
}

/* Save a ring set, reload it and check that each entry was judged (and
 * scrubbed) by its own ABI's table and kept its do32bit. */
static void load_judges_by_own_table(const char *path)
{
	unsigned int loaded, discarded;

	memset(minicorpus_shm, 0, sizeof(*minicorpus_shm));
	put_entry(NR_SHARED, true, 7, 0x11);
	put_entry(NR_SHARED, false, 0x22, 0x33);
	put_entry(NR_PID64, true, 0x44, 0x55);
	put_entry(NR_PID32, true, 0x66, 0x77);
	put_entry(NR_HOLE32, true, 0x88, 0x99);
	if (!minicorpus_save_file(path))
		BUG("minicorpus abi: saving the corpus failed");

	loaded = load(path, &discarded);
	if (loaded != 3 || discarded != 2)
		BUG("minicorpus abi: the loader judged entries by the wrong table");
	/* The 32-bit fd slot is scrubbed; the 64-bit RANGE slot is not. */
	check_entry(NR_SHARED, 0, true, 0, 0x11);
	check_entry(NR_SHARED, 1, false, 0x22, 0x33);
	check_entry(NR_PID64, 0, true, 0x44, 0x55);
	if (minicorpus_shm->rings[NR_SHARED].count != 2 ||
	    minicorpus_shm->rings[NR_PID64].count != 1 ||
	    minicorpus_shm->rings[NR_PID32].count != 0 ||
	    minicorpus_shm->rings[NR_HOLE32].count != 0)
		BUG("minicorpus abi: the loader admitted the wrong entries");

	/* No 32-bit table to judge a do32bit entry by. */
	biarch = false;
	loaded = load(path, &discarded);
	biarch = true;
	if (loaded != 1 || discarded != 4)
		BUG("minicorpus abi: a uniarch load admitted a 32-bit entry");
	check_entry(NR_SHARED, 0, false, 0x22, 0x33);
}

/* The on-disk entry, as persist/minicorpus-file.c writes it. */
struct file_entry {
	uint32_t nr;
	uint32_t num_args;
	uint64_t args[6];
	uint32_t do32bit;
	uint32_t crc;
};

/* Entries load_judges_by_own_table() saved; they close the file. */
#define SAVED_ENTRIES	5

/* Rewrite the do32bit of NR_SHARED's 64-bit entry, the second saved,
 * refreshing its CRC or not, load the file, then put the entry back. */
static unsigned int load_patched_do32bit(const char *path, uint32_t do32bit,
					 bool refresh_crc,
					 unsigned int *discarded)
{
	struct file_entry orig, ent;
	unsigned int loaded;
	struct stat st;
	off_t off;
	int fd;

	fd = open(path, O_RDWR);
	if (fd < 0 || fstat(fd, &st) != 0)
		BUG("minicorpus abi: cannot open the saved corpus");
	off = st.st_size - (off_t) ((SAVED_ENTRIES - 1) * sizeof(ent));
	if (pread(fd, &orig, sizeof(orig), off) != (ssize_t) sizeof(orig) ||
	    orig.nr != NR_SHARED || orig.do32bit != 0)
		BUG("minicorpus abi: the saved corpus is not laid out as expected");

	ent = orig;
	ent.do32bit = do32bit;
	if (refresh_crc)
		ent.crc = crc32(&ent, offsetof(struct file_entry, crc));
	if (pwrite(fd, &ent, sizeof(ent), off) != (ssize_t) sizeof(ent))
		BUG("minicorpus abi: cannot patch the saved corpus");

	loaded = load(path, discarded);

	if (pwrite(fd, &orig, sizeof(orig), off) != (ssize_t) sizeof(orig))
		BUG("minicorpus abi: cannot restore the saved corpus");
	close(fd);
	return loaded;
}

/* do32bit must be 0 or 1, and the entry CRC must cover it.  Either way
 * the patched entry drops out of the five, leaving two loaded. */
static void load_checks_do32bit(const char *path)
{
	unsigned int discarded;

	if (load_patched_do32bit(path, 2, true, &discarded) != 2 ||
	    discarded != 3)
		BUG("minicorpus abi: an entry with do32bit 2 was loaded");
	if (load_patched_do32bit(path, 1, false, &discarded) != 2 ||
	    discarded != 3)
		BUG("minicorpus abi: a flipped do32bit passed the CRC");
}

/* A version 3 file has no ABI per entry: it is refused whole, so the
 * run starts cold and the next save rewrites it. */
static void load_refuses_version_3(const char *path)
{
	const uint32_t v3 = 3;
	unsigned int discarded;
	int fd;

	/* The corpus header opens with its magic, then the version. */
	fd = open(path, O_WRONLY);
	if (fd < 0 ||
	    pwrite(fd, &v3, sizeof(v3),
		   sizeof(struct trinity_persist_envelope) + sizeof(uint32_t)) !=
	    (ssize_t) sizeof(v3))
		BUG("minicorpus abi: cannot rewrite the header version");
	close(fd);

	if (load(path, &discarded) != 0 || discarded != 0 ||
	    minicorpus_shm->rings[NR_SHARED].count != 0)
		BUG("minicorpus abi: a version 3 file was not refused");
}

void minicorpus_abi_self_check(void);
void minicorpus_abi_self_check(void)
{
	char dir[] = "/tmp/trinity-minicorpus-test.XXXXXX";
	char path[sizeof(dir) + sizeof("/corpus")];

#ifndef ARCH_IS_BIARCH
	/* A uniarch get_syscall_entry() ignores do32: there is no split. */
	return;
#endif
	if (mkdtemp(dir) == NULL)
		BUG("minicorpus abi: mkdtemp failed");
	snprintf(path, sizeof(path), "%s/corpus", dir);

	minicorpus_shm = calloc(1, sizeof(*minicorpus_shm));
	if (minicorpus_shm == NULL)
		BUG("minicorpus abi: calloc failed");
	biarch = true;
	syscalls_64bit = abi_table[0];
	syscalls_32bit = abi_table[1];
	max_nr_64bit_syscalls = NR_ABI_END;
	max_nr_32bit_syscalls = NR_ABI_END;

	replay_filters_by_abi();
	load_judges_by_own_table(path);
	load_checks_do32bit(path);
	load_refuses_version_3(path);

	/* Back to the empty uniarch tables fake_parent.c provides. */
	biarch = false;
	syscalls_64bit = NULL;
	syscalls_32bit = NULL;
	max_nr_64bit_syscalls = 0;
	max_nr_32bit_syscalls = 0;
	free(minicorpus_shm);
	minicorpus_shm = NULL;

	if (unlink(path) != 0 || rmdir(dir) != 0)
		BUG("minicorpus abi: cleanup failed");
}
