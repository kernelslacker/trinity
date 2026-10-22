/*
 * Self-checks for the chain corpus (random_syscall/chain-corpus.c and
 * chain-persist.c).  Save and load zero the slots of a step whose saved
 * value is stale on replay, each step by its own ABI's table, and both
 * ends judge a chain by the same replay filter.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"		/* biarch, ARCH_IS_BIARCH */
#include "debug.h"		/* BUG */
#include "sequence.h"
#include "syscall.h"
#include "tables.h"		/* syscalls_{32,64}bit, max_nr_{32,64}bit_syscalls */
#include "utils.h"		/* ARRAY_SIZE */

/* One nr per case.  Each table's syscall there is named after its
 * argtypes. */
enum {
	NR_SHARED,	/* nothing stale in the 64-bit table, an fd in the 32-bit one */
	NR_MIX,		/* an fd, two pointers, then plain values, 64-bit table only */
	NR_NO_ARGS,	/* no arguments, 64-bit table only */
	NR_PID,		/* ARG_PID, 64-bit table only */
	NR_SANITISE,	/* has a sanitise callback, 64-bit table only */
	NR_HOLE,	/* no syscall in either table */
	NR_CHAIN_END,
};

static void fake_sanitise(struct syscallrecord *rec)
{
	(void) rec;
}

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

static struct syscallentry mix = {
	.name = "mix",
	.num_args = 6,
	.argtype = { [0] = ARG_FD, [1] = ARG_STRUCT_PTR_IN,
		     [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LEN,
		     [4] = ARG_RANGE, [5] = ARG_UNDEFINED },
};

static struct syscallentry no_args = {
	.name = "no_args",
	.num_args = 0,
};

static struct syscallentry pid_only = {
	.name = "pid_only",
	.num_args = 1,
	.argtype = { [0] = ARG_PID },
};

static struct syscallentry with_sanitise = {
	.name = "with_sanitise",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.sanitise = fake_sanitise,
};

/* [do32][nr]: the tables get_syscall_entry() reads while the test runs. */
static const struct syscalltable chain_table[2][NR_CHAIN_END] = {
	[0] = {
		[NR_SHARED] = { .entry = &range_range },
		[NR_MIX] = { .entry = &mix },
		[NR_NO_ARGS] = { .entry = &no_args },
		[NR_PID] = { .entry = &pid_only },
		[NR_SANITISE] = { .entry = &with_sanitise },
	},
	[1] = {
		[NR_SHARED] = { .entry = &fd_range },
	},
};

/* Slot j of step i holds SLOT_MARK(i, j) and its return value
 * RETVAL_MARK(i): distinct and nonzero, so a zeroed slot and a swapped
 * one both show. */
#define SLOT_MARK(i, j)	(0x7a00UL + (i) * 0x10UL + (j))
#define RETVAL_MARK(i)	(0x5e00UL + (i))

#define SCRUB_REASON	CHAIN_SAVE_TRANSITION

/* A step as the executor records it, and which of its declared slots
 * replay must find zeroed. */
static const struct {
	unsigned int nr;
	bool do32bit;
	unsigned int num_args;
	unsigned int stale;
} scrub_steps[] = {
	{ NR_MIX, false, 6, 0x07 },
	/* The same nr under both ABIs: a step judged by the wrong table
	 * shows. */
	{ NR_SHARED, false, 2, 0x00 },
	{ NR_SHARED, true, 2, 0x01 },
};

static void fresh_ring(void)
{
	memset(chain_corpus_shm, 0, sizeof(*chain_corpus_shm));
}

/* Put a chain in the ring as it stands, past save's filter and scrub. */
static void put_chain(const struct chain_entry *e)
{
	struct chain_corpus_ring *ring = chain_corpus_shm;

	ring->slots[ring->head % CHAIN_CORPUS_RING_SIZE] = *e;
	ring->head++;
	if (ring->count < CHAIN_CORPUS_RING_SIZE)
		ring->count++;
}

/* The scrub_steps chain with every slot raw. */
static void raw_scrub_chain(struct chain_entry *e)
{
	unsigned int i, j;

	memset(e, 0, sizeof(*e));
	e->len = ARRAY_SIZE(scrub_steps);
	e->save_reason = SCRUB_REASON;
	for (i = 0; i < e->len; i++) {
		e->steps[i].nr = scrub_steps[i].nr;
		e->steps[i].do32bit = scrub_steps[i].do32bit;
		for (j = 0; j < 6; j++)
			e->steps[i].args[j] = SLOT_MARK(i, j);
		e->steps[i].retval = RETVAL_MARK(i);
	}
}

/* Whether the ring holds the scrub_steps chain alone, its stale slots
 * zero and everything else as saved. */
static bool ring_holds_scrubbed_chain(void)
{
	const struct chain_entry *e = &chain_corpus_shm->slots[0];
	unsigned int i, j;

	if (chain_corpus_shm->count != 1 || e->len != ARRAY_SIZE(scrub_steps) ||
	    e->save_reason != SCRUB_REASON)
		return false;
	for (i = 0; i < e->len; i++) {
		const struct chain_step *s = &e->steps[i];

		if (s->nr != scrub_steps[i].nr ||
		    s->do32bit != scrub_steps[i].do32bit ||
		    s->retval != RETVAL_MARK(i))
			return false;
		for (j = 0; j < scrub_steps[i].num_args; j++) {
			if (s->args[j] != (((scrub_steps[i].stale >> j) & 1) ?
					   0 : SLOT_MARK(i, j)))
				return false;
		}
	}
	return true;
}

/* An fd or pointer saved from one run is closed, freed or overwritten
 * in the next. */
static void save_zeroes_stale_slots(void)
{
	struct chain_entry raw;

	fresh_ring();
	raw_scrub_chain(&raw);
	chain_corpus_save(raw.steps, raw.len, SCRUB_REASON, NR_MIX);
	if (!ring_holds_scrubbed_chain())
		BUG("chain scrub: save kept a stale slot or lost a plain one");
}

/* A corpus written before save zeroed these slots still holds raw
 * values: the loader must clear them as save does.  The chain goes into
 * the ring directly, as save would no longer write it. */
static void load_zeroes_stale_slots(const char *path)
{
	unsigned int loaded, discarded;
	struct chain_entry raw;

	fresh_ring();
	raw_scrub_chain(&raw);
	put_chain(&raw);
	if (!chain_corpus_save_file(path))
		BUG("chain scrub: saving the corpus failed");

	fresh_ring();
	if (!chain_corpus_load_file(path, &loaded, &discarded) ||
	    loaded != 1 || discarded != 0)
		BUG("chain scrub: the loader dropped the chain");
	if (!ring_holds_scrubbed_chain())
		BUG("chain scrub: the loader kept a stale slot or lost a plain one");
}

/* Two-step chains, and whether the replay filter admits them. */
static const struct {
	struct {
		unsigned int nr;
		bool do32bit;
	} step[2];
	bool admitted;
} admit_cases[] = {
	/* A call with no arguments still shapes its chain. */
	{ { { NR_NO_ARGS, false }, { NR_SHARED, false } }, true },
	/* A pid argument, a sanitise callback and a missing syscall each
	 * refuse the chain they sit in. */
	{ { { NR_SHARED, false }, { NR_PID, false } }, false },
	{ { { NR_SANITISE, false }, { NR_SHARED, false } }, false },
	{ { { NR_SHARED, false }, { NR_HOLE, false } }, false },
	{ { { NR_MIX, false }, { NR_SHARED, true } }, true },
};

static void admit_chain(unsigned int c, struct chain_entry *e)
{
	unsigned int i;

	memset(e, 0, sizeof(*e));
	e->len = ARRAY_SIZE(admit_cases[c].step);
	e->save_reason = CHAIN_SAVE_PC;
	for (i = 0; i < e->len; i++) {
		e->steps[i].nr = admit_cases[c].step[i].nr;
		e->steps[i].do32bit = admit_cases[c].step[i].do32bit;
	}
}

static void save_admits_by_the_replay_filter(void)
{
	unsigned int c, admitted = 0;

	fresh_ring();
	for (c = 0; c < ARRAY_SIZE(admit_cases); c++) {
		struct chain_entry e;

		admit_chain(c, &e);
		chain_corpus_save(e.steps, e.len, e.save_reason, e.steps[0].nr);
		if (admit_cases[c].admitted)
			admitted++;
		if (chain_corpus_shm->count != admitted)
			BUG("chain admit: save judged a chain wrongly");
	}
}

/* The loader asks the same filter of what is on disk, so a chain an
 * older binary saved and the table has since refused does not come
 * back.  All of them go into the ring directly, as save would no longer
 * write the refused ones. */
static void load_admits_by_the_replay_filter(const char *path)
{
	unsigned int c, loaded, discarded, slot = 0, nadmitted = 0;

	fresh_ring();
	for (c = 0; c < ARRAY_SIZE(admit_cases); c++) {
		struct chain_entry e;

		admit_chain(c, &e);
		put_chain(&e);
		if (admit_cases[c].admitted)
			nadmitted++;
	}
	if (!chain_corpus_save_file(path))
		BUG("chain admit: saving the corpus failed");

	fresh_ring();
	chain_corpus_load_file(path, &loaded, &discarded);
	if (loaded != nadmitted || discarded != ARRAY_SIZE(admit_cases) - nadmitted)
		BUG("chain admit: the loader judged chains wrongly");
	for (c = 0; c < ARRAY_SIZE(admit_cases); c++) {
		const struct chain_entry *e;

		if (!admit_cases[c].admitted)
			continue;
		e = &chain_corpus_shm->slots[slot++];
		if (e->steps[0].nr != admit_cases[c].step[0].nr ||
		    e->steps[1].nr != admit_cases[c].step[1].nr)
			BUG("chain admit: the loader admitted the wrong chains");
	}
}

void chain_corpus_self_check(void);
void chain_corpus_self_check(void)
{
	char dir[] = "/tmp/trinity-chain-corpus-test.XXXXXX";
	char path[sizeof(dir) + sizeof("/corpus")];

#ifndef ARCH_IS_BIARCH
	/* A uniarch get_syscall_entry() ignores do32: there is no ABI to
	 * judge a step by. */
	return;
#endif
	if (mkdtemp(dir) == NULL)
		BUG("chain corpus: mkdtemp failed");
	snprintf(path, sizeof(path), "%s/corpus", dir);

	chain_corpus_shm = calloc(1, sizeof(*chain_corpus_shm));
	if (chain_corpus_shm == NULL)
		BUG("chain corpus: calloc failed");
	biarch = true;
	syscalls_64bit = chain_table[0];
	syscalls_32bit = chain_table[1];
	max_nr_64bit_syscalls = NR_CHAIN_END;
	max_nr_32bit_syscalls = NR_CHAIN_END;

	save_zeroes_stale_slots();
	load_zeroes_stale_slots(path);
	save_admits_by_the_replay_filter();
	load_admits_by_the_replay_filter(path);

	/* Back to the empty uniarch tables fake_parent.c provides. */
	biarch = false;
	syscalls_64bit = NULL;
	syscalls_32bit = NULL;
	max_nr_64bit_syscalls = 0;
	max_nr_32bit_syscalls = 0;
	free(chain_corpus_shm);
	chain_corpus_shm = NULL;

	if (unlink(path) != 0 || rmdir(dir) != 0)
		BUG("chain corpus: cleanup failed");
}
