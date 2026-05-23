/*
 * SYSCALL_DEFINE1(adjtimex, struct timex __user *, txc_p
 *
 * On success, adjtimex() returns the clock state: */

#include <sys/timex.h>
#include <string.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Writable STA_* bits suitable for ADJ_STATUS.  Kept narrow so we land
 * on real PLL/FLL/PPS configurations the kernel parses, not on the
 * read-only or reserved bits.
 */
static const long adj_status_bits[] = {
	STA_PLL, STA_PPSFREQ, STA_FLL, STA_FREQHOLD,
};

static void fill_adj_offset(struct timex *tx)
{
	/* NTP offset: +-512000 usec (or nsec with ADJ_NANO) */
	tx->offset = (long) (rnd_modulo_u32(1024001)) - 512000;
}

static void fill_adj_frequency(struct timex *tx)
{
	/* Frequency: scaled ppm, +-512000 << 16 */
	tx->freq = (long) (rand32() % 67108865) - 33554432;
}

static void fill_adj_status(struct timex *tx)
{
	unsigned int i, bits;

	bits = 1 + rnd_modulo_u32(ARRAY_SIZE(adj_status_bits));
	tx->status = 0;
	for (i = 0; i < bits; i++)
		tx->status |= adj_status_bits[rnd_modulo_u32(
			ARRAY_SIZE(adj_status_bits))];
}

static void fill_adj_tick(struct timex *tx)
{
	/* Tick: 900000/HZ to 1100000/HZ usec, ~9000-11000 for HZ=100 */
	tx->tick = 9000 + (long) (rnd_modulo_u32(2001));
}

static void sanitise_adjtimex(struct syscallrecord *rec)
{
	struct timex *tx;
	unsigned int roll;

	tx = (struct timex *) get_writable_struct(sizeof(*tx));
	if (!tx)
		return;
	memset(tx, 0, sizeof(*tx));

	/*
	 * Mode bucket: 60% read-only (modes == 0), 40% spread across the
	 * write modes the kernel actually parses.  Random arg fill almost
	 * never lands cleanly on the write-mode bits, so the per-mode
	 * field validators stay cold without an explicit table.
	 */
	roll = rnd_modulo_u32(100);

	if (roll < 60) {
		tx->modes = 0;
	} else if (roll < 68) {
		tx->modes = ADJ_OFFSET;
		fill_adj_offset(tx);
	} else if (roll < 76) {
		tx->modes = ADJ_FREQUENCY;
		fill_adj_frequency(tx);
	} else if (roll < 84) {
		tx->modes = ADJ_STATUS;
		fill_adj_status(tx);
	} else if (roll < 92) {
		tx->modes = ADJ_TICK;
		fill_adj_tick(tx);
	} else if (roll < 96) {
		/* Combined offset + frequency: parsed by the same path that
		 * services real ntpd updates. */
		tx->modes = ADJ_OFFSET | ADJ_FREQUENCY;
		fill_adj_offset(tx);
		fill_adj_frequency(tx);
	} else if (roll < 98) {
		tx->modes = ADJ_MAXERROR;
		tx->maxerror = rnd_modulo_u32(1000000);
	} else {
		tx->modes = ADJ_TIMECONST;
		tx->constant = rnd_modulo_u32(11);	/* 0-10 */
	}

	rec->a1 = (unsigned long) tx;
	avoid_shared_buffer_inout(&rec->a1, sizeof(struct timex));
}

static void post_adjtimex(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < TIME_OK || ret > TIME_ERROR)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_adjtimex = {
	.name = "adjtimex",
	.group = GROUP_TIME,
	.num_args = 1,
	.argname = { [0] = "txc_p" },
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_adjtimex,
	.post = post_adjtimex,
	.rettype = RET_BORING,
};
