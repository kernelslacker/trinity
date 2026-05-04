/*
 * SYSCALL_DEFINE1(adjtimex, struct timex __user *, txc_p
 *
 * On success, adjtimex() returns the clock state: */

#include <sys/timex.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static unsigned long adj_modes[] = {
	ADJ_OFFSET, ADJ_FREQUENCY, ADJ_MAXERROR, ADJ_ESTERROR,
	ADJ_STATUS, ADJ_TIMECONST, ADJ_SETOFFSET, ADJ_MICRO,
	ADJ_NANO, ADJ_TICK,
	ADJ_OFFSET_SINGLESHOT, ADJ_OFFSET_SS_READ,
};

static void sanitise_adjtimex(struct syscallrecord *rec)
{
	struct timex *tx;

	tx = (struct timex *) get_writable_struct(sizeof(*tx));
	if (!tx)
		return;
	memset(tx, 0, sizeof(*tx));

	tx->modes = RAND_ARRAY(adj_modes);

	switch (tx->modes) {
	case ADJ_OFFSET:
		/* NTP offset: +-512000 usec (or nsec with ADJ_NANO) */
		tx->offset = (rand() % 1024001) - 512000;
		break;
	case ADJ_FREQUENCY:
		/* Frequency: scaled ppm, +-512000 << 16 */
		tx->freq = (rand32() % 67108865) - 33554432;
		break;
	case ADJ_MAXERROR:
		tx->maxerror = rand() % 1000000;
		break;
	case ADJ_ESTERROR:
		tx->esterror = rand() % 1000000;
		break;
	case ADJ_STATUS:
		/* Only writable STA_* bits */
		tx->status = rand() & 0xff;
		break;
	case ADJ_TIMECONST:
		tx->constant = rand() % 11;	/* 0-10 */
		break;
	case ADJ_TICK:
		/* Tick: 900000/HZ to 1100000/HZ usec, ~9000-11000 for HZ=100 */
		tx->tick = 9000 + (rand() % 2001);
		break;
	case ADJ_SETOFFSET:
		tx->time.tv_sec = (rand() % 3) - 1;
		tx->time.tv_usec = rand() % 1000000;
		break;
	}

	rec->a1 = (unsigned long) tx;
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
};
