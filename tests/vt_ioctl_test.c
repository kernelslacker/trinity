/*
 * Self-check for the vt group's termio and TIOCSIG args (ioctls/vt-tioc.c),
 * held to what the tty layer reads: TCGETA and the TCSETA family copy a
 * struct termio (user_termio_to_kernel_termios(), drivers/tty/tty_ioctl.c),
 * and TIOCSIG takes its signal as the arg value, which pty_signal()
 * (drivers/tty/pty.c) sends to the other side's foreground process group.
 */

#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>		/* struct termio, TC* and TIOC* */
#include <termios.h>		/* CREAD */

#include "debug.h"		/* BUG */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "sanitise.h"		/* get_writable_address, writable_pool_init */
#include "syscall.h"		/* struct syscallrecord */
#include "utils.h"		/* ARRAY_SIZE */

#define ROUNDS		2000

static const struct ioctl_group *vt_grp;

/* The arg the sanitiser leaves for @request. */
static unsigned long vt_arg(unsigned long request)
{
	static struct syscallrecord rec;

	memset(&rec, 0, sizeof(rec));
	fake_ioctl_request = request;
	vt_grp->sanitise(vt_grp, &rec);
	return rec.a3;
}

/* A set reads the flags as a termio's four unsigned shorts, so CREAD,
 * which every set the group builds asks for, is in c_cflag, and the
 * output and local flags are not always empty. */
static void termio_sets_read_a_termio(void)
{
	static const unsigned long sets[] = { TCSETA, TCSETAW, TCSETAF };
	unsigned int s, i;

	for (s = 0; s < ARRAY_SIZE(sets); s++) {
		unsigned int built = 0, oflag = 0, lflag = 0;

		for (i = 0; i < ROUNDS; i++) {
			unsigned long arg = vt_arg(sets[s]);
			const struct termio *t = (const struct termio *) arg;

			if (arg == FAKE_IOCTL_JUNK_ARG)
				continue;
			built++;
			if (!(t->c_cflag & CREAD))
				BUG("vt: a TCSETA-family termio's c_cflag lacks CREAD");
			oflag += t->c_oflag != 0;
			lflag += t->c_lflag != 0;
		}
		if (built == 0)
			BUG("vt: the TCSETA family built no termio");
		if (oflag == 0 || lflag == 0)
			BUG("vt: a TCSETA-family termio's output or local flags are always empty");
	}
}

/* pty_signal() sends SIGINT, SIGQUIT or SIGTSTP and refuses anything
 * else; children ignore SIGINT and SIGTSTP, while SIGQUIT ends one. */
static void tiocsig_sends_a_signal_children_ignore(void)
{
	unsigned int i, intr = 0, tstp = 0;

	for (i = 0; i < ROUNDS; i++) {
		unsigned long arg = vt_arg(TIOCSIG);

		if (arg == SIGINT)
			intr++;
		else if (arg == SIGTSTP)
			tstp++;
		else
			BUG("vt: TIOCSIG's arg is not SIGINT or SIGTSTP");
	}
	if (intr == 0 || tstp == 0)
		BUG("vt: TIOCSIG does not send both SIGINT and SIGTSTP");
}

void vt_ioctl_self_check(void);
void vt_ioctl_self_check(void)
{
	vt_grp = fake_ioctl_group("vt");
	if (vt_grp == NULL)
		BUG("vt: the group did not register");
	if (get_writable_address(sizeof(unsigned long)) == NULL)
		writable_pool_init();
	termio_sets_read_a_termio();
	tiocsig_sends_a_signal_children_ignore();
}
