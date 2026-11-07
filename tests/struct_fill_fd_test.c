/*
 * Self-check for struct_fill's FT_FD arm: a cataloged struct's fd field
 * never names a protected fd, as no scalar fd slot does: a protected draw
 * is drawn again, and -1 stands in once the budget is spent on them.
 */

#include <unistd.h>

#include "args-internal.h"	/* struct_fill_passes */
#include "debug.h"		/* BUG */
#include "fd.h"			/* fd_is_protected */
#include "struct_catalog.h"

extern int fake_random_fd;	/* fake_stubs.c */

/* An FT_FD field, filled while the fd pool hands out only @drawn. */
static int fill_fd_field(int drawn)
{
	const struct struct_field fields[1] = {{
		.name   = "fd_probe",
		.offset = 0,
		.size   = sizeof(int),
		.tag    = FT_FD,
	}};
	int fd;

	fake_random_fd = drawn;
	struct_fill_passes((unsigned char *) &fd, sizeof(fd), fields, 1, NULL);
	fake_random_fd = -1;
	return fd;
}

void struct_fill_fd_self_check(void);
void struct_fill_fd_self_check(void)
{
	if (fill_fd_field(STDERR_FILENO) != -1)
		BUG("struct_fill: an FT_FD field names a protected fd");

	if (fd_is_protected(STDIN_FILENO))
		BUG("struct_fill: stdin is protected");
	if (fill_fd_field(STDIN_FILENO) != STDIN_FILENO)
		BUG("struct_fill: an FT_FD field turns away an fd no one protects");
}
