#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "params.h"
#include "types.h"
#include "taint.h"
#include "trinity.h"

int kernel_taint_initial = 0;

static bool taint_available = false;

int get_taint(void)
{
	int fd, ret = 0;
	char buffer[11];

	if (!taint_available)
		return 0;

	fd = open("/proc/sys/kernel/tainted", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;

	buffer[10] = 0;

	ret = read(fd, buffer, 10);

	if (ret > 0) {
		char *endptr;
		long val;

		errno = 0;
		val = strtol(buffer, &endptr, 10);
		if (errno != 0 || endptr == buffer)
			ret = 0;
		else
			ret = (int)val;
	} else {
		ret = 0;
	}

	close(fd);
	return ret;
}

static bool became_tainted = false;

bool is_tainted(void)
{
	/*
	 * Microoptimise the case where we became tainted. We don't need
	 * multiple reads of /proc.
	 */
	if (became_tainted == true)
		return true;

	/* Only check taint if the mask allows it */
	if (kernel_taint_mask != 0) {
		int ret = 0;

		ret = get_taint();
		if (((ret & kernel_taint_mask) & (~kernel_taint_initial)) != 0) {
			became_tainted = true;
			return true;
		}
	}
	return false;
}
static void toggle_taint_flag(int bit)
{
	kernel_taint_mask |= (1U << bit);
}

static void toggle_taint_flag_by_name(char *beg, char *end)
{
	char flagname[TAINT_NAME_LEN];
	char *name;

	if (end == NULL) {
		name = beg;
	} else {
		int maxlen;

		name = flagname;
		maxlen = end - beg;
		if (maxlen > (TAINT_NAME_LEN - 1))
			maxlen = TAINT_NAME_LEN - 1;
		strncpy(flagname, beg, maxlen);
		flagname[maxlen] = 0;
	}

	if (strcmp(name,"PROPRIETARY_MODULE") == 0)
		toggle_taint_flag(TAINT_PROPRIETARY_MODULE);
	else if (strcmp(name,"FORCED_MODULE") == 0)
		toggle_taint_flag(TAINT_FORCED_MODULE);
	else if (strcmp(name,"UNSAFE_SMP") == 0)
		toggle_taint_flag(TAINT_UNSAFE_SMP);
	else if (strcmp(name,"FORCED_RMMOD") == 0)
		toggle_taint_flag(TAINT_FORCED_RMMOD);
	else if (strcmp(name,"MACHINE_CHECK") == 0)
		toggle_taint_flag(TAINT_MACHINE_CHECK);
	else if (strcmp(name,"BAD_PAGE") == 0)
		toggle_taint_flag(TAINT_BAD_PAGE);
	else if (strcmp(name,"USER") == 0)
		toggle_taint_flag(TAINT_USER);
	else if (strcmp(name,"DIE") == 0)
		toggle_taint_flag(TAINT_DIE);
	else if (strcmp(name,"OVERRIDDEN_ACPI_TABLE") == 0)
		toggle_taint_flag(TAINT_OVERRIDDEN_ACPI_TABLE);
	else if (strcmp(name,"WARN") == 0)
		toggle_taint_flag(TAINT_WARN);
	else if (strcmp(name,"CRAP") == 0)
		toggle_taint_flag(TAINT_CRAP);
	else if (strcmp(name,"FIRMWARE_WORKAROUND") == 0)
		toggle_taint_flag(TAINT_FIRMWARE_WORKAROUND);
	else if (strcmp(name,"OOT_MODULE") == 0)
		toggle_taint_flag(TAINT_OOT_MODULE);
	else {
		outputerr("Unrecognizable kernel taint flag \"%s\".\n", name);
		exit(EXIT_FAILURE);
	}
}

void process_taint_arg(char *taintarg)
{
	char *beg, *end;

	if (kernel_taint_param_occured == false) {
		kernel_taint_param_occured = true;
		kernel_taint_mask = 0; //We now only care about flags that user specified.
	}

	beg = taintarg;
	end = strchr(beg, ',');
	while(end != NULL) {
		toggle_taint_flag_by_name(beg,end);
		beg = end + 1;
		end = strchr(beg, ',');
	}
	toggle_taint_flag_by_name(beg,end);
}

void init_taint_checking(void)
{
	int fd;

	fd = open("/proc/sys/kernel/tainted", O_RDONLY);
	if (fd >= 0) {
		taint_available = true;
		close(fd);
	}

	kernel_taint_initial = get_taint();
	if (kernel_taint_initial != 0)
		output(0, "Kernel was tainted on startup. Will ignore flags that are already set.\n");
}
