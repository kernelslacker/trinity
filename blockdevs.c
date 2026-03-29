#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include "bdevs.h"
#include "list.h"
#include "trinity.h"
#include "types.h"
#include "utils.h"

static unsigned int nr_blockdevs = 0;

struct bdevlist {
	struct list_head list;
	const char *name;
};

static struct bdevlist *bdevs = NULL;

static void add_to_bdevlist(const char *name)
{
	struct bdevlist *newnode;
	struct stat sb;
	char pathbuf[PATH_MAX];
	const char *path = name;

	/* If the path doesn't start with /dev/, prepend it. */
	if (strncmp(name, "/dev/", 5) != 0) {
		snprintf(pathbuf, sizeof(pathbuf), "/dev/%s", name);
		path = pathbuf;
	}

	/* Verify the path exists and is a block device. */
	if (stat(path, &sb) == -1) {
		outputerr("Couldn't stat %s: not a valid device node.\n", path);
		return;
	}

	if (!S_ISBLK(sb.st_mode)) {
		outputerr("%s is not a block device.\n", path);
		return;
	}

	newnode = zmalloc(sizeof(struct bdevlist));
	newnode->name = strdup(path);
	if (!newnode->name) {
		free(newnode);
		return;
	}
	list_add_tail(&newnode->list, &bdevs->list);
	nr_blockdevs++;
}

static void stat_dev(char *name)
{
	struct stat sb;
	int ret;

	ret = lstat(name, &sb);

	if (ret == -1) {
		outputerr("Couldn't open %s\n", name);
		exit(EXIT_FAILURE);
	}

	if (!(S_ISBLK(sb.st_mode))) {
		outputerr("Sorry, %s doesn't look like a block device.\n", name);
		exit(EXIT_FAILURE);
	}

	add_to_bdevlist(name);
}

void process_bdev_param(char *optarg)
{
	unsigned int len, i;
	char *str = optarg;

	len = strlen(optarg);

	/* Check if there are any commas. If so, split them into multiple devs. */
	for (i = 0; i < len; i++) {
		if (optarg[i] == ',') {
			optarg[i] = 0;
			stat_dev(str);
			str = optarg + i + 1;
		}
	}

	stat_dev(str);
}

void init_bdev_list(void)
{
	bdevs = zmalloc(sizeof(struct bdevlist));
	INIT_LIST_HEAD(&bdevs->list);
}

void dump_bdev_list(void)
{
	struct list_head *node;

	output(1, "Found %u block devices.\n", nr_blockdevs);
	list_for_each(node, &bdevs->list) {
		struct bdevlist *nl;

		nl = (struct bdevlist *) node;
		output(1, "%s\n", nl->name);
	}
}
