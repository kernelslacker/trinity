#pragma once

#include "list.h"

struct packet {
	struct list_head list;
	struct timespec tp;
	char * data;
};
