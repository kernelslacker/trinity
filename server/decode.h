#pragma once

//#include "trinity.h"
#include "udp.h"

struct msgfunc {
	void (*func)(char *buf);
};

extern const struct msgfunc decodefuncs[MAX_LOGMSGTYPE];
