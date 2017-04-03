#pragma once

//#include "trinity.h"
#include "udp.h"

#define MAXBUF 10240

extern char buf[MAXBUF];

struct msgfunc {
	void (*func)(void);
};

extern const struct msgfunc decodefuncs[MAX_LOGMSGTYPE];
