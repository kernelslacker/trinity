#pragma once

#include <sys/wait.h>

#ifndef __WNOTHREAD
#define __WNOTHREAD 0x20000000
#endif
#ifndef __WALL
#define __WALL      0x40000000
#endif
#ifndef __WCLONE
#define __WCLONE    0x80000000
#endif
