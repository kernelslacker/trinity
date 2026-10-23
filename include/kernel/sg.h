#pragma once

/*
 * SG_GET_ACCESS_COUNT is defined in the kernel's own include/scsi/sg.h,
 * which is not exported, and glibc's <scsi/sg.h> lacks it.
 */
#include <scsi/sg.h>

#ifndef SG_GET_ACCESS_COUNT
#define SG_GET_ACCESS_COUNT	0x2289
#endif
