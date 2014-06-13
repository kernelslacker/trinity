#pragma once

#include "utils.h"

void show_backtrace(void);

extern void __BUG(const char *bugtxt, const char *filename, const char *funcname, unsigned int lineno);

#define BUG(bugtxt)	{ \
	__BUG(bugtxt, __FILE__, __func__, __LINE__); \
	unreachable(); \
}

#define BUG_ON(condition)	do { if ((condition)) BUG(__stringify(condition)); } while (0)
