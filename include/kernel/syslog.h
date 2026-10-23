#pragma once

/*
 * syslog(2) action numbers.  The kernel keeps them in its internal
 * include/linux/syslog.h, which headers_install does not export, and
 * glibc's <sys/klog.h> declares klogctl() without them.
 */
#ifndef SYSLOG_ACTION_CLOSE
#define SYSLOG_ACTION_CLOSE		0
#endif
#ifndef SYSLOG_ACTION_OPEN
#define SYSLOG_ACTION_OPEN		1
#endif
#ifndef SYSLOG_ACTION_READ
#define SYSLOG_ACTION_READ		2
#endif
#ifndef SYSLOG_ACTION_READ_ALL
#define SYSLOG_ACTION_READ_ALL		3
#endif
#ifndef SYSLOG_ACTION_READ_CLEAR
#define SYSLOG_ACTION_READ_CLEAR	4
#endif
#ifndef SYSLOG_ACTION_CLEAR
#define SYSLOG_ACTION_CLEAR		5
#endif
#ifndef SYSLOG_ACTION_CONSOLE_OFF
#define SYSLOG_ACTION_CONSOLE_OFF	6
#endif
#ifndef SYSLOG_ACTION_CONSOLE_ON
#define SYSLOG_ACTION_CONSOLE_ON	7
#endif
#ifndef SYSLOG_ACTION_CONSOLE_LEVEL
#define SYSLOG_ACTION_CONSOLE_LEVEL	8
#endif
#ifndef SYSLOG_ACTION_SIZE_UNREAD
#define SYSLOG_ACTION_SIZE_UNREAD	9
#endif
#ifndef SYSLOG_ACTION_SIZE_BUFFER
#define SYSLOG_ACTION_SIZE_BUFFER	10
#endif
