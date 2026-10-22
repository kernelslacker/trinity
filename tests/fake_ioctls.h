#pragma once

struct ioctl_group;

/*
 * What pick_random_ioctl() leaves in the arg.  A sanitiser that builds a
 * struct replaces it, so a left-over one means it built none.
 */
#define FAKE_IOCTL_JUNK_ARG	0xdeadbeefUL

/* The request pick_random_ioctl() picks.  The test sets it. */
extern unsigned long fake_ioctl_request;

/* The registered group called @name, or NULL. */
const struct ioctl_group *fake_ioctl_group(const char *name);
