#pragma once

#include <sys/syscall.h>
#include <unistd.h>

#include <linux/bpf.h>

static inline int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}
