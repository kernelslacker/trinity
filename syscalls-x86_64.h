#ifndef _SYSCALLS_x86_64_H
#define _SYSCALLS_x86_64_H 1

/* Syscalls from arch/x86/include/asm/unistd_64.h as of 2.6.35 */

#include "scrashme.h"
#include "sanitise.h"

#define NR_SYSCALLS 302

struct syscalltable syscalls_x86_64[NR_SYSCALLS+1] = {
	/*-----------------------------------------------------------------------------------------------
	  #0
	   SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count) */
	{
		.name = "read",
		.num_args = 3,
		.sanitise = sanitise_read,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #1
	   SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf, size_t, count) */
	{
		.name = "write",
		.num_args = 3,
		.sanitise = sanitise_write,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #2
	   SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, int, mode) */
	{
		.name = "open",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #3
	   SYSCALL_DEFINE1(close, unsigned int, fd) */
	{
		.name = "close",
		.num_args = 1,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #4
	   SYSCALL_DEFINE2(newstat, const char __user *, filename, struct stat __user *, statbuf) */
	{
		.name = "newstat",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #5
	   SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf) */
	{
		.name = "newfstat",
		.num_args = 2,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #6
	   SYSCALL_DEFINE2(newlstat, const char __user *, filename, struct stat __user *, statbuf) */
	{
		.name = "newlstat",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #7
	   SYSCALL_DEFINE3(poll, struct pollfd __user *, ufds, unsigned int, nfds, long, timeout_msecs) */
	{
		.name = "poll",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #8
	   SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, origin) */
	{
		.name = "lseek",
		.num_args = 3,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #9
	   SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
                unsigned long, prot, unsigned long, flags,
                unsigned long, fd, unsigned long, off) */
	{
		.name = "mmap",
		.num_args = 6,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
		.arg5type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #10
	   SYSCALL_DEFINE3(mprotect, unsigned long, start, size_t, len, unsigned long, prot) */
	{
		.name = "mprotect",
		.num_args = 3,
		.arg1name = "start",
		.arg1type = ARG_ADDRESS,
		.arg2name = "len",
		.arg2type = ARG_LEN,
		.arg3name = "prot",
		.sanitise = sanitise_mprotect,
	},
	/*-----------------------------------------------------------------------------------------------
	  #11
	   SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len) */
	{
		.name = "munmap",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #12
	   SYSCALL_DEFINE1(brk, unsigned long, brk) */
	{
		.name = "brk",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #13
	   SYSCALL_DEFINE4(rt_sigaction, int, sig,
                const struct sigaction __user *, act,
                struct sigaction __user *, oact,
                size_t, sigsetsize) */
	{
		.name = "rt_sigaction",
		.num_args = 4,
		.sanitise = sanitise_rt_sigaction,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #14
	   SYSCALL_DEFINE4(rt_sigprocmask, int, how, sigset_t __user *, set,
		sigset_t __user *, oset, size_t, sigsetsize) */
	{
		.name = "rt_sigprocmask",
		.num_args = 4,
		.sanitise = sanitise_rt_sigprocmask,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #15
	   long sys_rt_sigreturn(struct pt_regs *regs) */
	{
		.name = "rt_sigreturn",
		.num_args = 1,
		.flags = AVOID_SYSCALL,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #16
	   SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg) */
	{
		.name = "ioctl",
		.num_args = 3,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #17
	   SYSCALL_DEFINE(pread64)(unsigned int fd, char __user *buf, size_t count, loff_t pos) */
	{
		.name = "pread64",
		.num_args = 4,
		.sanitise = sanitise_pread64,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #18
	   SYSCALL_DEFINE(pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t pos) */
	{
		.name = "pwrite64",
		.num_args = 4,
		.sanitise = sanitise_pwrite64,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #19
	   SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen) */
	{
		.name = "readv",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #20
	   SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen) */
	{
		.name = "writev",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #21
	   SYSCALL_DEFINE2(access, const char __user *, filename, int, mode) */
	{
		.name = "access",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #22
	   SYSCALL_DEFINE1(pipe, int __user *, fildes) */
	{
		.name = "pipe",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #23
	   SYSCALL_DEFINE5(select, int, n, fd_set __user *, inp, fd_set __user *, outp,
                fd_set __user *, exp, struct timeval __user *, tvp)  */
	{
		.name = "select",
		.num_args = 5,
		.flags = AVOID_SYSCALL,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #24
	   SYSCALL_DEFINE0(sched_yield) */
	{
		.name = "sched_yield",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #25
	   SYSCALL_DEFINE5(mremap, unsigned long, addr, unsigned long, old_len,
                unsigned long, new_len, unsigned long, flags,
                unsigned long, new_addr) */
	{
		.name = "mremap",
		.num_args = 5,
		.sanitise = sanitise_mremap,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
		.arg3type = ARG_LEN,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #26
	   SYSCALL_DEFINE3(msync, unsigned long, start, size_t, len, int, flags) */
	{
		.name = "msync",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #27
	   SYSCALL_DEFINE3(mincore, unsigned long, start, size_t, len, unsigned char __user *, vec) */
	{
		.name = "mincore",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #28
	   SYSCALL_DEFINE3(madvise, unsigned long, start, size_t, len_in, int, behavior) */
	{
		.name = "madvise",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #29
	   SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg) */
	{
		.name = "shmget",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #30
	   SYSCALL_DEFINE3(shmat, int, shmid, char __user *, shmaddr, int, shmflg) */
	{
		.name = "shmat",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #31
	   SYSCALL_DEFINE3(shmctl, int, shmid, int, cmd, struct shmid_ds __user *, buf) */
	{
		.name = "shmctl",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #32
	   SYSCALL_DEFINE1(dup, unsigned int, fildes) */
	{
		.name = "dup",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #33
	   SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd) */
	{
		.name = "dup2",
		.num_args = 2,
		.arg1type = ARG_FD,
		.arg2type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #34
	   SYSCALL_DEFINE0(pause) */
	{
		.name = "pause",
		.num_args = 0,
		.flags = AVOID_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #35
	   SYSCALL_DEFINE2(nanosleep, struct timespec __user *, rqtp, struct timespec __user *, rmtp) */
	{
		.name = "nanosleep",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #36
	   SYSCALL_DEFINE2(getitimer, int, which, struct itimerval __user *, value) */
	{
		.name = "getitimer",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #37
	   SYSCALL_DEFINE1(alarm, unsigned int, seconds) */
	{
		.name = "alarm",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #38
	   SYSCALL_DEFINE3(setitimer, int, which, struct itimerval __user *, value, struct itimerval __user *, ovalue) */
	{
		.name = "setitimer",
		.num_args = 3,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #39
	   SYSCALL_DEFINE0(getpid) */
	{
		.name = "getpid",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #40
	   SYSCALL_DEFINE4(sendfile, int, out_fd, int, in_fd, off_t __user *, offset, size_t, count) */
	{
		.name = "sendfile",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_FD,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #41
	   SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol) */
	{
		.name = "socket",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #42
	   SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr, int, addrlen */
	{
		.name = "connect",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #43
	   SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr, int __user *, upeer_addrlen) */
	{
		.name = "accept",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #44
	   SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
                 unsigned, flags, struct sockaddr __user *, addr,
                 int, addr_len) */
	{
		.name = "sendto",
		.num_args = 6,
		.sanitise = sanitise_sendto,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
		.arg5type = ARG_ADDRESS,
		.arg6type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #45
	   SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
                unsigned, flags, struct sockaddr __user *, addr,
                int __user *, addr_len) */
	{
		.name = "recvfrom",
		.num_args = 6,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
		.arg5type = ARG_ADDRESS,
		.arg6type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #46
	   SYSCALL_DEFINE3(sendmsg, int, fd, struct msghdr __user *, msg, unsigned, flags) */
	{
		.name = "sendmsg",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #47
	   SYSCALL_DEFINE3(recvmsg, int, fd, struct msghdr __user *, msg, unsigned int, flags) */
	{
		.name = "recvmsg",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #48
	   SYSCALL_DEFINE2(shutdown, int, fd, int, how) */
	{
		.name = "shutdown",
		.num_args = 2,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #49
	   SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen) */
	{
		.name = "bind",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #50
	   SYSCALL_DEFINE2(listen, int, fd, int, backlog) */
	{
		.name = "listen",
		.num_args = 2,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #51
	   SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr, int __user *, usockaddr_len) */
	{
		.name = "getsockname",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #52
	   SYSCALL_DEFINE3(getpeername, int, fd, struct sockaddr __user *, usockaddr, int __user *, usockaddr_len) */
	{
		.name = "getpeername",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #53
	   SYSCALL_DEFINE4(socketpair, int, family, int, type, int, protocol, int __user *, usockvec) */
	{
		.name = "socketpair",
		.num_args = 4,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #54
	   SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen) */
	{
		.name = "setsockopt",
		.num_args = 5,
		.arg1type = ARG_FD,
		.arg4type = ARG_ADDRESS,
		.arg5type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #55
	   SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname, char __user *, optval, int __user *, optlen) */
	{
		.name = "getsockopt",
		.num_args = 5,
		.arg1type = ARG_FD,
		.arg4type = ARG_ADDRESS,
		.arg5type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #56
	   long sys_clone(unsigned long clone_flags, unsigned long newsp,
		void __user *parent_tid, void __user *child_tid, struct pt_regs *regs) */
	{
		.name = "clone",
		.num_args = 5,
		.flags = AVOID_SYSCALL,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #57
	   int sys_fork(struct pt_regs *regs) */
	{
		.name = "fork",
		.num_args = 1,
		.flags = AVOID_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #58
	   int sys_vfork(struct pt_regs *regs) */
	{
		.name = "vfork",
		.num_args = 1,
		.flags = AVOID_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #59
	   long sys_execve(const char __user *name,
                const char __user *const __user *argv,
                const char __user *const __user *envp, struct pt_regs *regs) */
	{
		.name = "execve",
		.num_args = 4,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #60
	   SYSCALL_DEFINE1(exit, int, error_code) */
	{
		.name = "exit",
		.num_args = 1,
		.flags = AVOID_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #61
	   SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
                 int, options, struct rusage __user *, ru) */
	{
		.name = "wait4",
		.num_args = 4,
		.arg2type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #62
	   SYSCALL_DEFINE2(kill, pid_t, pid, int, sig) */
	{
		.name = "kill",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #63
	   SYSCALL_DEFINE1(uname, struct old_utsname __user *, name) */
	{
		.name = "uname",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #64
	   SYSCALL_DEFINE3(semget, key_t, key, int, nsems, int, semflg) */
	{
		.name = "semget",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #65
	   SYSCALL_DEFINE3(semop, int, semid, struct sembuf __user *, tsops, unsigned, nsops) */
	{
		.name = "semop",
		.num_args = 3,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #66
	   SYSCALL_DEFINE(semctl)(int semid, int semnum, int cmd, union semun arg) */
	{
		.name = "semctl",
		.num_args = 4,
	},
	/*-----------------------------------------------------------------------------------------------
	  #67
	   SYSCALL_DEFINE1(shmdt, char __user *, shmaddr) */
	{
		.name = "shmdt",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #68
	   SYSCALL_DEFINE2(msgget, key_t, key, int, msgflg) */
	{
		.name = "msgget",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #69
	   SYSCALL_DEFINE4(msgsnd, int, msqid, struct msgbuf __user *, msgp, size_t, msgsz, int, msgflg) */
	{
		.name = "msgsnd",
		.num_args = 4,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #70
	   SYSCALL_DEFINE5(msgrcv, int, msqid, struct msgbuf __user *, msgp, size_t, msgsz, long, msgtyp, int, msgflg) */
	{
		.name = "msgrcv",
		.num_args = 5,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #71
	   SYSCALL_DEFINE3(msgctl, int, msqid, int, cmd, struct msqid_ds __user *, buf) */
	{
		.name = "msgctl",
		.num_args = 3,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #72
	   SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg) */
	{
		.name = "fcntl",
		.num_args = 3,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #73
	   SYSCALL_DEFINE2(flock, unsigned int, fd, unsigned int, cmd) */
	{
		.name = "flock",
		.num_args = 2,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #74
	   SYSCALL_DEFINE1(fsync, unsigned int, fd) */
	{
		.name = "fsync",
		.num_args = 1,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #75
	   SYSCALL_DEFINE1(fdatasync, unsigned int, fd) */
	{
		.name = "fdatasync",
		.num_args = 1,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #76
	   SYSCALL_DEFINE2(truncate, const char __user *, path, long, length) */
	{
		.name = "truncate",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #77
	   SYSCALL_DEFINE2(ftruncate, unsigned int, fd, unsigned long, length) */
	{
		.name = "ftruncate",
		.num_args = 2,
		.arg1type = ARG_FD,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #78
	   SYSCALL_DEFINE3(getdents, unsigned int, fd,
	    struct linux_dirent __user *, dirent, unsigned int, count) */
	{
		.name = "getdents",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #79
	   SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size) */
	{
		.name = "getcwd",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #80
	   SYSCALL_DEFINE1(chdir, const char __user *, filename) */
	{
		.name = "chdir",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #81
	   SYSCALL_DEFINE1(fchdir, unsigned int, fd) */
	{
		.name = "fchdir",
		.num_args = 1,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #82
	   SYSCALL_DEFINE2(rename, const char __user *, oldname, const char __user *, newname */
	{
		.name = "rename",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #83
	   SYSCALL_DEFINE2(mkdir, const char __user *, pathname, int, mode) */
	{
		.name = "mkdir",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #84
	   SYSCALL_DEFINE1(rmdir, const char __user *, pathname) */
	{
		.name =	 "rmdir",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #85
	   SYSCALL_DEFINE2(creat, const char __user *, pathname, int, mode) */
	{
		.name = "creat",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #86
	   SYSCALL_DEFINE2(link, const char __user *, oldname, const char __user *, newname) */
	{
		.name = "link",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #87
	   SYSCALL_DEFINE1(unlink, const char __user *, pathname) */
	{
		.name = "unlink",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #88
	   SYSCALL_DEFINE2(symlink, const char __user *, oldname, const char __user *, newname) */
	{
		.name = "symlink",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #89
	   SYSCALL_DEFINE3(readlink, const char __user *, path, char __user *, buf, int, bufsiz) */
	{
		.name = "readlink",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #90
	   SYSCALL_DEFINE2(chmod, const char __user *, filename, mode_t, mode) */
	{
		.name = "chmod",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #91
	   SYSCALL_DEFINE2(fchmod, unsigned int, fd, mode_t, mode) */
	{
		.name = "fchmod",
		.num_args = 2,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #92
	   SYSCALL_DEFINE3(chown, const char __user *, filename, uid_t, user, gid_t, group) */
	{
		.name = "chown",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #93
	   SYSCALL_DEFINE3(fchown, unsigned int, fd, uid_t, user, gid_t, group) */
	{
		.name = "fchown",
		.num_args = 3,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #94
	   SYSCALL_DEFINE3(lchown, const char __user *, filename, uid_t, user, gid_t, group) */
	{
		.name = "lchown",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #95
	   SYSCALL_DEFINE1(umask, int, mask) */
	{
		.name = "umask",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #96
	   SYSCALL_DEFINE2(gettimeofday, struct timeval __user *, tv, struct timezone __user *, tz) */
	{
		.name = "gettimeofday",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #97
	   SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim) */
	{
		.name = "getrlimit",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #98
	   SYSCALL_DEFINE2(getrusage, int, who, struct rusage __user *, ru) */
	{
		.name = "getrusage",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #99
	   SYSCALL_DEFINE1(sysinfo, struct sysinfo __user *, info) */
	{
		.name = "sysinfo",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #100
	   SYSCALL_DEFINE1(times, struct tms __user *, tbuf) */
	{
		.name = "times",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #101
	   SYSCALL_DEFINE4(ptrace, long, request, long, pid, long, addr, long, data) */
	{
		.name = "ptrace",
		.num_args = 4,
	},
	/*-----------------------------------------------------------------------------------------------
	  #102
	   SYSCALL_DEFINE0(getuid) */
	{
		.name = "getuid",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #103
	   SYSCALL_DEFINE3(syslog, int, type, char __user *, buf, int, len) */
	{
		.name = "syslog",
		.num_args = 3,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #104
	   SYSCALL_DEFINE0(getgid) */
	{
		.name = "getgid",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #105
	   SYSCALL_DEFINE1(setuid, uid_t, uid) */
	{
		.name = "setuid",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #106
	   SYSCALL_DEFINE1(setgid, gid_t, gid) */
	{
		.name = "setgid",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #107
	   SYSCALL_DEFINE0(geteuid) */
	{
		.name = "geteuid",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #108
	   SYSCALL_DEFINE0(getegid) */
	{
		.name = "getegid",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #109
	   SYSCALL_DEFINE2(setpgid, pid_t, pid, pid_t, pgid) */
	{
		.name = "setpgid",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #110
	   SYSCALL_DEFINE0(getppid) */
	{
		.name = "getppid",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #111
	   SYSCALL_DEFINE0(getpgrp) */
	{
		.name = "getpgrp",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #112
	   SYSCALL_DEFINE0(setsid) */
	{
		.name = "setsid",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #113
	   SYSCALL_DEFINE2(setreuid, uid_t, ruid, uid_t, euid) */
	{
		.name = "setreuid",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #114
	   SYSCALL_DEFINE2(setregid, gid_t, rgid, gid_t, egid) */
	{
		.name = "setregid",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #115
	   SYSCALL_DEFINE2(getgroups, int, gidsetsize, gid_t __user *, grouplist) */
	{
		.name = "getgroups",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #116
	   SYSCALL_DEFINE2(setgroups, int, gidsetsize, gid_t __user *, grouplist) */
	{
		.name = "setgroups",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #117
	   SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid) */
	{
		.name = "setresuid",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #118
	   SYSCALL_DEFINE3(getresuid, uid_t __user *, ruid, uid_t __user *, euid, uid_t __user *, suid) */
	{
		.name = "getresuid",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #119
	   SYSCALL_DEFINE3(setresgid, gid_t, rgid, gid_t, egid, gid_t, sgid) */
	{
		.name = "setresgid",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #120
	   SYSCALL_DEFINE3(getresgid, gid_t __user *, rgid, gid_t __user *, egid, gid_t __user *, sgid) */
	{
		.name = "getresgid",
		.num_args = 3,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #121
	   SYSCALL_DEFINE1(getpgid, pid_t, pid) */
	{
		.name = "getpgid",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #122
	   SYSCALL_DEFINE1(setfsuid, uid_t, uid) */
	{
		.name = "setfsuid",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #123
	   SYSCALL_DEFINE1(setfsgid, gid_t, gid) */
	{
		.name = "setfsgid",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #124
	   SYSCALL_DEFINE1(getsid, pid_t, pid) */
	{
		.name = "getsid",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #125
	   SYSCALL_DEFINE2(capget, cap_user_header_t, header, cap_user_data_t, dataptr) */
	{
		.name = "capget",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #126
	   SYSCALL_DEFINE2(capset, cap_user_header_t, header, const cap_user_data_t, data) */
	{
		.name = "capset",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #127
	   SYSCALL_DEFINE2(rt_sigpending, sigset_t __user *, set, size_t, sigsetsize) */
	{
		.name = "rt_sigpending",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #128
	   SYSCALL_DEFINE4(rt_sigtimedwait, const sigset_t __user *, uthese,
                 siginfo_t __user *, uinfo, const struct timespec __user *, uts,
                 size_t, sigsetsize) */
	{
		.name = "rt_sigtimedwait",
		.num_args = 4,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #129
	   SYSCALL_DEFINE3(rt_sigqueueinfo, pid_t, pid, int, sig, siginfo_t __user *, uinfo) */
	{
		.name = "rt_sigqueueinfo",
		.num_args = 3,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #130
	   SYSCALL_DEFINE2(rt_sigsuspend, sigset_t __user *, unewset, size_t, sigsetsize) */
	{
		.name = "rt_sigsuspend",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #131
	   long sys_sigaltstack(const stack_t __user *uss, stack_t __user *uoss,
                 struct pt_regs *regs) */
	{
		.name = "sigaltstack",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #132
	   SYSCALL_DEFINE2(utime, char __user *, filename, struct utimbuf __user *, times) */
	{
		.name = "utime",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #133
	   SYSCALL_DEFINE3(mknod, const char __user *, filename, int, mode, unsigned, dev) */
	{
		.name = "mknod",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #134
	   SYSCALL_DEFINE1(uselib, const char __user *, library) */
	{
		.name = "ni_syscall (uselib)",
		.num_args = 0,
		.flags = NI_SYSCALL,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #135
	   SYSCALL_DEFINE1(personality, unsigned int, personality */
	{
		.name = "personality",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #136
	   SYSCALL_DEFINE2(ustat, unsigned, dev, struct ustat __user *, ubuf) */
	{
		.name = "ustat",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #137
	   SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf) */
	{
		.name = "statfs",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #138
	   SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct statfs __user *, buf) */
	{
		.name = "fstatfs",
		.num_args = 2,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #139
	   SYSCALL_DEFINE3(sysfs, int, option, unsigned long, arg1, unsigned long, arg2) */
	{
		.name = "sysfs",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #140
	   SYSCALL_DEFINE2(getpriority, int, which, int, who) */
	{
		.name = "getpriority",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #141
	   SYSCALL_DEFINE3(setpriority, int, which, int, who, int, niceval) */
	{
		.name = "setpriority",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #142
	   SYSCALL_DEFINE2(sched_setparam, pid_t, pid, struct sched_param __user *, param) */
	{
		.name = "sched_setparam",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #143
	   SYSCALL_DEFINE2(sched_getparam, pid_t, pid, struct sched_param __user *, param) */
	{
		.name = "sched_getparam",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #144
	   SYSCALL_DEFINE3(sched_setscheduler, pid_t, pid, int, policy, struct sched_param __user *, param) */
	{
		.name = "sched_setscheduler",
		.num_args = 3,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #145
	   SYSCALL_DEFINE1(sched_getscheduler, pid_t, pid) */
	{
		.name = "sched_getscheduler",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #146
	   SYSCALL_DEFINE1(sched_get_priority_max, int, policy) */
	{
		.name = "sched_get_priority_max",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #147
	   SYSCALL_DEFINE1(sched_get_priority_min, int, policy) */
	{
		.name = "sched_get_priority_min",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #148
	   SYSCALL_DEFINE2(sched_rr_get_interval, pid_t, pid, struct timespec __user *, interval) */
	{
		.name = "sched_rr_get_interval",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #149
	   SYSCALL_DEFINE2(mlock, unsigned long, start, size_t, len) */
	{
		.name = "mlock",
		.num_args = 2,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #150
	   SYSCALL_DEFINE2(munlock, unsigned long, start, size_t, len) */
	{
		.name = "munlock",
		.num_args = 2,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #151
	   SYSCALL_DEFINE1(mlockall, int, flags) */
	{
		.name = "mlockall",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #152
	   SYSCALL_DEFINE0(munlockall) */
	{
		.name = "munlockall",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #153
	   SYSCALL_DEFINE0(vhangup */
	{
		.name = "vhangup",
		.num_args = 0,
		.flags = AVOID_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #154
	   asmlinkage int sys_modify_ldt(int func, void __user *ptr, unsigned long bytecount) */
	{
		.name = "modify_ldt",
		.num_args = 3,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #155
	   SYSCALL_DEFINE2(pivot_root, const char __user *, new_root, const char __user *, put_old) */
	{
		.name = "pivot_root",
		.num_args = 2,
		.flags = CAPABILITY_CHECK,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #156
	   SYSCALL_DEFINE1(sysctl, struct __sysctl_args __user *, args */
	{
		.name = "sysctl",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #157
	   SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
                 unsigned long, arg4, unsigned long, arg5) */
	{
		.name = "prctl",
		.num_args = 5,
	},
	/*-----------------------------------------------------------------------------------------------
	  #158
	   long sys_arch_prctl(int code, unsigned long addr) */
	{
		.name = "arch_prctl",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #159
	   SYSCALL_DEFINE1(adjtimex, struct timex __user *, txc_p */
	{
		.name = "adjtimex",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #160
	   SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim) */
	{
		.name = "setrlimit",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #161
	   SYSCALL_DEFINE1(chroot, const char __user *, filename) */
	{
		.name = "chroot",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #162
	   SYSCALL_DEFINE0(sync) */
	{
		.name = "sync",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #163
	   SYSCALL_DEFINE1(acct, const char __user *, name) */
	{
		.name = "acct",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #164
	   SYSCALL_DEFINE2(settimeofday, struct timeval __user *, tv, struct timezone __user *, tz) */
	{
		.name = "settimeofday",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #165
	   SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
                 char __user *, type, unsigned long, flags, void __user *, data) */
	{
		.name = "mount",
		.num_args = 5,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #166
	   SYSCALL_DEFINE2(umount, char __user *, name, int, flags) */
	{
		.name = "umount",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #167
	   SYSCALL_DEFINE2(swapon, const char __user *, specialfile, int, swap_flags */
	{
		.name = "swapon",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #168
	   SYSCALL_DEFINE1(swapoff, const char __user *, specialfile) */
	{
		.name = "swapoff",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #169
	   SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd, void __user *, arg) */
	{
		.name = "reboot",
		.num_args = 4,
		.flags = CAPABILITY_CHECK,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #170
	   SYSCALL_DEFINE2(sethostname, char __user *, name, int, len) */
	{
		.name = "sethostname",
		.num_args = 2,
		.flags = CAPABILITY_CHECK,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #171
	   SYSCALL_DEFINE2(setdomainname, char __user *, name, int, len) */
	{
		.name = "setdomainname",
		.num_args = 2,
		.flags = CAPABILITY_CHECK,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #172
	   long sys_iopl(unsigned int level, struct pt_regs *regs) */
	{
		.name = "iopl",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #173
	   asmlinkage long sys_ioperm(unsigned long from, unsigned long num, int turn_on) */
	{
		.name = "ioperm",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #174
	    */
	{
		.name = "ni_syscall (create_module)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #175
	   SYSCALL_DEFINE3(init_module, void __user *, umod,
                 unsigned long, len, const char __user *, uargs) */
	{
		.name = "init_module",
		.num_args = 3,
		.flags = CAPABILITY_CHECK,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #176
	   SYSCALL_DEFINE2(delete_module, const char __user *, name_user, unsigned int, flags */
	{
		.name = "delete_module",
		.num_args = 2,
		.flags = CAPABILITY_CHECK,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #177
	    */
	{
		.name = "ni_syscall (get_kernel_syms)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #178
	    */
	{
		.name = "ni_syscall (query_module)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #179
	   SYSCALL_DEFINE4(quotactl, unsigned int, cmd, const char __user *, special,
                 qid_t, id, void __user *, addr) */
	{
		.name = "quotactl",
		.num_args = 4,
		.arg2type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #180
	   SYSCALL_DEFINE3(nfsservctl, int, cmd, struct nfsctl_arg __user *, arg, void __user *, res */
	{
		.name = "nfsservctl",
		.num_args = 3,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #181
	    */
	{
		.name = "ni_syscall (getpmsg)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #182
	    */
	{
		.name = "ni_syscall (putpmsg)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #183
	    */
	{
		.name = "ni_syscall (afs)",
		.num_args = 6,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #184
	    */
	{
		.name = "ni_syscall (tux)",
		.num_args = 6,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #185
	    */
	{
		.name = "ni_syscall (security)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #186
	   SYSCALL_DEFINE0(gettid) */
	{
		.name = "gettid",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #187
	   SYSCALL_DEFINE(readahead)(int fd, loff_t offset, size_t count) */
	{
		.name = "readahead",
		.num_args = 3,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #188
	   SYSCALL_DEFINE5(setxattr, const char __user *, pathname,
                 const char __user *, name, const void __user *, value,
                 size_t, size, int, flags) */
	{
		.name = "setxattr",
		.num_args = 5,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #189
	   SYSCALL_DEFINE5(lsetxattr, const char __user *, pathname,
                 const char __user *, name, const void __user *, value,
                 size_t, size, int, flags) */
	{
		.name = "lsetxattr",
		.num_args = 5,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #190
	   SYSCALL_DEFINE5(fsetxattr, int, fd, const char __user *, name,
                 const void __user *,value, size_t, size, int, flags) */
	{
		.name = "fsetxattr",
		.num_args = 5,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #191
	   SYSCALL_DEFINE4(getxattr, const char __user *, pathname,
                 const char __user *, name, void __user *, value, size_t, size) */
	{
		.name = "getxattr",
		.num_args = 4,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #192
	   SYSCALL_DEFINE4(lgetxattr, const char __user *, pathname,
                 const char __user *, name, void __user *, value, size_t, size) */
	{
		.name = "lgetxattr",
		.num_args = 4,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #193
	   SYSCALL_DEFINE4(fgetxattr, int, fd, const char __user *, name,
                 void __user *, value, size_t, size) */
	{
		.name = "fgetxattr",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #194
	   SYSCALL_DEFINE3(listxattr, const char __user *, pathname, char __user *, list, size_t, size */
	{
		.name = "listxattr",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #195
	   SYSCALL_DEFINE3(llistxattr, const char __user *, pathname, char __user *, list, size_t, size) */
	{
		.name = "llistxattr",
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #196
	   SYSCALL_DEFINE3(flistxattr, int, fd, char __user *, list, size_t, size) */
	{
		.name = "flistxattr",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #197
	   SYSCALL_DEFINE2(removexattr, const char __user *, pathname, const char __user *, name) */
	{
		.name = "removexattr",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #198
	   SYSCALL_DEFINE2(lremovexattr, const char __user *, pathname, const char __user *, name) */
	{
		.name = "lremovexattr",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #199
	   SYSCALL_DEFINE2(fremovexattr, int, fd, const char __user *, name) */
	{
		.name = "fremovexattr",
		.num_args = 2,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #200
	   SYSCALL_DEFINE2(tkill, pid_t, pid, int, sig) */
	{
		.name = "tkill",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #201
	   SYSCALL_DEFINE1(time, time_t __user *, tloc) */
	{
		.name = "time",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #202
	   SYSCALL_DEFINE6(futex, u32 __user *, uaddr, int, op, u32, val,
                 struct timespec __user *, utime, u32 __user *, uaddr2, u32, val3) */
	{
		.name = "futex",
		.num_args = 6,
		.arg1type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #203
	   SYSCALL_DEFINE3(sched_setaffinity, pid_t, pid, unsigned int, len,
                 unsigned long __user *, user_mask_ptr) */
	{
		.name = "sched_setaffinity",
		.num_args = 3,
		.arg2type = ARG_LEN,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #204
	   SYSCALL_DEFINE3(sched_getaffinity, pid_t, pid, unsigned int, len,
                 unsigned long __user *, user_mask_ptr) */
	{
		.name = "sched_getaffinity",
		.num_args = 3,
		.arg2type = ARG_LEN,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #205
	    */
	{
		.name = "ni_syscall (set_thread_area)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #206
	   SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp) */
	{
		.name = "io_setup",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #207
	   SYSCALL_DEFINE1(io_destroy, aio_context_t, ctx) */
	{
		.name = "io_destroy",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #208
	   SYSCALL_DEFINE5(io_getevents, aio_context_t, ctx_id,
                long, min_nr,
                long, nr,
                struct io_event __user *, events,
                struct timespec __user *, timeout) */
	{
		.name = "io_getevents",
		.num_args = 5,
		.arg4type = ARG_ADDRESS,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #209
	   SYSCALL_DEFINE3(io_submit, aio_context_t, ctx_id, long, nr,
                 struct iocb __user * __user *, iocbpp) */
	{
		.name = "io_submit",
		.num_args = 3,
		.arg2type = ARG_LEN,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #210
	   SYSCALL_DEFINE3(io_cancel, aio_context_t, ctx_id, struct iocb __user *, iocb,
                 struct io_event __user *, result) */
	{
		.name = "io_cancel",
		.num_args = 3,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #211
	    */
	{
		.name = "ni_syscall (get_thread_area)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #212
	   SYSCALL_DEFINE(lookup_dcookie)(u64 cookie64, char __user * buf, size_t len) */
	{
		.name = "lookup_dcookie",
		.num_args = 3,
		.flags = CAPABILITY_CHECK,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #213
	   SYSCALL_DEFINE1(epoll_create, int, size) */
	{
		.name = "epoll_create",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #214
	    */
	{
		.name = "ni_syscall (epoll_ctl_old)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #215
	    */
	{
		.name = "ni_syscall (epoll_wait_old)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #216
	   SYSCALL_DEFINE5(remap_file_pages, unsigned long, start, unsigned long, size,
                 unsigned long, prot, unsigned long, pgoff, unsigned long, flags) */
	{
		.name = "remap_file_pages",
		.num_args = 5,
	},
	/*-----------------------------------------------------------------------------------------------
	  #217
	   SYSCALL_DEFINE3(getdents64, unsigned int, fd,
                 struct linux_dirent64 __user *, dirent, unsigned int, count) */
	{
		.name = "getdents64",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #218
	   SYSCALL_DEFINE1(set_tid_address, int __user *, tidptr) */
	{
		.name = "set_tid_address",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #219
	   SYSCALL_DEFINE0(restart_syscall) */
	{
		.name = "restart_syscall",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #220
	   SYSCALL_DEFINE4(semtimedop, int, semid, struct sembuf __user *, tsops,
                 unsigned, nsops, const struct timespec __user *, timeout) */
	{
		.name = "semtimedop",
		.num_args = 4,
		.arg2type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #221
	   SYSCALL_DEFINE(fadvise64)(int fd, loff_t offset, size_t len, int advice) */
	{
		.name = "fadvise64",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #222
	   SYSCALL_DEFINE3(timer_create, const clockid_t, which_clock,
                struct sigevent __user *, timer_event_spec,
                timer_t __user *, created_timer_id) */
	{
		.name = "timer_create",
		.num_args = 3,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #223
	   SYSCALL_DEFINE4(timer_settime, timer_t, timer_id, int, flags,
                const struct itimerspec __user *, new_setting,
                struct itimerspec __user *, old_setting) */
	{
		.name = "timer_settime",
		.num_args = 4,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #224
	   SYSCALL_DEFINE2(timer_gettime, timer_t, timer_id, struct itimerspec __user *, setting) */
	{
		.name = "timer_gettime",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #225
	   SYSCALL_DEFINE1(timer_getoverrun, timer_t, timer_id) */
	{
		.name = "timer_getoverrun",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #226
	   SYSCALL_DEFINE1(timer_delete, timer_t, timer_id) */
	{
		.name = "timer_delete",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #227
	   SYSCALL_DEFINE2(clock_settime, const clockid_t, which_clock, const struct timespec __user *, tp) */
	{
		.name = "clock_settime",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #228
	   SYSCALL_DEFINE2(clock_gettime, const clockid_t, which_clock, struct timespec __user *,tp) */
	{
		.name = "clock_gettime",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #229
	   SYSCALL_DEFINE2(clock_getres, const clockid_t, which_clock, struct timespec __user *, tp) */
	{
		.name = "clock_getres",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #230
	   SYSCALL_DEFINE4(clock_nanosleep, const clockid_t, which_clock, int, flags,
                const struct timespec __user *, rqtp,
                struct timespec __user *, rmtp) */
	{
		.name = "clock_nanosleep",
		.num_args = 4,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #231
	   SYSCALL_DEFINE1(exit_group, int, error_code) */
	{
		.name = "exit_group",
		.num_args = 1,
		.flags = AVOID_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #232
	   SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events, int, maxevents, int, timeout) */
	{
		.name = "epoll_wait",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #233
	   SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event __user *, event) */
	{
		.name = "epoll_ctl",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg3type = ARG_FD,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #234
	   SYSCALL_DEFINE3(tgkill, pid_t, tgid, pid_t, pid, int, sig) */
	{
		.name = "tgkill",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #235
	   SYSCALL_DEFINE2(utimes, char __user *, filename, struct timeval __user *, utimes) */
	{
		.name = "utimes",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #236
	    */
	{
		.name = "ni_syscall (vserver)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},
	/*-----------------------------------------------------------------------------------------------
	  #237
	   SYSCALL_DEFINE6(mbind, unsigned long, start, unsigned long, len,
                unsigned long, mode, unsigned long __user *, nmask,
                unsigned long, maxnode, unsigned, flags) */
	{
		.name = "mbind",
		.num_args = 6,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #238
	   SYSCALL_DEFINE3(set_mempolicy, int, mode, unsigned long __user *, nmask, unsigned long, maxnode) */
	{
		.name = "set_mempolicy",
		.num_args = 3,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #239
	   SYSCALL_DEFINE5(get_mempolicy, int __user *, policy,
                unsigned long __user *, nmask, unsigned long, maxnode,
                unsigned long, addr, unsigned long, flags) */
	{
		.name = "get_mempolicy",
		.num_args = 5,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #240
	   SYSCALL_DEFINE4(mq_open, const char __user *, u_name, int, oflag, mode_t, mode, struct mq_attr __user *, u_attr) */
	{
		.name = "mq_open",
		.num_args = 4,
		.arg1type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #241
	   SYSCALL_DEFINE1(mq_unlink, const char __user *, u_name) */
	{
		.name = "mq_unlink",
		.num_args = 1,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #242
	   SYSCALL_DEFINE5(mq_timedsend, mqd_t, mqdes, const char __user *, u_msg_ptr,
                size_t, msg_len, unsigned int, msg_prio,
                const struct timespec __user *, u_abs_timeout) */
	{
		.name = "mq_timedsend",
		.num_args = 5,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #243
	   SYSCALL_DEFINE5(mq_timedreceive, mqd_t, mqdes, char __user *, u_msg_ptr,
                size_t, msg_len, unsigned int __user *, u_msg_prio,
                const struct timespec __user *, u_abs_timeout) */
	{
		.name = "mq_timedreceive",
		.num_args = 5,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
		.arg4type = ARG_ADDRESS,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #244
	   SYSCALL_DEFINE2(mq_notify, mqd_t, mqdes, const struct sigevent __user *, u_notification) */
	{
		.name = "mq_notify",
		.num_args = 2,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #245
	   SYSCALL_DEFINE3(mq_getsetattr, mqd_t, mqdes,
                const struct mq_attr __user *, u_mqstat,
                struct mq_attr __user *, u_omqstat) */
	{
		.name = "mq_getsetattr",
		.num_args = 3,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #246
	   SYSCALL_DEFINE4(kexec_load, unsigned long, entry, unsigned long, nr_segments,
		struct kexec_segment __user *, segments, unsigned long, flags) */
	{
		.name = "kexec_load",
		.num_args = 4,
		.flags = CAPABILITY_CHECK,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #247
	   SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
		infop, int, options, struct rusage __user *, ru) */
	{
		.name = "waitid",
		.num_args = 5,
		.arg3type = ARG_ADDRESS,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #248
	   SYSCALL_DEFINE5(add_key, const char __user *, _type,
                const char __user *, _description,
                const void __user *, _payload,
                size_t, plen,
                key_serial_t, ringid) */
	{
		.name = "add_key",
		.num_args = 5,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #249
	   SYSCALL_DEFINE4(request_key, const char __user *, _type,
                const char __user *, _description,
                const char __user *, _callout_info,
                key_serial_t, destringid) */
	{
		.name = "request_key",
		.num_args = 4,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #250
	   SYSCALL_DEFINE5(keyctl, int, option, unsigned long, arg2, unsigned long, arg3,
                unsigned long, arg4, unsigned long, arg5) */
	{
		.name = "keyctl",
		.num_args = 5,
	},
	/*-----------------------------------------------------------------------------------------------
	  #251
	   SYSCALL_DEFINE3(ioprio_set, int, which, int, who, int, ioprio) */
	{
		.name = "ioprio_set",
		.num_args = 3,
	},
	/*-----------------------------------------------------------------------------------------------
	  #252
	   SYSCALL_DEFINE2(ioprio_get, int, which, int, who) */
	{
		.name = "ioprio_get",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #253
	   SYSCALL_DEFINE0(inotify_init) */
	{
		.name = "inotify_init",
		.num_args = 0,
	},
	/*-----------------------------------------------------------------------------------------------
	  #254
	   SYSCALL_DEFINE3(inotify_add_watch, int, fd, const char __user *, pathname, u32, mask) */
	{
		.name = "inotify_add_watch",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #255
	   SYSCALL_DEFINE2(inotify_rm_watch, int, fd, __s32, wd) */
	{
		.name = "inotify_rm_watch",
		.num_args = 2,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #256
	   SYSCALL_DEFINE4(migrate_pages, pid_t, pid, unsigned long, maxnode,
                 const unsigned long __user *, old_nodes,
                 const unsigned long __user *, new_nodes) */
	{
		.name = "migrate_pages",
		.num_args = 4,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #257
	   SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, int, mode) */
	{
		.name = "openat",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #258
	   SYSCALL_DEFINE3(mkdirat, int, dfd, const char __user *, pathname, int, mode) */
	{
		.name = "mkdirat",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #259
	   SYSCALL_DEFINE4(mknodat, int, dfd, const char __user *, filename, int, mode, unsigned, dev) */
	{
		.name = "mknodat",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #260
	   SYSCALL_DEFINE5(fchownat, int, dfd, const char __user *, filename, uid_t, user,
                gid_t, group, int, flag) */
	{
		.name = "fchownat",
		.num_args = 5,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #261
	   SYSCALL_DEFINE3(futimesat, int, dfd, const char __user *, filename,
                 struct timeval __user *, utimes) */
	{
		.name = "futimesat",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #262
	   SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,
                struct stat64 __user *, statbuf, int, flag) */
	{
		.name = "fstatati64",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #263
	   SYSCALL_DEFINE3(unlinkat, int, dfd, const char __user *, pathname, int, flag) */
	{
		.name = "unlinkat",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #264
	   SYSCALL_DEFINE4(renameat, int, olddfd, const char __user *, oldname,
                 int, newdfd, const char __user *, newname) */
	{
		.name = "renameat",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_FD,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #265
	   SYSCALL_DEFINE5(linkat, int, olddfd, const char __user *, oldname,
                 int, newdfd, const char __user *, newname, int, flags) */
	{
		.name = "linkat",
		.num_args = 5,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_FD,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #266
	   SYSCALL_DEFINE3(symlinkat, const char __user *, oldname,
                 int, newdfd, const char __user *, newname) */
	{
		.name = "symlinkat",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_FD,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #267
	   SYSCALL_DEFINE4(readlinkat, int, dfd, const char __user *, pathname,
                 char __user *, buf, int, bufsiz) */
	{
		.name = "readlinkat",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #268
	   SYSCALL_DEFINE3(fchmodat, int, dfd, const char __user *, filename, mode_t, mode) */
	{
		.name = "fchmodat",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #269
	   SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode) */
	{
		.name = "faccessat",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #270
	   SYSCALL_DEFINE6(pselect6, int, n, fd_set __user *, inp, fd_set __user *, outp,
                fd_set __user *, exp, struct timespec __user *, tsp,
                void __user *, sig) */
	{
		.name = "pselect6",
		.num_args = 6,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
		.arg5type = ARG_ADDRESS,
		.arg6type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #271
	   SYSCALL_DEFINE5(ppoll, struct pollfd __user *, ufds, unsigned int, nfds,
                 struct timespec __user *, tsp, const sigset_t __user *, sigmask, size_t, sigsetsize)  */
	{
		.name = "ppoll",
		.num_args = 5,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #272
	   SYSCALL_DEFINE1(unshare, unsigned long, unshare_flags) */
	{
		.name = "unshare",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #273
	   SYSCALL_DEFINE2(set_robust_list, struct robust_list_head __user *, head, size_t, len) */
	{
		.name = "set_robust_list",
		.num_args = 2,
		.sanitise = sanitise_set_robust_list,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #274
	   SYSCALL_DEFINE3(get_robust_list, int, pid,
                struct robust_list_head __user * __user *, head_ptr,
                size_t __user *, len_ptr) */
	{
		.name = "get_robust_list",
		.num_args = 3,
		.arg1type = ARG_ADDRESS,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #275
	   SYSCALL_DEFINE6(splice, int, fd_in, loff_t __user *, off_in,
                int, fd_out, loff_t __user *, off_out,
                size_t, len, unsigned int, flags) */
	{
		.name = "splice",
		.num_args = 6,
		.sanitise = sanitise_splice,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_FD,
		.arg4type = ARG_ADDRESS,
		.arg5type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #276
	   SYSCALL_DEFINE4(tee, int, fdin, int, fdout, size_t, len, unsigned int, flags) */
	{
		.name = "tee",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_FD,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #277
	   SYSCALL_DEFINE(sync_file_range)(int fd, loff_t offset, loff_t nbytes, unsigned int flags) */
	{
		.name = "sync_file_range",
		.num_args = 4,
		.sanitise = sanitise_sync_file_range,
		.arg1type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #278
	   SYSCALL_DEFINE4(vmsplice, int, fd, const struct iovec __user *, iov,
                 unsigned long, nr_segs, unsigned int, flags) */
	{
		.name = "vmsplice",
		.num_args = 4,
		.sanitise = sanitise_vmsplice,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #279
	   SYSCALL_DEFINE6(move_pages, pid_t, pid, unsigned long, nr_pages,
                const void __user * __user *, pages,
                const int __user *, nodes,
                int __user *, status, int, flags) */
	{
		.name = "move_pages",
		.num_args = 6,
		.arg1type = ARG_LEN,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #280
	   SYSCALL_DEFINE4(utimensat, int, dfd, const char __user *, filename,
                 struct timespec __user *, utimes, int, flags) */
	{
		.name = "utimensat",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #281
	   SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events,
                 int, maxevents, int, timeout) */
	{
		.name = "epoll_pwait",
		.num_args = 6,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #282
	   SYSCALL_DEFINE3(signalfd, int, ufd, sigset_t __user *, user_mask, size_t, sizemask) */
	{
		.name = "signalfd",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #283
	   SYSCALL_DEFINE2(timerfd_create, int, clockid, int, flags) */
	{
		.name = "timerfd_create",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #284
	   SYSCALL_DEFINE1(eventfd, unsigned int, count) */
	{
		.name = "eventfd",
		.num_args = 1,
		.arg2type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #285
	   SYSCALL_DEFINE(fallocate)(int fd, int mode, loff_t offset, loff_t len) */
	{
		.name = "fallocate",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg4type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #286
	   SYSCALL_DEFINE4(timerfd_settime, int, ufd, int, flags,
                 const struct itimerspec __user *, utmr,
                 struct itimerspec __user *, otmr) */
	{
		.name = "timerfd_settime",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #287
	   SYSCALL_DEFINE2(timerfd_gettime, int, ufd, struct itimerspec __user *, otmr) */
	{
		.name = "timerfd_gettime",
		.num_args = 2,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #288
	   SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
                 int __user *, upeer_addrlen, int, flags) */
	{
		.name = "accept4",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #289
	   SYSCALL_DEFINE4(signalfd4, int, ufd, sigset_t __user *, user_mask,
                 size_t, sizemask, int, flags) */
	{
		.name = "signalfd4",
		.num_args = 4,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #290
	   SYSCALL_DEFINE2(eventfd2, unsigned int, count, int, flags) */
	{
		.name = "eventfd2",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #291
	   SYSCALL_DEFINE1(epoll_create1, int, flags) */
	{
		.name = "epoll_create1",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #292
	   SYSCALL_DEFINE3(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags) */
	{
		.name = "dup3",
		.num_args = 3,
		.arg1type = ARG_FD,
		.arg2type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #293
	   SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags) */
	{
		.name = "pipe2",
		.num_args = 2,
		.arg1type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #294
	   SYSCALL_DEFINE1(inotify_init1, int, flags) */
	{
		.name = "inotify_init1",
		.num_args = 1,
	},
	/*-----------------------------------------------------------------------------------------------
	  #295
	   SYSCALL_DEFINE5(preadv, unsigned long, fd, const struct iovec __user *, vec,
                 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h) */
	{
		.name = "preadv",
		.num_args = 5,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #296
	   SYSCALL_DEFINE5(pwritev, unsigned long, fd, const struct iovec __user *, vec,
                 unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h) */
	{
		.name = "pwritev",
		.num_args = 5,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
	},
	/*-----------------------------------------------------------------------------------------------
	  #297
	   SYSCALL_DEFINE4(rt_tgsigqueueinfo, pid_t, tgid, pid_t, pid, int, sig,
                 siginfo_t __user *, uinfo) */
	{
		.name = "rt_tgsigqueueinfo",
		.num_args = 4,
		.arg4type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #298
	   SYSCALL_DEFINE5(perf_event_open,
                 struct perf_event_attr __user *, attr_uptr,
                 pid_t, pid, int, cpu, int, group_fd, unsigned long, flags) */
	{
		.name = "perf_event_open",
		.num_args = 5,
		.arg1type = ARG_ADDRESS,
		.arg4type = ARG_FD,
	},
	/*-----------------------------------------------------------------------------------------------
	  #299
	   SYSCALL_DEFINE5(recvmmsg, int, fd, struct mmsghdr __user *, mmsg,
                 unsigned int, vlen, unsigned int, flags,
                 struct timespec __user *, timeout) */
	{
		.name = "recvmmsg",
		.num_args = 5,
		.arg1type = ARG_FD,
		.arg2type = ARG_ADDRESS,
		.arg3type = ARG_LEN,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #300
	   SYSCALL_DEFINE2(fanotify_init, unsigned int, flags, unsigned int, event_f_flags) */
	{
		.name = "fanotify_init",
		.num_args = 2,
	},
	/*-----------------------------------------------------------------------------------------------
	  #301
	   SYSCALL_DEFINE(fanotify_mark)(int fanotify_fd, unsigned int flags,
		__u64 mask, int dfd, const char  __user * pathname) */
	{
		.name = "fanotify_mark",
		.num_args = 5,
		.arg1type = ARG_FD,
		.arg4type = ARG_FD,
		.arg5type = ARG_ADDRESS,
	},
	/*-----------------------------------------------------------------------------------------------
	  #302
	   SYSCALL_DEFINE4(prlimit64, pid_t, pid, unsigned int, resource,
                 const struct rlimit64 __user *, new_rlim,
                 struct rlimit64 __user *, old_rlim) */
	{
		.name = "prlimit64",
		.num_args = 4,
		.arg3type = ARG_ADDRESS,
		.arg4type = ARG_ADDRESS,
	},
};
#endif	/* _SYSCALLS_x86_64_H */
