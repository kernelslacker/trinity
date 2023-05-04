#!/bin/sh
#
# Run from with a kernel source tree.
# Update the hashes after adding support to Trinity.

# $1 = filename $2 = hash $3 = pattern
#
check()
{
  if [ ! -f $1 ]; then
    echo "$1 is no longer present"
  else
    NEW=$(grep "[0123456789]" $1 | grep "$3" | sha1sum | awk '{ print $1 }')
    if [ "$NEW" != "$2" ]; then
      echo "$1 $3 changed. ($NEW)"
      YEAR=$(date +%Y -d "1 month ago")
      git annotate $1 | grep $YEAR | grep "$3"
      echo
    fi
  fi
}


# new syscalls
# Note: Commented out checks are likely out of date, but they're for architectures
#  I don't have time to care about. Step up and contribute if you care.
#
check include/uapi/asm-generic/unistd.h    11c46e9ce6393e7c8a17577c6128b78684395016 sys_
#check arch/alpha/include/uapi/asm/unistd.h 51fa669a21d8f26a0c9de8280a3cfd9c257a0d28 _NR_
#check arch/arm/include/uapi/asm/unistd.h   7c601d436a3ebbe05a9b6813c0ffcf8eedaf101b SYSCALL
check arch/x86/entry/syscalls/syscall_32.tbl     a2232d6f101274762e9fab44dabb07d86a3719ee sys_
check arch/x86/entry/syscalls/syscall_64.tbl     60d2554683c0a8638f6a874f2ff74ede49435564 sys_
check arch/x86/entry/syscalls/syscall_64.tbl     da39a3ee5e6b4b0d3255bfef95601890afd80709 stub_
#check arch/ia64/kernel/entry.S             e6a21b973609ec08cd19b0b8c67830f8570e93ef "data8\ sys_"
#check arch/mips/kernel/scall32-o32.S       b1501a675dd998fe2af68ae43cd797cf18d67b33 sys_
#check arch/parisc/kernel/syscall_table.S   25d14db60070cb29499a9a16c975c7984f124f74 ENTRY_
#check arch/powerpc/include/asm/systbl.h    8d11bade2537d955bd694ae30b2e986c680bba54 SYS
#check arch/s390/include/uapi/asm/unistd.h  0f5821c2413561ec2581631cc60dc189700d7494 __NR_
#check arch/sh/kernel/syscalls_64.S         aa1a2e958b9e1c6129bc9b488148ecf5c4bc2a7e sys_
#check arch/sparc/kernel/systbls_32.S       98100f9dedc82d82ac18a33fd68dc7e4852ffcb8 sys_

# new setsockopt values
check include/uapi/asm-generic/socket.h	e32fa013c2d914164d2a70ecabb3f23563b59de8 SO_
check include/uapi/linux/tcp.h          149a6ee4bb5bb81fd8d44923c5846f85b7130d5e \#define\ TCP_
check include/uapi/linux/in.h           0116e6878df350e74ec730fd9f455efb95e510c8 \#define\ IP_

# Check for new packet families
check include/linux/socket.h 52069f49a4646e9692c6b3186172fbd1fa681dcf SOL_
check include/linux/socket.h 02ead19934fd61e127ccfb46445afea2caed4ece AF_

# MSG_ flags
check include/linux/socket.h 94a5669653d7098b8c4a4391aeabb593b5940486 \ MSG_

# new netlink protos
check include/uapi/linux/netlink.h 97cad03cf941de83421ddcfc5178af06a05cea50 "#define\ NETLINK_"

# new O_ flags
check include/uapi/asm-generic/fcntl.h 256ab30dfec0915704a13755ba645c448a65220c O_

# new F_ flags
check include/uapi/asm-generic/fcntl.h 98cf236ce61466e272727683eba11493d41c6b27 F_

# new splice flags
check include/linux/splice.h fb753f99bf38f7c041427c442f199aa2049fa329 SPLICE_F_

# new madvise flags
check include/uapi/asm-generic/mman-common.h fdfd95258ab07c7377584912890dd286beae4f9f MADV_

# new mremap flags
check include/uapi/linux/mman.h 3465560bc9439e3edabb652ce31d6a0d0e1aa400 MREMAP_

# new IPPROTO's
check include/uapi/linux/in.h  80799106aba80b40af5416f0d5cc47dea8b02225 \ \ IPPROTO_

# Check for new errnos
check include/uapi/asm-generic/errno.h	da39a3ee5e6b4b0d3255bfef95601890afd80709 134

# new prctls
check include/uapi/linux/prctl.h 2b3c44c13ff4df4b9062898f6bb5a3323283ab7d PR_

# new fallocate flags
check include/uapi/linux/falloc.h c46220c8e3bd5e237d02880e0d2ac16e88a6d7c0 FALLOC_
# new fallocate flags
check include/uapi/linux/falloc.h c46220c8e3bd5e237d02880e0d2ac16e88a6d7c0 FL_


# special: we want to know when MPOL_MF_VALID changes.
NEW=$(grep -C2 MPOL_MF_VALID include/uapi/linux/mempolicy.h | sha1sum | awk '{ print $1 }')
if [ "$NEW" != "1cf1845ede2e209d84ef0ab0dce6b523a70bb3ca" ]; then
  echo "MPOL_MF_VALID changed. ($NEW)"
fi

