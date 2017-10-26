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
check include/uapi/asm-generic/unistd.h    e1f35cf48a7ae6a07949ad3e875cb7937c2c6cf0 sys_
#check arch/alpha/include/uapi/asm/unistd.h 51fa669a21d8f26a0c9de8280a3cfd9c257a0d28 _NR_
#check arch/arm/include/uapi/asm/unistd.h   7c601d436a3ebbe05a9b6813c0ffcf8eedaf101b SYSCALL
check arch/x86/entry/syscalls/syscall_32.tbl     1b9ed3050a88b2d84bdb7dbcfe2ab23b8234bee8 sys_
check arch/x86/entry/syscalls/syscall_64.tbl     d52841da5ee801bfd7277fccf5b76d30566ace1a sys_
check arch/x86/entry/syscalls/syscall_64.tbl     da39a3ee5e6b4b0d3255bfef95601890afd80709 stub_
#check arch/ia64/kernel/entry.S             e6a21b973609ec08cd19b0b8c67830f8570e93ef "data8\ sys_"
#check arch/mips/kernel/scall32-o32.S       b1501a675dd998fe2af68ae43cd797cf18d67b33 sys_
#check arch/parisc/kernel/syscall_table.S   25d14db60070cb29499a9a16c975c7984f124f74 ENTRY_
#check arch/powerpc/include/asm/systbl.h    8d11bade2537d955bd694ae30b2e986c680bba54 SYS
#check arch/s390/include/uapi/asm/unistd.h  0f5821c2413561ec2581631cc60dc189700d7494 __NR_
#check arch/sh/kernel/syscalls_64.S         aa1a2e958b9e1c6129bc9b488148ecf5c4bc2a7e sys_
#check arch/sparc/kernel/systbls_32.S       98100f9dedc82d82ac18a33fd68dc7e4852ffcb8 sys_

# new setsockopt values
check include/uapi/asm-generic/socket.h	848bfd5d1700324c48e1216da2abdda7515b230b SO_
check include/uapi/linux/tcp.h          ed5bbfa500b64aad4d742b2eed0d35ce22ab36b8 \#define\ TCP_
check include/uapi/linux/in.h           0116e6878df350e74ec730fd9f455efb95e510c8 \#define\ IP_

# Check for new packet families
check include/linux/socket.h 17b4779bb45a76825972f41d1fa1f8d2b908a21b SOL_
check include/linux/socket.h 80c34154051e712d03e81577d494efe8f09139a8 AF_

# MSG_ flags
check include/linux/socket.h 91b84d05363d32e88375567a9bb7a4e16d738ea8 \ MSG_

# new netlink protos
check include/uapi/linux/netlink.h 1f391f35d0443f432871cbb366d1150973eb2bcb "#define\ NETLINK_"

# new O_ flags
check include/uapi/asm-generic/fcntl.h 256ab30dfec0915704a13755ba645c448a65220c O_

# new F_ flags
check include/uapi/asm-generic/fcntl.h 98cf236ce61466e272727683eba11493d41c6b27 F_

# new splice flags
check include/linux/splice.h fb753f99bf38f7c041427c442f199aa2049fa329 SPLICE_F_

# new madvise flags
check include/uapi/asm-generic/mman-common.h c6e990af02fd65c13c5e25c2d4e7dffa32724b23 MADV_

# new mremap flags
check include/uapi/linux/mman.h 556bcea4a4581a03a600c2d383c462840f1c0e6c MREMAP_

# new IPPROTO's
check include/uapi/linux/in.h  80799106aba80b40af5416f0d5cc47dea8b02225 \ \ IPPROTO_

# Check for new errnos
check include/uapi/asm-generic/errno.h	da39a3ee5e6b4b0d3255bfef95601890afd80709 134

# new prctls
check include/uapi/linux/prctl.h 54a153856a9136a9bad87deed2475f8eca2ebbbb PR_

# new fallocate flags
check include/uapi/linux/falloc.h c46220c8e3bd5e237d02880e0d2ac16e88a6d7c0 FALLOC_
# new fallocate flags
check include/uapi/linux/falloc.h c46220c8e3bd5e237d02880e0d2ac16e88a6d7c0 FL_


# special: we want to know when MPOL_MF_VALID changes.
NEW=$(grep -C2 MPOL_MF_VALID include/uapi/linux/mempolicy.h | sha1sum | awk '{ print $1 }')
if [ "$NEW" != "1cf1845ede2e209d84ef0ab0dce6b523a70bb3ca" ]; then
  echo "MPOL_MF_VALID changed. ($NEW)"
fi

