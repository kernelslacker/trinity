#pragma once

#include <linux/kvm.h>

#ifndef KVMIO
#define KVMIO 0xAE
#endif
#ifndef KVM_GET_REG_LIST
struct kvm_reg_list {
        __u64 n; /* number of regs */
        __u64 reg[0];
};
#define KVM_GET_REG_LIST          _IOWR(KVMIO, 0xb0, struct kvm_reg_list)
#endif

#ifndef KVM_S390_UCAS_MAP
struct kvm_s390_ucas_mapping {
        __u64 user_addr;
        __u64 vcpu_addr;
        __u64 length;
};
#define KVM_S390_UCAS_MAP         _IOW(KVMIO, 0x50, struct kvm_s390_ucas_mapping)
#endif

#ifndef KVM_S390_UCAS_UNMAP
#define KVM_S390_UCAS_UNMAP       _IOW(KVMIO, 0x51, struct kvm_s390_ucas_mapping)
#endif

#ifndef KVM_S390_VCPU_FAULT
#define KVM_S390_VCPU_FAULT       _IOW(KVMIO, 0x52, unsigned long)
#endif

#ifndef KVM_XEN_HVM_CONFIG
struct kvm_xen_hvm_config {
	__u32 flags;
	__u32 msr;
	__u64 blob_addr_32;
	__u64 blob_addr_64;
	__u8 blob_size_32;
	__u8 blob_size_64;
	__u8 pad2[30];
};
#define KVM_XEN_HVM_CONFIG        _IOW(KVMIO,  0x7a, struct kvm_xen_hvm_config)
#endif

#ifndef KVM_PPC_GET_PVINFO
struct kvm_ppc_pvinfo {
	/* out */
	__u32 flags;
	__u32 hcall[4];
	__u8  pad[108];
};
#define KVM_PPC_GET_PVINFO        _IOW(KVMIO,  0xa1, struct kvm_ppc_pvinfo)
#endif

#ifndef KVM_SET_TSC_KHZ
#define KVM_SET_TSC_KHZ           _IO(KVMIO,  0xa2)
#endif

#ifndef KVM_GET_TSC_KHZ
#define KVM_GET_TSC_KHZ           _IO(KVMIO,  0xa3)
#endif

#ifndef KVM_GET_DEBUGREGS
struct kvm_debugregs {
	__u64 db[4];
	__u64 dr6;
	__u64 dr7;
	__u64 flags;
	__u64 reserved[9];
};
#define KVM_GET_DEBUGREGS         _IOR(KVMIO,  0xa1, struct kvm_debugregs)
#define KVM_SET_DEBUGREGS         _IOW(KVMIO,  0xa2, struct kvm_debugregs)
#endif

#ifndef KVM_ENABLE_CAP
struct kvm_enable_cap {
	/* in */
	__u32 cap;
	__u32 flags;
	__u64 args[4];
	__u8  pad[64];
};
#define KVM_ENABLE_CAP            _IOW(KVMIO,  0xa3, struct kvm_enable_cap)
#endif

#ifndef KVM_GET_XSAVE
struct kvm_xsave {
	__u32 region[1024];
};
#define KVM_GET_XSAVE             _IOR(KVMIO,  0xa4, struct kvm_xsave)
#define KVM_SET_XSAVE             _IOW(KVMIO,  0xa5, struct kvm_xsave)
#endif

#ifndef KVM_GET_XCRS
#define KVM_MAX_XCRS    16
struct kvm_xcr {
	__u32 xcr;
	__u32 reserved;
	__u64 value;
};

struct kvm_xcrs {
	__u32 nr_xcrs;
	__u32 flags;
	struct kvm_xcr xcrs[KVM_MAX_XCRS];
	__u64 padding[16];
};
#define KVM_GET_XCRS              _IOR(KVMIO,  0xa6, struct kvm_xcrs)
#define KVM_SET_XCRS              _IOW(KVMIO,  0xa7, struct kvm_xcrs)
#endif

#ifndef KVM_SIGNAL_MSI
struct kvm_msi {
        __u32 address_lo;
        __u32 address_hi;
        __u32 data;
        __u32 flags;
        __u32 devid;
        __u8  pad[12];
};
#define KVM_SIGNAL_MSI            _IOW(KVMIO,  0xa5, struct kvm_msi)
#endif

#ifndef KVM_DIRTY_TLB
struct kvm_dirty_tlb {
        __u64 bitmap;
        __u32 num_dirty;
};
#define KVM_DIRTY_TLB             _IOW(KVMIO,  0xaa, struct kvm_dirty_tlb)
#endif

#ifndef KVM_GET_ONE_REG
struct kvm_one_reg {
        __u64 id;
        __u64 addr;
};
#define KVM_GET_ONE_REG           _IOW(KVMIO,  0xab, struct kvm_one_reg)
#endif

#ifndef KVM_SET_ONE_REG
#define KVM_SET_ONE_REG           _IOW(KVMIO,  0xac, struct kvm_one_reg)
#endif

#ifndef KVM_KVMCLOCK_CTRL
#define KVM_KVMCLOCK_CTRL         _IO(KVMIO,   0xad)
#endif

#ifndef KVM_PPC_GET_SMMU_INFO
#define KVM_PPC_PAGE_SIZES_MAX_SZ	8

struct kvm_ppc_one_page_size {
	__u32 page_shift;	/* Page shift (or 0) */
	__u32 pte_enc;		/* Encoding in the HPTE (>>12) */
};

struct kvm_ppc_one_seg_page_size {
	__u32 page_shift;	/* Base page shift of segment (or 0) */
	__u32 slb_enc;		/* SLB encoding for BookS */
	struct kvm_ppc_one_page_size enc[KVM_PPC_PAGE_SIZES_MAX_SZ];
};

struct kvm_ppc_smmu_info {
	__u64 flags;
	__u32 slb_size;
	__u16 data_keys;
	__u16 instr_keys;
	struct kvm_ppc_one_seg_page_size sps[KVM_PPC_PAGE_SIZES_MAX_SZ];
};
#define KVM_PPC_GET_SMMU_INFO	  _IOR(KVMIO,  0xa6, struct kvm_ppc_smmu_info)
#endif

#ifndef KVM_PPC_ALLOCATE_HTAB
#define KVM_PPC_ALLOCATE_HTAB	  _IOWR(KVMIO, 0xa7, __u32)
#endif

#ifndef KVM_PPC_GET_HTAB_FD
struct kvm_get_htab_fd {
	__u64	flags;
	__u64	start_index;
	__u64	reserved[2];
};
#define KVM_PPC_GET_HTAB_FD	  _IOW(KVMIO,  0xaa, struct kvm_get_htab_fd)
#endif

