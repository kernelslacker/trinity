# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

###### download kernek packages
wget_kernel_srpm(){
	wget http://download.lab.bos.redhat.com/brewroot/packages/kernel/3.10.0/327.el7/src/kernel-3.10.0-327.el7.src.rpm
	wget http://download.lab.bos.redhat.com/brewroot/packages/kernel/3.10.0/327.el7/x86_64/kernel-devel-3.10.0-327.el7.x86_64.rpm
}

###### Install kpatch-katch packages
RPM_BUILD=/root/rpmbuild/BUILD/

# For kernel source code
prepare_kernel_source(){
	NAME=kernel
	VERSION_RELEASE=3.10.0-327.el7
	ARCH=x86_64
	KERNEL_SRC=$RPM_BUILD/$NVR/linux-3.10.0-327.el7.${ARCH}/
	KERNEL_SRPM=kernel-3.10.0-327.el7.src.rpm
	KERNEL_SPEC=/root/rpmbuild/SPECS/kernel.spec

	[ ! -f $KERNEL_SRPM ] && wget http://download.lab.bos.redhat.com/brewroot/packages/kpatch-patch/7.2/3.el7/src/$KERNEL_SRPM
	yum -y install kernel kernel-devel kernel-debuginfo
	rpm -ivh $KERNEL_SRPM
	yum-builddep -y $KERNEL_SPEC

	! grep "with_gcov 1" &&
	sed -i "/{with_gcov/i\
	%define with_gcov 1" $KERNEL_SPEC
	rpmbuild -bp $KERNEL_SPEC
	cd $KERNEL_SRC
	cp configs/kernel-3.10.0-x86_64.config  .config
	make oldnoconfig
	make prepare modules_prepare
}

# For kpatch source code
prepare_kpatch_source(){
	KPP_SRPM=kpatch-patch-7.2-3.el7.src.rpm 
	KPP_SPEC=/root/rpmbuild/SPECS/kpatch-patch.spec 

	[ ! -f $KPP_SRPM ] && wget http://download.lab.bos.redhat.com/brewroot/packages/kpatch-patch/7.2/3.el7/src/$KPP_SRPM
	rpm -ivh $KPP_SRPM
	sed -i 's/306.0.1/327/g' $KPP_SPEC
	yum-builddep -y $KPP_SPEC
	rpmbuild -bp $KPP_SPEC
	tar -zxvf v0.2.2.tar.gz 
	cd $SOURCES/kpatch-0.2.2
	sed -i "1iGCOV_PROFILE := y" kmod/Makefile
	make KPATCH_BUILD=/root/rpmbuild/BUILD/kernel-3.10.0-327.el7/linux-3.10.0-327.el7.x86_64/  V=1

}

# cleanup kernel source for kpatch.ko
clean_kernel_source(){
	cd $KERNEL_SRC
	make mrproper
}

# Build source of kpatch.ko in kmod

build_kpatch_ko(){


}

# Build kpatch-patch,ko
build_kpatch_patch_ko(){
	./kpatch-build -s /root/rpmbuild/BUILD/kernel-3.10.0-327.el7/linux-3.10.0-327.el7.x86_64/  -c /root/rpmbuild/BUILD/kernel-3.10.0-327.el7/linux-3.10.0-327.el7.x86_64/.config -t vmlinux --skip-gcc-check -v /root/rpmbuild/BUILD/kernel-3.10.0-327.el7/linux-3.10.0-327.el7.x86_64/vmlinux /root/rpmbuild/SOURCES/cmdline.patch  
  #./kpatch-build -s /root/rpmbuild/BUILD/kernel-3.10.0-327.el7/linux-3.10.0-327.el7.x86_64/  -c /root/rpmbuild/BUILD/kernel-3.10.0-327.el7/linux-3.10.0-327.el7.x86_64/.config -t vmlinux --skip-gcc-check -v /usr/lib/debug/usr/lib/modules/3.10.0-327.el7.x86_64/vmlinux /root/rpmbuild/SOURCES/cmdline.patch  
}
#sed -i '1i\GCOV_PROFILE := y'  ./cpu/Makefile  ./events/Makefile  ./irq/Makefile ./time/Makefille ./trace/Makefile
