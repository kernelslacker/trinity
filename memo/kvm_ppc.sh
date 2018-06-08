
wget https://download.qemu.org/qemu-2.11.1.tar.xz
tar xf qemu-2.11.1.tar.xz 
cd qemu-2.11.1/
sed 's,H_CPU_BEHAV_FAVOUR_SECURITY,getenv("BYPASS_SECURITY") ? 0 : &,' -i hw/ppc/spapr_hcall.c

./configure --target-list=ppc64-softmmu
make -j$(nproc)

cd pc-bios/

unset BYPASS_SECURITY
../ppc64-softmmu/qemu-system-ppc64 \
  -M pseries -cpu power8 \
  -nodefaults -nographic -serial stdio \
  -append loglevel=8 \
  -kernel $KERNEL


export BYPASS_SECURITY=1
../ppc64-softmmu/qemu-system-ppc64 \
  -M pseries -cpu power8 \
  -nodefaults -nographic -serial stdio \
  -append loglevel=8 \
  -kernel $KERNEL
