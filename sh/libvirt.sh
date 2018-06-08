/usr/libexec/qemu-kvm -enable-kvm -m 1024 -nographic -drive file=./rhel-7.4.qcow2,if=virtio,index=0,format=qcow2
/usr/libexec/qemu-kvm -kernel /boot/vmlinuz-4.14.0-rc3+  -initrd /boot/initramfs-4.14.0-rc3+.img  --append 'console=ttyS0 ftrace=function'  -m 1024 -name rhel-7.4  -nographic
