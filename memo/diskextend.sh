qemu-img resize ./rhel-7.4.qcow2 +10G
qemu-img info ./rhel-7.4.qcow2
fdisk /dev/vda; n; p; t; 4; w
vgextend rhel /dev/vda3
vgdisplay 
lvextend -L +9G /dev/mapper/rhel-root 
pvs
lsblk 
df -hl
xfs_growfs  /
