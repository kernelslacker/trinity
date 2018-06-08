/usr/libexec/qemu-kvm  -m 512G,slots=256,maxmem=1024G  -net nic -net user -display none -serial stdio -no-reboot  -numa node,nodeid=0,cpus=0-1 -numa node,nodeid=1,cpus=2-3 -smp sockets=2,cores=2,threads=1  -enable-kvm  -hda /var/lib/libvirt/images/rhel-6.9.qcow2  -vnc 0.0.0.0:1 -monitor telnet:127.0.0.1:1234,server,nowait 

(qemu) object_add memory-backend-ram,id=mem1,size=512G
(qemu) device_add pc-dimm,id=dimm1,memdev=mem1
