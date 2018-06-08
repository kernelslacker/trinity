1. create memory device xml (filename: memdevice.xml)

<memory model='dimm'>
<target>
<size unit='KiB'>131072</size>
<node>0</node>
</target>
</memory>

2. hotplug memory
[~]# virsh attach-device rhel7.2 memdevice.xml
Device attached successfully
