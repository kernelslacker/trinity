#!/bin/bash
# Runtime config for the fuzz box: debugfs/kcov perms for trinity, plus
# an iSCSI target with a ramdisk LUN so the login + SCSI CDB paths are
# reachable from any local TCP connect to 127.0.0.1:3260.

setup_iscsi() {
    modprobe iscsi_target_mod 2>/dev/null

    if [ ! -d /sys/kernel/config/target ]; then
        echo "setup_iscsi: /sys/kernel/config/target not present (CONFIG_TARGET_CORE off?), skipping"
        return 0
    fi

    local TGT=/sys/kernel/config/target/iscsi/iqn.2026-05.fuzz:t/tpgt_1
    mkdir -p $TGT/np/127.0.0.1:3260
    echo 0 > $TGT/attrib/authentication
    echo 0 > $TGT/attrib/demo_mode_write_protect
    echo 1 > $TGT/attrib/generate_node_acls
    echo 1 > $TGT/attrib/cache_dynamic_acls

    local RD=/sys/kernel/config/target/core/rd_mcp_0/ram0
    mkdir -p $RD
    echo 16384 > $RD/control
    echo 1 > $RD/enable

    mkdir -p $TGT/lun/lun_0
    ln -s $RD $TGT/lun/lun_0/storage

    echo 1 > $TGT/enable
}

chmod 777 /sys/kernel/debug/
chmod 666 /sys/kernel/debug/kcov

mount -t configfs none /sys/kernel/config

setup_iscsi
