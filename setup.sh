#!/bin/bash
# Runtime config for the fuzz box: debugfs/kcov perms for trinity, plus
# an iSCSI target with a ramdisk LUN so the login + SCSI CDB paths are
# reachable from any local TCP connect to 127.0.0.1:3260.

set -euo pipefail

# Write a value to a sysfs/configfs attribute, but only if it isn't
# already set to that value. This keeps the script idempotent across
# re-runs (re-writing an already-enabled attribute typically EINVALs).
write_if_changed() {
    local path=$1
    local value=$2
    if [ -r "$path" ] && [ "$(cat "$path")" = "$value" ]; then
        return 0
    fi
    echo "$value" > "$path"
}

setup_iscsi() {
    modprobe iscsi_target_mod 2>/dev/null || true

    if [ ! -d /sys/kernel/config/target ]; then
        echo "setup_iscsi: /sys/kernel/config/target not present (CONFIG_TARGET_CORE off?), skipping"
        return 0
    fi

    local TGT=/sys/kernel/config/target/iscsi/iqn.2026-05.fuzz:t/tpgt_1
    mkdir -p "$TGT/np/127.0.0.1:3260"
    write_if_changed "$TGT/attrib/authentication" 0
    write_if_changed "$TGT/attrib/demo_mode_write_protect" 0
    write_if_changed "$TGT/attrib/generate_node_acls" 1
    write_if_changed "$TGT/attrib/cache_dynamic_acls" 1

    local RD=/sys/kernel/config/target/core/rd_mcp_0/ram0
    mkdir -p "$RD"
    write_if_changed "$RD/control" 16384
    write_if_changed "$RD/enable" 1

    mkdir -p "$TGT/lun/lun_0"
    ln -sfn "$RD" "$TGT/lun/lun_0/storage"

    write_if_changed "$TGT/enable" 1
}

chmod 777 /sys/kernel/debug/
chmod 666 /sys/kernel/debug/kcov

if ! mountpoint -q /sys/kernel/config; then
    mount -t configfs none /sys/kernel/config
fi

setup_iscsi
