#!/bin/bash
set -Eeuo pipefail

# TODO: Make this script support mounting different files.

# Example sequence of copying the vmlinux file from a mounted LVM partition.
# ls -l /dev/mapper/
# sudo kpartx -av /dev/mapper/vg-ubuntu--20--04
# sudo mount -o ro /dev/mapper/vg-ubuntu--20--04-part5 /mnt
# cp /mnt/usr/lib/debug/boot/vmlinux-5.15.0-67-generic  ~/
# sudo umount /mnt
