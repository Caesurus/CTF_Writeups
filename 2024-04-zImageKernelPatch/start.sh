#!/usr/bin/env bash
stty intr ^]    # to change the interrupt key from ^c to ^]
#qemu-system-arm -M vexpress-a9 -kernel zImage -drive file=rootfs.ext2,if=sd -append console=ttyAMA0,115200 root=/dev/mmcblk0 -serial stdio -net nic,model=lan9118 -net user
qemu-system-arm -M vexpress-a9 -kernel zImage_patched -drive file=rootfs.ext2,if=sd -nographic -append "console=ttyAMA0,115200 root=/dev/mmcblk0" -net nic,model=lan9118 -net user #-s -S
stty intr ^c    # revert back to ctrl-c
