#!/usr/bin/env bash
gdb-multiarch -ex 'target remote 127.0.0.1:1234' -ex "b *0x8025c600" -ex "disable 1" extracted_kernel.elf 
