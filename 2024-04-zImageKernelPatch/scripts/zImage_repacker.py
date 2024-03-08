#!/usr/bin/env python3

import argparse
import gzip
import os
import sys

# Constants
VMLINUX_GZ = "vmlinux.gz"
VMLINUX_RECOMPRESSED_GZ = "vmlinux_recompressed.gz"
EXTRACTED_KERNEL = "extracted_kernel"
EXTRACTED_KERNEL_PATCHED = "extracted_kernel.patched"
ZIMAGE_PATCHED = "zImage_patched"
TRAILING_BYTES_LEN = 61-4
GZIP_HEADER = b'\x1f\x8b\x08\x00'

def hex_dump(data, length):
    offset = 0
    while offset < length:
        chunk = data[offset:offset+16]
        hex_values = ' '.join(f'{byte:02x}' for byte in chunk)
        ascii_values = ''.join(chr(byte) if 32 <= byte <= 127 else '.' for byte in chunk)
        print(f'{offset:08x}  {hex_values:<48}  |{ascii_values}|')
        offset += 16

def find_gzip_offset(file_path):
    with open(file_path, 'rb') as file:
        file_content = file.read()
    offset = file_content.find(GZIP_HEADER)
    if offset == -1:
        raise ValueError("GZIP header not found")
    return offset

def extract_kernel(zImage_path):
    print(f"[+] Extracting kernel from {zImage_path}")
    offset = find_gzip_offset(zImage_path)
    with open(zImage_path, 'rb') as zImage, open(VMLINUX_GZ, 'wb') as output:
        zImage.seek(offset)
        output.write(zImage.read()[:-TRAILING_BYTES_LEN])
    print(f"[+] Decompressing to {EXTRACTED_KERNEL}")
    with open(VMLINUX_GZ, 'rb') as f_in:
        with gzip.open(f_in, 'rb') as gz_in:
            with open(EXTRACTED_KERNEL, 'wb') as f_out:
                f_out.write(gz_in.read())

def compress_kernel(zImage_path):
    print(f"[+] Compressing kernel from {zImage_path}")
    offset = find_gzip_offset(zImage_path)
    
    with open(zImage_path, 'rb') as zImage:
        prepended_data = zImage.read(offset)
        zImage.seek(-TRAILING_BYTES_LEN, 2)
        trailing_data = zImage.read(TRAILING_BYTES_LEN)
        zImage.seek(0,0)
        zImage_data = zImage.read()

    print(f"[+] Compressing kernel from {EXTRACTED_KERNEL_PATCHED} > {VMLINUX_RECOMPRESSED_GZ}")
    ret = os.system(f"gzip -9 -c -n {EXTRACTED_KERNEL_PATCHED}> {VMLINUX_RECOMPRESSED_GZ}")
    if ret:
        raise Exception("gzip command failed")
    
    original_gz_size = (len(zImage_data) - offset - TRAILING_BYTES_LEN)
    with open(VMLINUX_RECOMPRESSED_GZ, 'rb') as gz_in:
        compressed_data = gz_in.read()
        if len(compressed_data) > original_gz_size:
            raise Exception(f"Compressed size is larger than allowed. {len(compressed_data)} > {original_gz_size}")
    
    print(f'Original gz size: {original_gz_size}, new size: {len(compressed_data)}')
    extracted_size_bytes =compressed_data[-4:]
    compressed_data = compressed_data[:-4]
    
    hex_dump(zImage_data[-TRAILING_BYTES_LEN:], TRAILING_BYTES_LEN)

    with open(ZIMAGE_PATCHED, 'wb') as patched:
        patched.write(prepended_data)
        patched.write(compressed_data)
        patched.write(b'\x00' * (original_gz_size - len(compressed_data)-4))
        patched.write(extracted_size_bytes)
        patched.write(trailing_data)
    print(f"[+] Kernel compressed and patched into {ZIMAGE_PATCHED}")

def main():
    parser = argparse.ArgumentParser(description="Kernel extractor and compressor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-x", "--extract", action="store_true", help="Extract the kernel")
    group.add_argument("-c", "--compress", action="store_true", help="Compress the kernel")
    parser.add_argument("-i", "--input", required=True, help="Path to zImage file", metavar="zImage_file")
    
    args = parser.parse_args()

    if args.extract:
        extract_kernel(args.input)
    elif args.compress:
        compress_kernel(args.input)

if __name__ == "__main__":
    main()
