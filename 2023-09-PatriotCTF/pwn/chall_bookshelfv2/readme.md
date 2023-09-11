# Bookshelfv2

![Image](../../images/pctf-bookshelfv2.png)

## Bookshelf

The initial version of the challenge is a fairly simple ROP challenge. It has some fun `mini puzzles` that you have to figure out before getting a pointer to `puts` and a stack override. The main idea is to use libc for gadgets and then ROP your way to the flag. The usual read/execve works well.

The [exploit for bookshelf v1](../chall_bookshelf/exploit.py) can be found is this repo, but I probably won't go into a writeup about that.

## Bookshelfv2

This variant is a bit different but starts the same. You have to use a buffer overflow in writing a book to overflow just enough to update the variable indicating whether you're and admin. 

This is possible because the code prepends `(AB): ` to the buffer allowing for us to write past the end with the `strcat`.

Once we've done that, we can access the admin only menu section. But we don't have a libc leak yet, so we need to get creative.

My solution was to do the following ROP with the gadgets available in the main binary:
```python
payload = b'A'*48
payload += p64(0x404200)   # rbp
payload += p64(GAD_POP_RDI)
payload += p64(0x404020)   # leak from puts from here 
payload += p64(0x4012ba)   # puts
payload += p64(0x41424344) # extra for pop rbp
payload += p64(0x401130)   # _start again
```

We place the address we want to leak (`puts` in the `plt`) into `rdi` and then jump to call `puts` with a `ret` right after it:
```asm
0x4012ba   call puts
0x4012bf   nop
0x4012c0   pop rbp
0x4012c1   ret
```

And then the final ret calls back to `_start` again. This way we have our leaked address and maintain execution control. The application starts all over again and we have a valid leak!

At this point we can calculate the base address of `libc`, effectively defeating ASLR yet again, and use the same ROP chain from the first challenge to pop a shell.

[Full exploit](./exploit.py)

## Summary

A great little challenge that allows us to use this technique of jumping back to `_start`.
