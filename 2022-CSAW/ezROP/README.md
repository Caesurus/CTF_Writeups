# CSAW ezROP challenge.

This year has been very busy with work and family life, so there haven't been a lot of CTFs I've been able to participate in. When CSAW started, I had a little bit of time and figured I'd try to maintain some exploit skills so that I don't totally lose touch with CTFs.

I'm a sucker for a good ROP challenge, so `ezROP` seemed like it shouldn't be too hard, and solvable within the time I had available.

Usually I try to take more time to explain the full process and try to provide a step-by-step guide, but it's a bit more than I have time for at the moment. So here is the summary account, with some extra explanations where I feel they might be beneficial. 

## Summary:

- Overflow buffer
- Bypass "protection mechanism"
- Leak libc address from GOT, loop execution to restart with libc base calculated
- Use libc to get more gadgets
- Use a gadget to clear r12, r13, r14, r15 so one gadget constraints are met 
- Use one-gadget to pop a shell
- Profit

### Bypass protection mechanism
The "protection" comes in the form of a check. The code is as follows:
```C
int check(char *s){
    char *ptr = s;
    while(*ptr!=0)
    {
        if(*ptr=='\n')
        {
            *ptr = 0; break;
        }
        if(isalpha(*ptr) || *ptr==' ')
            ptr++;
        else
        {
            puts("Hey Hacker! Welcome to CSAW'22!");
            exit(1);
        }
    }
    printf("Nice to meet you, %s! Welcome to CSAW'22!\n",s);
    return 1;
}
```
Here, if there is any character in the buffer that isn't isalpha(), or a space, we get booted out. 
Even though we already overwrote the return pointer, the call to `exit()` restricts us from using it. 
The "bypass" was simply to start the payload with a newline character. This stops the check, and allows us to build a ROP chain without the restrictions.

### ROP Gadgets

Since the binary is fairly small, there aren't a lot of gadgets available. And importantly, there is no `syscall, ret` gadget. So it became obvious that the goal was probably to use LIBC to get the necessary gadgets. 

### Leaking LIBC offsets
I reused some code that calls `puts`, and preloaded the necessary offsets to print out the libc address of `fclose` and `setvbuf`. Once I had those, we can use a libc database like https://libc.rip/ to identify the libc being used. One thing that was necessary was to finish the first ROP chain with a jump back to _start so that we can do a second payload that has references into libc address space.

### One Gadget
I used the one_gadget script to find a gadget:
```shell 
# one_gadget local_libc/libc6_2.31-0ubuntu9.9_amd64.so
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL
  ```
The constraints were easy to meet since there was a gadget in the binary that proved very useful: `pop r12; pop r13; pop r14; pop r15; ret;`.

### Full exploit code:
- [exploit.py](./exploit.py)