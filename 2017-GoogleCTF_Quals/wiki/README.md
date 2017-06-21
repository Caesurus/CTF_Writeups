# GoogleCTF 2017 - Wiki

## Description:
> Wiki  
> Go solve it already!
> Challenge running at `wiki.ctfcompetition.com:1337`

## Synopsis / TL;DR
The binary is a Position Independent Executable([PIE](https://en.wikipedia.org/wiki/Position-independent_code)). This means that all of the executable application code is in randomized memory locations.

The binary asks you to input a username, and then you're expected to supply the password for that user account. The password is read out of a file: `db/<username>`. There is no way to know what the correct password is. The password must also be a multiple of 8. But we'll get round to why later. If the correct password is supplied, the flag will be printed out.

The function accepting input for the password has a buffer overflow vulnerability, but since its a PIE, ~~we have no usable places to return to~~ (or so I thought). I attempted to return to the only *'known'* memory location available `0xffffffffff600000`(vsyscall) but got crashes I didn't understand.

After many many hours and failed attempts I gave up on this problem and only solved it afterwards with help from team mates.

Here is the entry in vsyscall:
```asm
disassemble 0xffffffffff600000,+10
Dump of assembler code from 0xffffffffff600000 to 0xffffffffff60000a:
   0xffffffffff600000:	mov    rax,0x60
   0xffffffffff600007:	syscall 
   0xffffffffff600009:	ret    
```
It turns out that what I did not realize was that the call to `0xffffffffff600000` was working just fine, but gdb was not breaking upon return, execution would work find and it was just taking the next item off the stack to return to.

The solution involves finding a good location to return to that is already on the stack. So you don't actually have Remote Code Execution (REC) to solve this.

Final exploit code [here](./exploit.py)


## The full journey 

I'm going to try to explain the ride this challenge took me on. 

I'll try to go into what the thought process was (as best as I can remember). 

I will try to explain things as simply as possible, in my attempt to do so I'll probably seem a bit long winded to those who are familiar with the concepts being covered here. 
Let me appologize up front, sorry :)

### Analyzing the binary


### Step 1

