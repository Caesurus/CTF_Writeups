# GoogleCTF 2017 - Wiki

## Description:
> Wiki  
> Go solve it already!
> Challenge running at `wiki.ctfcompetition.com:1337`

## Synopsis / TL;DR
The binary `challenge` is a Position Independent Executable([PIE](https://en.wikipedia.org/wiki/Position-independent_code)). This means that all of the executable application code is in randomized memory locations.

The binary asks you to input a username, and then you're expected to supply the password for that user account. The password is read out of a file: `db/<username>`. There is no way to know what the correct password is. The password must also be a multiple of 8. But we'll get round to why later. If the correct password is supplied, the flag will be printed out.

The function accepting input for the password has a buffer overflow vulnerability, but since its a PIE, ~~we have no usable places to return to~~ (or so I thought). I attempted to return to the only *'known'* memory location available `0xffffffffff600000`(vsyscall) but got crashes I didn't understand. I tried finding a way to leak a memory location but was unsuccessful.

After many many hours and failed attempts I gave up on this problem and only really understood the solution after the competition ended (with help from team mates).

Here is the entry in vsyscall:
```asm
disassemble 0xffffffffff600000,+10
Dump of assembler code from 0xffffffffff600000 to 0xffffffffff60000a:
   0xffffffffff600000:	mov    rax,0x60
   0xffffffffff600007:	syscall 
   0xffffffffff600009:	ret    
```
It turns out that what I did not realize was that the call to `0xffffffffff600000` was working just fine, but gdb was not breaking upon return, execution would work fine and it was just taking the next item off the stack to return to *faceplam*.

The final solution involves finding a good location to return to that is already on the stack. So you don't actually have Remote Code Execution (REC) to solve this.

Final exploit code [here](./exploit.py)


## The full journey 

I'm going to try to explain the ride this challenge took me on.

I'll try to go into what the thought process was (as best as I can remember), so there were plenty of dead ends. 

I will try to explain things as simply as possible, in my attempt to do so I'll probably seem a bit long winded to those who are familiar with the concepts being covered here. 
Let me apologize up front, "sorry" :)

### Analyzing the binary

After downloading the binary locally, lets look at binary to see what we're dealing with:
```bash
code@box:~/CTF_Writeups/2017-GoogleCTF_Quals/wiki$ checksec challenge
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Sigh... After having just finished the 'Inst Prof' challenge, I knew that the `PIE enabled` meant this wasn't going to be an easy one.
For those not familiar with Position Independent Executable([PIE](https://en.wikipedia.org/wiki/Position-independent_code)), it basically means the code executes properly regardless of its absolute address. That base absolute address is randomized on every run, so there is no way (that I know of) to guess it. 

*Thought* _I'm going to need to leak something to calculate the base address_

Lets look at the memory map, 
```
Start              End                Perm      Name
0x0000555555554000 0x0000555555556000 r-xp      /home/code/CTF_Writeups/2017-GoogleCTF_Quals/wiki/challenge
0x0000555555755000 0x0000555555756000 r--p      /home/code/CTF_Writeups/2017-GoogleCTF_Quals/wiki/challenge
0x0000555555756000 0x0000555555757000 rw-p      /home/code/CTF_Writeups/2017-GoogleCTF_Quals/wiki/challenge
0x00007ffff7a0e000 0x00007ffff7bcd000 r-xp      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p      mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fc9000 0x00007ffff7fcc000 rw-p      mapped
0x00007ffff7ff6000 0x00007ffff7ff8000 rw-p      mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p      [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp      [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p      mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p      [stack]
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]
```

### Step 1, Let's make the binary operate correctly locally.

When I first fired up the binary and started playing with it, I didn't have the directory structure in place for it to read out any valid users. While stepping through the code with [pwndbg](https://github.com/pwndbg/pwndbg) I sort of follewed along with what it was expecting. So I connected to the remote server and did a `LIST`
```bash
$ ./challenge 
LIST
xmlset_roodkcableoj28840ybtide
Fortimanager_Access
1MB@tMaN
```
Great! So I created a directory called `db` and created files in that directory. In the files I added a default password.

Then I proceeded to try to get a better understanding of what was going on. 

### Step 2, Open the binary in our favorite analysis tool
Lets fire up [Binary Ninja](https://binary.ninja/), and take a look. 
![alt text][Binja1]
And another view:
![alt text][Binja2]
Now, we start seeing some interesting strings there:
```
USER
PASS
LIST
```
But having used PIE in Binary Ninja before, I knew I that it sometimes needs a little help finding functions. So address 0xd42-0xe10 probably has a function (or two) in there somewhere. (Binary Ninja is working on improving this). So we can click on an address and press `p` and tell it there is a function there. And Ctrl-Z works fine, so if the defined function doesn't make sense you can just 'undo' that change. 

OK, so here is where I spent a bunch of time looking and understanding the code, renaming functions etc... The process is not fun to describe, so lets just dive into what I found. This was not just static analysis, it was hours of running the binary and cross referencing etc... [After renaming and defining things](https://github.com/Caesurus/CTF_Writeups/blob/master/2017-GoogleCTF_Quals/images/wiki-binja3.png)

What I found (function names are mine):
* Function `wrapped_read()`.

   This reads in user input. Calls `read()`, 1 byte at a time until the passed in length is reached or a newline is found.

* Function `compare_str()`.

   This compares two strings, it will keep looping till a NULL character is encountered, or the first difference is found. I thought it was curious that someone would implement this themselves when they could have called `strcmp()`. Turn out there was a good reason for this. Returns 1 if strings match, return 0 if they don't.
   
* Command: `LIST`. 

   This reads the contents of `db` directory and prints each file in the directory (except for `.`) This is also the only location where something is output to STDOUT. If there is a possible leak, this had to be it.

* Command: `USER`. 

   This takes user input (0x80 bytes) and checks if `/` is present in the string. 
   If it is, `exit()` is called.
   If not, then pass it to another function, I called it `process_USER_FILE`

* Function `process_USER_FILE()`.

   This function will open the users file in the `db` directory, read the contents (spoiler: it's the password), and return the `strdup()`. In very basic terms, the function will read the password onto the stack, then call `strdup()` which will allocate memory on the heap, copy the string into it, and return a pointer to the string on the heap.
   We really can't control the input into `strdup`, so I didn't look too closely at whether this was vulnerable.
   
* Command: `PASS`. 

   This function `process_PASS()` has a stack size of `0x88` but will accept user input and accept `0x1000` bytes of input. So this is an obvious buffer overflow. OK that's the vulnerability. This also only accepts the user input if the length is a multiple of 8, if it's not, then `exit()`... mmm
   
   If the password is correct it will call `system("cat flag.txt")`, otherwise just return.

![alt text][Binja4]
See the `sub rsp,0x88`, but then `0x1000` is passed to `wrapped_read()`

### Step 3, Lets overflow that buffer!!!

Oh yeah, lets overflow the password input and control where we return to. Easy right? But it took all of 3 seconds to go "Ohhh... Damn PIE". Since all the addresses are randomized, I haven't got a reliable address to return to.

But wait, you know what... I'll be smart and when overwriting the return pointer on the stack, I'll just overwrite the last byte, or last two bytes. Since it's little endian, I can just update those bytes, the rest will already be valid bytes for the memory location. So I just need to update the last couple bytes to return to the `system("cat flag.txt")` code. 

I was soo happy, "take that" I exclaimed!... And then I tried it and it called `exit()`.. Duh, the password has to be a multiple of 8. *sigh* So that's not going to work! That's why there was that limitation!!!

### Step 4, Smash head against hard objects... 
OK, back to looking for other options (not necessarily in this order). 

- What can I do to leak an address? (spoiler: after many hours of looking... nothing)

- I don't have to overwrite the return pointer, what if I just overwrite the two values on the stack before the return. One gets loaded into `rbx`(this is the pointer for our user read buffer), and the other gets loaded into `rbp`. Neither is helpful without knowing a usable address.

- Can I return to the one constant 'known' address, the `vsyscall` memory? I got wierd crashes when returning to `0xffffffffff600000`. So I didn't persue this further *sigh... hindsight is 20/20*

- Is one of the users passwords designed to pass something to `strdup()` that is somehow needed? 

- Are the password lengths for each user different, and can I somehow detect that?

*Getting desperate...*

- The string compare exits on the first byte that doesn't match... can do a timing attack? NO... That code is so fast and the network latency makes that impossible.

And so after hours and hours of working on the problem I'm sad to say I gave up. 

### Step 5, wait for the CTF to be over and go hunting for answers. *I NEED to KNOW!!!*
Fast forward a couple of hours and the CTF is over. I talk with people from other teams and try to get answers. 

Then someone passed me the solution... D'OH!!!!

### Step 6, Solve it.

The missing piece was that I didn't realize that my call to the `vsyscall` worked just fine.
```
   0xffffffffff600000:	mov    rax,0x60
   0xffffffffff600007:	syscall 
   0xffffffffff600009:	ret  
```
Syscall 0x60 is executed, and then it does a return. But my debugger didn't break on the return and just took the next item off the stack to return to and went off into the weeds. I didn't piece that together and didn't persue it hard enough.



[Binja1]: https://github.com/Caesurus/CTF_Writeups/blob/master/2017-GoogleCTF_Quals/images/wiki-binja1.png "Binary Ninja looking at main." 
[Binja2]: https://github.com/Caesurus/CTF_Writeups/blob/master/2017-GoogleCTF_Quals/images/wiki-binja2.png "Binary Ninja, needs some manual help with PIE" 
[Binja3]: https://github.com/Caesurus/CTF_Writeups/blob/master/2017-GoogleCTF_Quals/images/wiki-binja3.png "Renaming stuff is helpful" 
[Binja4]: https://github.com/Caesurus/CTF_Writeups/blob/master/2017-GoogleCTF_Quals/images/wiki-binja4.png "Buffer overflow" 


