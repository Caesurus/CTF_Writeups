# Whitehat 2017 - Shellcode_revenge++

I only managed to play one challenge in this CTF. The challenge was obviously trying to get you to write alpha numeric 64bit shellcode.

Generally I enjoy these shellcode challenges when I have plenty of time to play. During the CTF I didn't have much time available.

Usually one of the first things I'll look at doing is writing just enough shellcode to do another `read()` so that I can bypass the filters.

But even that sounded tedious. So I started looking for a way to bypass the shellcoding part of it altogether, after a bit of digging I managed to come up with a way.

## Description of attack:

This utilizes a 3 stage payload.

1) Utilize the BOF which will only allow you overwrite the return address (no more than that, so ROP is limited)
  - This is meant to allow you to jump to the shellcode
2) Instead overwrite the RBP and return pointer, and return to section of code that does a `read()`
  - Since it's reading to a location relative to RBP, it's now getting read into BSS executable memory.
  - We are still limited in length
3) Write just enough shellcode (no filters) to be able to do yet another read with much more buffer
4) Jump to this small section of shellcode
5) Read in a much larger section of shellcode, no restrictions other than newline.
6) Exectute newly uploaded shellcode
7) Profit

