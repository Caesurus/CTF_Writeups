> 2 - garbage
> One of our team members developed a Flare-On challenge but accidentally deleted it. We recovered it using extreme digital forensic techniques but it seems to be corrupted. We would fix it but we are too busy solving today's most important information security threats affecting our global economy. You should be able to get it working again, reverse engineer it, and acquire the flag.
2_-_garbage.7z

# Disclaimer
I should probably take a moment to issue a disclaimer that I usually don't do anything with PE files, so this is a whole new world for me. So by no means should this be taken as the 'correct approach' to solving this challenge.

I also recently switched to a new job which now frequently scratches that part of my brain that I usually relied on CTF problems to scratch. This results in a lower desire/drive to work on challenges during my spare time. That said, I felt that the first couple of Flare-On challenges should be within my rusty reach and time budget. Since they were outside my comfort zone, I figured I should give them a shot.


# TLDR;

I fumbled my way through the UPX unpacking, and used Ghidras emulation capabilities to grab the flag.


## Initial overview

After extracting the 7z, we get a file: `garbage.exe`
Upon initial inspection, we see that the file seems to be truncated at the end.

![Binja screenshot sections](https://gist.githubusercontent.com/Caesurus/3f2f5c47a714bf8838d6b49d43acef66/raw/81fb6e7125bf091c47e314f3af829bd1718979f3/sections.png)

![Binja screenshot truncated](https://gist.githubusercontent.com/Caesurus/3f2f5c47a714bf8838d6b49d43acef66/raw/5aad64b3331b9387826e7619aeee958c8ab38f52/truncated.png)


It also seemed obvious that the file was UPX packed. So my first attempt was to download the latest version of UPX and tried to unpack it. This unfortunately failed because it didn't determine the file was a valid PE file.

I've never dealt with corrupt PE files, but the manifest section looked like simple XML, so I tried copy/pasting from another binary. In addition to this, the `.rsrc` section defined in the PE header states
```c
.rsrc section started  {0x419000-0x41a000}
```
but our truncated file only goes till `0x419123`, So I added a bunch of nulls to the end of the file.


## Unpacked UPX

Once I fixed the xml in what I presume is the manifest section, together with the length, the exe still wouldn't run. But UPX was able to unpack it!

So now we are able to see something meaningful in ghidra, and it was easy to find the function that looked like it was decoding two strings.
```C
  string_1 = (undefined4 *)
                          
             "nPTnaGLkIqdcQwvieFQKGcTGOTbfMjDNmvibfBDdFBhoPaBbtfQuuGWYomtqTFqvBSKdUMmciqKSGZaosWCSoZlcIlyQpOwkcAgw "
  ;
  cp_string_1 = local_12c;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *cp_string_1 = *string_1;
    string_1 = string_1 + 1;
    cp_string_1 = cp_string_1 + 1;
  }
  iVar2 = 0x19;
  local_54 = 0x40a1e0a;
  *(undefined2 *)cp_string_1 = *(undefined2 *)string_1;
  local_50 = 0x1a021623;
  local_4c = 0x24086644;
  string_1 = (undefined4 *)
                          
             "KglPFOsQDxBPXmclOpmsdLDEPMRWbMDzwhDGOyqAkVMRvnBeIkpZIhFznwVylfjrkqprBPAdPuaiVoVugQAlyOQQtxBNsTdPZgDH "
  ;
  cp_string_1 = local_c4;
```
That looks pretty promising....

However when trying to run the unpacked binary there are still errors, after many attempts and reading up on PE files etc, it seemed that this was due to the import tables still being corrupted.

I read several guides on how to rebuild the Import Table Directory/Import Address Table etc. Ultimately I failed, I got frustrated with not being able to fix IAT with tools like Scylla. I probably was just doing it wrong, or I was meant to do it manually?

I just wanted to run that isolated function, I don't want to load the whole binary!!!

__So what are the next Options?__:
- Static analysis of the code, reimplement it in C or python...
- Emulation!

Although I've definitely done the static analysis and reimplementation in the past, it sounded like a _"less than fun"_ exercise. Time to try emulation!

## Emulation 
### Qiling
As a long time user and fan of usercorn, I've been looking for an excuse to give Qiling a shot and compare its functionality.


https://github.com/qilingframework/qiling


Unfortunately even the most basic examples of loading a `.exe` failed because of failures to load libraries. There may be a way to get around this, but I honestly didn't spend very long on it because there was another option I wanted to try.


### Ghidra emulation!
This has been something I only recently found out about, but have been wanting to get to play with. This seemed like a great time to try it out.


I found this excellent article:
https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb


This was also helpful:
https://github.com/cetfor/GhidraSnippets

I started out with the sample code in the article, and expected to run into a ton of errors. 


The first error I encountered was that the registers used were incorrect, So that was an easy fix just switching out 64bit to 32bit. EG:(RAX->EAX) 


Then defined the function as the starting point (EIP) and kept the ESP and EBP the same as the examples.
```C
    myEntry = getSymbolAddress("FUN_0040106b")
    
    # Set initial EIP
    mainFunctionEntryLong = int("0x{}".format(myEntry), 16)
    emuHelper.writeRegister(emuHelper.getPCRegister(), mainFunctionEntryLong)
```

The next time that I ran the script it actually ran, and did a bunch of stuff. But crashed at this line:
```asm
        00401166 ff 15 0c        CALL       dword ptr [PTR_0040d00c]                         -> 00012418
                 d0 40 00
```
Because `00012418` is not valid memory! Obviously because the pointer never got initialized properly. When we look at that PTR:
```asm
                             0  CreateFileA  <<not bound>>
                             PTR_0040d00c                                    XREF[1]:     FUN_0040106b:00401166  
        0040d00c 18 24 01 00     addr       00012418                                         IMAGE_THUNK_DATA32
```
We can see that it's trying to call `CreateFileA`, and so it seemed obvious enough that it was trying to create a file. Since we don't actually want to do this, I needed to figure out how to skip over this instruction. I did so by doing:
```python
        if executionAddress == getAddress(0x0401166):
            emuHelper.writeRegister(emuHelper.getPCRegister(), 0x40116c)
            print("skipping")
```
I don't know if this is the best approach. Shout out and leave a comment if you know a better way. It should be noted that we want this function to return a non-negative one. So eax (which is stored into `iVar2`) is already in a good state for this.
```c
  if (iVar2 != -1) {
    local_140 = 0;
    FUN_00401000(local_13c,(int)&local_5c,0x3d,(int)local_12c);
    (*(code *)(undefined *)0x123f8)(iVar2,local_13c[0],0x3d,&local_140,0);
    FUN_00401045(local_13c);
    (*(code *)(undefined *)0x12426)(iVar2);
    FUN_00401000(local_13c,(int)&local_1c,0x14,(int)local_c4);
    (*(code *)(undefined *)0x12442)(0,0,local_13c[0],0,0,0);
    FUN_00401045(local_13c);
  }
```

On the next run, the script failed here:
```asm
        004011ae ff 15 04        CALL       dword ptr [PTR_0040d004]                         -> 000123f8
                 d0 40 00
```
Again, it's a library call to `WriteFile`. Well we don't care about actually doing this, but lets find out what is trying to be written.

So since this is x86, parameters are passed to the function by pushing onto the stack:
```asm
        004011a4 50              PUSH       EAX
        004011a5 6a 3d           PUSH       0x3d
        004011a7 ff b5 c8        PUSH       dword ptr [EBP + local_13c]
                 fe ff ff
        004011ad 56              PUSH       ESI
```

Here I calculated `[EBP + local_13c]` to be `0x2ffeffa4`, and since I just wanted to grab the flag, just wanted to dump the memory there:
```python
        if executionAddress == getAddress(0x4011ad):
            mem1 = emuHelper.readMemory(getAddress(0x2ffeffa4), 60)
            flagstr = ''
            for i in mem1:
                if i < 255 and i > 0:
                    flagstr += chr(i)
            print(flagstr)
            return
```
BOOOM, it prints the flag:
```python
.
.
.
Address: 0x004011ad (PUSH ESI)
  EIP = 0x00000000004011ad
  EAX = 0x000000002ffefec0
  EBX = 0x0000000000000000
  ECX = 0x000000002ffeffa4
  EDX = 0x000000000000003c
  ESI = 0x000000002ffefec4
  EDI = 0x000000002ffeffa2
  ESP = 0x000000002ffefe88
  EBP = 0x000000002ffefffc
  eflags = 0x0000000000000000
MsgBox("Congrats! Your key is: CorruptG4rbage@flare-on.com")
2_garbage.py> Finished!
```

## Summary

Ghidra emulation is pretty awesome!!! I went from not knowing anything about Ghidra emulation, to grabbing the flag within about 30mins. This speaks volumes for how usable it is. 


