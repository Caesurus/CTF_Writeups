# PicoCTF 2018 - RE Circuit123 - 800 pts

## Description
Can you crack the key to [decrypt](https://2018shell1.picoctf.com/static/f5574cc5fb752ce65d53e22bf7141424/decrypt.py) [map2](https://2018shell1.picoctf.com/static/f5574cc5fb752ce65d53e22bf7141424/map2.txt) for us? The key to [map1](https://2018shell1.picoctf.com/static/f5574cc5fb752ce65d53e22bf7141424/map1.txt) is 11443513758266689915.

## decrypt.py Script overview
This challenge expects you to pass a key (number), and a map file to the script. It will then process the key and check it against several OR/XOR gates in a circuit. If the key is correct, it will use it to decrypt a sha512 value to reveal the flag.

## Initial impressions
I was feeling fairly good about having completed the other RE problems this CTF had to offer. When I initially looked at this problem I either neglected to read the hint, or the hint initially wasn't there. I didn't have a lot of time to dedicate to this CTF and there were SO many challenges that I decided to skip it. This is mainly because it was outside my norm, it wasn't an ELF file and I just decided not to tackle it.

## That itch in the back of your brain
After doing a couple of the entry level `Binary Exploitation` and `Crypto` challenges I just kept thinking about this challenge. It felt like it was that itch that needed to be scratched. Life was happening around me, family/work etc, but I really felt like I needed to at least try to solve it. It looked like it was the last RE challenge, and leaving it bugged my OCD way too much.

## Initial Attempt - The hard way
My first attempt at solving this was to cycle through each gate and trying to determine the known quantities:
For example, working backwards we know the very last gates value. So if the gate before it is an OR gate we can assume
```
1 | 1 = 1
1 | 0 = 1
0 | 1 = 1
0 | 0 = 0
```
So if the output is 0, then the two inputs would logically be 0 as well. I then spent some time working through the chain backwards trying to figure out what is 'known' and what we don't know for sure yet.

Given that, we can then look at the XOR gates:
```
1 ^ 1 = 0
1 ^ 0 = 1
0 ^ 1 = 1
0 ^ 0 = 0
```
If we know any of the two values, then we can be confident about the third value.

I got fairly far with this approach, and then it hit me like running into a brick wall. I was writing a constraint solver. WTH wasn't I using z3?

## The right way
Once I had that realization it was a quick modification of the original script that would generate a z3 script for me.

[decrypt_z3_final.py](decrypt_z3_final.py)

```
$ ./decrypt_z3_final.py map2.txt  > generated_z3.py
$ python generated_z3.py     
10100101000110110111010001001010000101101110111001000110010101111001011011101111101000101010111101001110000110110011001011001101

219465169949186335766963147192904921805
$ python decrypt.py 219465169949186335766963147192904921805 map2.txt
Attempting to decrypt map2.txt...
Congrats the flag for map2.txt is: picoCTF{36cc0cc10d273941c34694abdb21580d__aw350m3_ari7hm37ic__}
```

After I solved it I went back to check the hint and saw:
#### Hint
*Have you heard of z3?*

#### Oh well...
¯\\\_(ツ)_/¯
