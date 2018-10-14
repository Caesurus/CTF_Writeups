# PicoCTF 2018 - RE assembly-3 - 400 pts

## Description
What does asm3(0xb5e8e971,0xc6b58a95,0xe20737e9) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](https://2018shell1.picoctf.com/static/914cb4b741cf358f0cdd4d9d07ad5671/end_asm_rev.S) located in the directory at /problems/assembly-3_3_bfab45ee7af9befc86795220ffa362f4.

## Approach
I took the easiest approach I could think of... Compile and run the code.
Compile the [end_asm_rev.S](end_asm_rev.S) code. I was lazy and just copy/pasted the code into https://defuse.ca/online-x86-assembler.htm#disassembly

I then took the bytecode and pasted it into a buffer in a c application, defined the function pointer to take three parameters, and passed the parameters in the description.
```
// gcc asm3.c -o asm3_out -fno-stack-protector -z execstack -no-pie -m32

char shellcode[] = "\x55\x89\xE5\xB8\x19\x00\x00\x00\x30\xC0\x8A\x65\x0A\x66\xC1\xE0\x10\x2A\x45\x0D\x02\x65\x0C\x66\x33\x45\x12\x89\xEC\x5D\xC3";

int main(int argc, char **argv){
        int (*fp) (int, int, int);
        fp = (void *)shellcode;
        int ret = fp(0xb5e8e971,0xc6b58a95,0xe20737e9);
        printf("ret = 0x%x\n", ret);

}
```

```
gcc asm3.c -o asm3_out -fno-stack-protector -z execstack -no-pie -m32
```

```
$ ./asm3_out
ret = 0x7771
```

I thought this was an easy and fun way to solve this.
