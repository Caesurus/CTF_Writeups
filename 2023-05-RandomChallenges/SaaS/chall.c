#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SIZE 0x100

// http://shell-storm.org/online/Online-Assembler-and-Disassembler/?inst=xor+rax%2C+rax%0D%0Amov+rdi%2C+rsp%0D%0Aand+rdi%2C+0xfffffffffffff000%0D%0Asub+rdi%2C+0x2000%0D%0Amov+rcx%2C+0x600%0D%0Arep+stosq%0D%0Axor+rbx%2C+rbx%0D%0Axor+rcx%2C+rcx%0D%0Axor+rdx%2C+rdx%0D%0Axor+rsp%2C+rsp%0D%0Axor+rbp%2C+rbp%0D%0Axor+rsi%2C+rsi%0D%0Axor+rdi%2C+rdi%0D%0Axor+r8%2C+r8%0D%0Axor+r9%2C+r9%0D%0Axor+r10%2C+r10%0D%0Axor+r11%2C+r11%0D%0Axor+r12%2C+r12%0D%0Axor+r13%2C+r13%0D%0Axor+r14%2C+r14%0D%0Axor+r15%2C+r15%0D%0A&arch=x86-64&as_format=inline#assembly
#define HEADER "\x48\x31\xc0\x48\x89\xe7\x48\x81\xe7\x00\xf0\xff\xff\x48\x81\xef\x00\x20\x00\x00\x48\xc7\xc1\x00\x06\x00\x00\xf3\x48\xab\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xe4\x48\x31\xed\x48\x31\xf6\x48\x31\xff\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff"

#define FLAG_SIZE 64

char flag[FLAG_SIZE];

void load_flag() {
  int fd;
  if ((fd = open("flag.txt", O_RDONLY)) == -1)
    error(EXIT_FAILURE, errno, "open flag");
  if (read(fd, flag, FLAG_SIZE) == -1)
    error(EXIT_FAILURE, errno, "read flag");
  if (close(fd) == -1)
    error(EXIT_FAILURE, errno, "close flag");
}

void setup() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  int ret = 0;
  if (ctx != NULL) {
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
      SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    ret |= seccomp_load(ctx);
  }
  seccomp_release(ctx);
  if (ctx == NULL || ret)
    error(EXIT_FAILURE, 0, "seccomp");
}

int main()
{
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  load_flag();
  puts("Welcome to Shellcode as a Service!");

  void* addr = mmap(NULL, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  memcpy(addr, HEADER, sizeof(HEADER));
  read(0, addr + sizeof(HEADER) - 1, SIZE);

  setup();
  goto *addr;
}
