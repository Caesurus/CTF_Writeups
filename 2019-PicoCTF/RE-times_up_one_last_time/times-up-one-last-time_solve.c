#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

main() {
  open("/dev/urandom", 0);
  open("/dev/null", 0);
  open("/dev/urandom", 0);




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

