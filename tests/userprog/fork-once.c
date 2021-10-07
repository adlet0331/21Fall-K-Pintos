/* Forks and waits for a single child process. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void) 
{
  int pid;

  pid = fork("child");
  msg("fork finish");
  if (pid){
    msg("Pid is %d", pid);
    int status = wait (pid);
    msg ("Parent: child exit status is %d", status);
  } else {
    msg ("child run");
    exit(81);
  }
}
