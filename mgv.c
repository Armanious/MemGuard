#include <stdio.h>
#include <signal.h>
#include <pthread.h>

void memguard_violation(void *addr){
    fprintf(stderr, "MemGuard access violation occurred at address %p!\n\tTerminating thread now!", addr);
    pthread_exit((void *) SIGSEGV);
    // exit(SIGSEGV);
}
