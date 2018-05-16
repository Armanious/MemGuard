#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <time.h>



void __attribute__((noinline)) __safe_verify_safe_region(){
  printf("Beginning safe region verification...\n");
  int failed = 0;
  unsigned long *arr = (unsigned long*) 0x10000;
  for(unsigned int idx = 0; idx < (0x4000000 - 0x10000) / sizeof(unsigned long); idx++){
    if((failed = arr[idx] != 0)){
      printf("Address at %p = %lx\n", &arr[idx], arr[idx]);
      break;
    }
    arr[idx] = (unsigned long) -1;
  }
  printf("Safe region verification completed: %s\n", failed ? "failed" : "success");
}

void trigger_violation(char *ptr){
  if(ptr) ptr = (char*) ((unsigned long)(ptr) % (1UL << 25));
  if((unsigned long)ptr < (1UL << 16)) ptr = (char*) ((1UL << 16) + 42);
  printf("Program should reach here...triggering violation at %p\n", ptr);
  *ptr = 23;
  printf("Hopefully a violation was triggered at %p\n", ptr);
}




