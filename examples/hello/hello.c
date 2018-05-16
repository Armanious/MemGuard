#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <time.h>



volatile int *global_array;
int x;

static void min_for_cmov(int i, int x, int y){
  srand(time(0));
  int r = rand();
  global_array[i] = r % 2 ? x : y;
}

static void global_stuff(){
  char buf[4096];
  x = 123 + ((unsigned) global_stuff) % 31;
  buf[x] = 'x';
  printf("address of x = %p\nvalue of x = %d\n", &x, x);
  printf("address of buf[x] = %p\nvalue of buf[x] = %d\n", &buf[x], buf[x]);
  global_array = malloc(923 * sizeof(int));
}

static void local_stuff(){
  char buf[4096];
  int y = 456;
  buf[y] = 'y';
  printf("address of y = %p\nvalue of y = %d\n", &y, y);
  printf("address of buf[y] = %p\nvalue of buf[y] = %d\n", &buf[y], buf[y]);
}

static void local_stuff_with_args(int n){
  char buf[4096];
  buf[n] = 'n';
  printf("address of n = %p\nvalue of n = %d\n", &n, n);
}

static void __attribute__((noinline)) __safe_verify_safe_region(){
  printf("Beginning safe region verification...\n");
  int failed = 0;
  unsigned long *arr = (unsigned long*) 0x10000;
  for(unsigned int idx = 0; idx < (0x4000000) / sizeof(unsigned long); idx++){
    if((failed = arr[idx] != 0)){
      printf("Address at %p = %lx\n", &arr[idx], arr[idx]);
      break;
    }
    arr[idx] = (unsigned long) -1;
  }
  printf("Safe region verification completed: %s\n", failed ? "failed" : "success");
}

static void trigger_violation(char *ptr){
  if(ptr) ptr = (char*) ((unsigned long)(ptr) % (1UL << 25));
  if((unsigned long)ptr < (1UL << 16)) ptr = (char*) ((1UL << 16) + 42);
  min_for_cmov(x, (unsigned int) trigger_violation, (int) ((unsigned long) ptr) % 70);
  
  printf("Program should reach here...triggering violation at %p\n", ptr);
  *ptr = 23;
  printf("Should not reach here! I just accessed secret data :(\n");
  while(1);
}

void memguard_violation(void *ptr){
  printf("MemGuard violation trigered at: %p\n\tKilling process now.\n", ptr);
  exit(1);
}


void foo(long *bar){
    (*bar)++;
}

int main() {
  mmap(0x10000, 1UL << 26, 3, 49, -1, 0);
  global_stuff();
  local_stuff();
  local_stuff_with_args(42);
  //__safe_verify_safe_region();
  trigger_violation((char*)local_stuff);
  return 0;
}
