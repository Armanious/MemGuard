#include <stdio.h>

void do_stuff();


void memguard_violation(void *ptr){
  printf("MemGuard violation trigered at: %p\n", ptr);
  // exit(1);
}

int main(){
  __safe_verify_safe_region();
  do_stuff();
  return 0;
}


