#include <stdio.h>
#include <stdlib.h>


void do_stuff(){
  printf("Hello world from across two files!\n");
  trigger_violation((char*)(0x10000 + (rand() % (1UL << 26))));
}


