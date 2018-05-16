#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct to_optimize {
    int f1_i;
    int f2_i;
    long *f3_arr;
    short f4_s;
} to_optimize_t;

to_optimize_t *initialize_struct(){
    to_optimize_t *res = (to_optimize_t *) malloc(sizeof(to_optimize_t));
    if(!res) return NULL;
    res->f3_arr = (long *) malloc(100 * sizeof(long));
    if(!res->f3_arr){
        free(res);
        return NULL;
    }

    res->f1_i = 0;
    res->f2_i = 0;
    // res->f3_arr already allocated
    memset(res->f3_arr, 0, 100 * sizeof(long));
    res->f4_s = 0;

    return res;
}

void do_stuff(to_optimize_t *res){
    res->f1_i <<= 2;
    res->f2_i += res->f1_i ^ res->f2_i;
    res->f3_arr[0]++;
    for(unsigned int i = 1; i < 100; i++){
        res->f3_arr[i] = res->f3_arr[i-1] + i;
    }
    res->f4_s = (short) res->f3_arr[99];
}

void destroy_struct(to_optimize_t *res){
    free(res->f3_arr);
    free(res);
}

void memguard_violation(void *addr){
    printf("MemGuard violation accessed address %p\n\tTerminating program", addr);
    exit(1);
}

int main(int argc, char **argv, char **envp){
    to_optimize_t *res = initialize_struct();
    for(int i = 0; i < 100000; i++) do_stuff(res);
}



