#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define BUF_SIZE 8192

int main(){
    unsigned long buf[BUF_SIZE];
    int rfd = open("/dev/urandom", O_RDONLY);
    if(rfd == -1){
        printf("Could not open /dev/urandom: %s (%d)\n", strerror(errno), errno);
        exit(1);
    }
    int wfd = open("r", O_WRONLY|O_CREAT|O_TRUNC);
    if(wfd == -1){
        printf("Could not open r: %s (%d)\n", strerror(errno), errno);
        exit(1);
    }
    for(int i = 0; i < 128; i++){
        read(rfd, (void*) buf, BUF_SIZE * sizeof(unsigned long));
        for(int j = 0; j < BUF_SIZE; j++) dprintf(wfd, "%lu\n", buf[j]);
        printf("%d/128 completed\n", i);
    }
    close(wfd);
    close(rfd);
    return 0;
}
