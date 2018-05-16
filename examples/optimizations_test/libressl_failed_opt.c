#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define AES_BLOCK_SIZE 128
#define N_WORDS (AES_BLOCK_SIZE / sizeof(unsigned long))

#define AES_ENCRYPT 1

typedef struct {
    unsigned long data[N_WORDS];
} aes_block_t;

#define UNALIGNED_MEMOPS_ARE_FAST 0

void memguard_violation(void *addr){
    printf("MemGuard access violation occurred at address %p\n\tTerminating program", addr);
    exit(1);
}

void
AES_ige_encrypt(const unsigned char *in, unsigned char *out, size_t length,
  unsigned char *ivec, const int enc)
{
	size_t n;
	size_t len;

	len = length / AES_BLOCK_SIZE;

	if (AES_ENCRYPT == enc) {
		if (in != out && (UNALIGNED_MEMOPS_ARE_FAST ||
		    ((size_t)in|(size_t)out|(size_t)ivec) %
		    sizeof(long) == 0)) {
			aes_block_t *ivp = (aes_block_t *)ivec;
			aes_block_t *iv2p = (aes_block_t *)(ivec + AES_BLOCK_SIZE);

			while (len) {
				aes_block_t *inp = (aes_block_t *)in;
				aes_block_t *outp = (aes_block_t *)out;

				for (n = 0; n < N_WORDS; ++n)
					outp->data[n] = inp->data[n] ^ ivp->data[n];
				
                printf("Some function call\n");
                
                for (n = 0; n < N_WORDS; ++n)
					outp->data[n] ^= iv2p->data[n];
				ivp = outp;
				iv2p = inp;
				--len;
				in += AES_BLOCK_SIZE;
				out += AES_BLOCK_SIZE;
			}
			memcpy(ivec, ivp->data, AES_BLOCK_SIZE);
			memcpy(ivec + AES_BLOCK_SIZE, iv2p->data, AES_BLOCK_SIZE);
		} else {
			aes_block_t tmp, tmp2;
			aes_block_t iv;
			aes_block_t iv2;

            printf("Some function call\n");
            printf("Some function call\n");

			while (len) {
				printf("Some function call\n");
                for (n = 0; n < N_WORDS; ++n)
					tmp2.data[n] = tmp.data[n] ^ iv.data[n];
				printf("Some function call\n");
                for (n = 0; n < N_WORDS; ++n)
					tmp2.data[n] ^= iv2.data[n];
				printf("Some function call\n");
                iv = tmp2;
				iv2 = tmp;
				--len;
				in += AES_BLOCK_SIZE;
				out += AES_BLOCK_SIZE;
			}
			memcpy(ivec, iv.data, AES_BLOCK_SIZE);
			memcpy(ivec + AES_BLOCK_SIZE, iv2.data, AES_BLOCK_SIZE);
		}
	} else {
		if (in != out && (UNALIGNED_MEMOPS_ARE_FAST ||
		    ((size_t)in|(size_t)out|(size_t)ivec) %
		    sizeof(long) == 0)) {
			aes_block_t *ivp = (aes_block_t *)ivec;
			aes_block_t *iv2p = (aes_block_t *)(ivec + AES_BLOCK_SIZE);

			while (len) {
				aes_block_t tmp;
				aes_block_t *inp = (aes_block_t *)in;
				aes_block_t *outp = (aes_block_t *)out;

				for (n = 0; n < N_WORDS; ++n)
					tmp.data[n] = inp->data[n] ^ iv2p->data[n];
				printf("Some function call\n");
                for (n = 0; n < N_WORDS; ++n)
					outp->data[n] ^= ivp->data[n];
				ivp = inp;
				iv2p = outp;
				--len;
				in += AES_BLOCK_SIZE;
				out += AES_BLOCK_SIZE;
			}
			memcpy(ivec, ivp->data, AES_BLOCK_SIZE);
			memcpy(ivec + AES_BLOCK_SIZE, iv2p->data, AES_BLOCK_SIZE);
		} else {
			aes_block_t tmp, tmp2;
			aes_block_t iv;
			aes_block_t iv2;

            
            printf("Some function call\n");
            printf("Some function call\n");

			while (len) {
				printf("Some function call\n");
                tmp2 = tmp;
				for (n = 0; n < N_WORDS; ++n)
					tmp.data[n] ^= iv2.data[n];
				
                printf("Some function call\n");
                
                for (n = 0; n < N_WORDS; ++n)
					tmp.data[n] ^= iv.data[n];
				printf("Some function call\n");
                iv = tmp2;
				iv2 = tmp;
				--len;
				in += AES_BLOCK_SIZE;
				out += AES_BLOCK_SIZE;
			}
			memcpy(ivec, iv.data, AES_BLOCK_SIZE);
			memcpy(ivec + AES_BLOCK_SIZE, iv2.data, AES_BLOCK_SIZE);
		}
	}
}


int main(int argc, char **argv, char **envp){
    printf("Agh\n");
}


