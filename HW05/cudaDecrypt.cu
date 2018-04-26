#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>

#include "cuda.h"
#include "functions.c"

  __device__ unsigned int modP(unsigned int a, unsigned int b, unsigned int p) {
  unsigned int za = a;
  unsigned int ab = 0;

  while (b > 0) {
    if (b%2 == 1) ab = (ab +  za) % p;
    za = (2 * za) % p;
    b /= 2;
  }
  return ab;
}

//compute a^b mod p safely
  __device__ unsigned int modE(unsigned int a, unsigned int b, unsigned int p) {
  unsigned int z = a;
  unsigned int aExpb = 1;

  while (b > 0) {
    if (b%2 == 1) aExpb = modP(aExpb, z, p);
    z = modP(z, z, p);
    b /= 2;
  }
  return aExpb;
}
   __global__ void kernelFindKey(unsigned int g,unsigned int p, unsigned int h, unsigned int *pointer) {
   
   int thread = threadIdx.x;
   int block = blockIdx.x;
   int Nblock = blockDim.x;

   int id = thread + block*Nblock;

   if (id<(p-1)) {
   if (modE(g,id,p)==h) {
        printf("Secret key found! x = %u \n", id);
        *pointer = id;
      } 
   }
}

int main (int argc, char **argv) {

  /* Part 2. Start this program by first copying the contents of the main function from 
     your completed decrypt.c main function. */

  //declare storage for an ElGamal cryptosytem
  unsigned int n, p, g, h, x;
  unsigned int Nints;

  //get the secret key from the user
  printf("Enter the secret key (0 if unknown): "); fflush(stdout);
  char stat = scanf("%u",&x);

  printf("Reading file.\n");

  /* Q3 Complete this function. Read in the public key data from public_key.txt
    and the cyphertexts from messages.txt. */

  FILE* key;
  key = fopen("bonus_public_key.txt", "r");
  fscanf(key, "%u \n %u \n %u \n %u \n", &n, &p, &g, &h);
  fclose(key);

  FILE* mess = fopen("bonus_message.txt", "r");
  fscanf(mess, "%u \n", &Nints);
  
  unsigned int *Zmessage = (unsigned int *) malloc(Nints*sizeof(unsigned int));
  unsigned int *a = (unsigned int *) malloc(Nints*sizeof(unsigned int));
 
  for (unsigned int i=0; i < Nints; i++) {
   fscanf(mess, "%u %u \n", &Zmessage[i], &a[i]);
  }
 

  fclose(mess);
  unsigned int Nthreads = 32;
  unsigned int Nblocks = ((unsigned int)(p-1)+Nthreads-1)/Nthreads;  

  unsigned int *h_k = (unsigned int *) malloc(sizeof(unsigned int));
  unsigned int *d_k;

  // find the secret key
  if (x==0 || modExp(g,x,p)!=h) {
    printf("Finding the secret key...\n");
    cudaMalloc(&d_k, sizeof(unsigned int));
    double startTime = clock();
    kernelFindKey <<< Nblocks, Nthreads >>> (g, p, h, d_k);
    cudaMemcpy(h_k, d_k, sizeof(unsigned int), cudaMemcpyDeviceToHost);
    cudaDeviceSynchronize();

    x = *h_k;
    double endTime = clock();
    printf("Secret key found! x = %u \n", x);

    double totalTime = (endTime-startTime)/CLOCKS_PER_SEC;
    double work = (double) p;
    double throughput = work/totalTime;
    printf("Searching all keys took %g seconds, throughput was %g values tested per second. \n", totalTime, throughput);
    }
  /* Q4 Make the search for the secret key parallel on the GPU using CUDA. */
    unsigned int bufferSize = 1024;
    unsigned char *message = (unsigned char *) malloc(bufferSize*sizeof(unsigned char));
    unsigned int charsPerInt = (n-1)/8;
    unsigned int Nchars = charsPerInt*Nints;

    double decryptStart = clock();
    ElGamalDecrypt(Zmessage, a, Nints, p, x);
    convertZToString(Zmessage, Nints, message, Nchars);
    double decryptEnd = clock();

    double decryptTime = (decryptEnd = decryptStart)/CLOCKS_PER_SEC;
    printf("decrypted message = \"%s\"\n", message);
    printf("It took %g seconds to decrypt the message. \n", decryptTime);
    printf("\n");
    
    free(Zmessage);
    free(h_k);
    cudaFree(d_k);
  return 0;
}
  


