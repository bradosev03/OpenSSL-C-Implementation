#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>


#include "DESEncrypt.h"
#include "DESDecrypt.h"
#include "CBCDESEncryption.h"
#include "CBCDESDecryption.h"

// public key, encrypted key, private key, text
 


int ksignEvpVerify(FILE * publicKeyFP, FILE * dataFileFP, FILE * sigFileFP)
{
    RSA *rsa_pkey = NULL;
    EVP_PKEY *pkey;
    EVP_MD_CTX ctx;
    unsigned char buffer[4096];
    size_t len;
    unsigned char *sig;
    unsigned int siglen;
    struct stat stat_buf;

    if (!PEM_read_RSA_PUBKEY(publicKeyFP, &rsa_pkey, NULL, NULL)) {
        fprintf(stderr, "Error loading RSA public Key File.\n");
        return 2;
    }
    pkey = EVP_PKEY_new();

    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey)) {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        return 3;
    }
    /* Read the signature */
    if (fstat(fileno(sigFileFP), &stat_buf) == -1) {
        fprintf(stderr, "Unable to read signature \n");
        return 4;
    }
    siglen = stat_buf.st_size;
    sig = (unsigned char *)malloc(siglen);
    if (sig == NULL) {
        fprintf(stderr, "Unable to allocated %d bytes for signature\n",
            siglen);
        return 5;
    }
    if ((fread(sig, 1, siglen, sigFileFP)) != siglen) {
        fprintf(stderr, "Unable to read %d bytes for signature\n",
            siglen);
        return 6;
    }
/*
    printf("Signature:");
    for (i = 0; i < siglen; i++) {
        fprintf(stdout, "%02x", sig[i]);
        if (i % 16 == 15)
            fprintf(stdout, "\n");
    }
    fprintf(stdout, "\n");
*/

    EVP_MD_CTX_init(&ctx);

    if (!EVP_VerifyInit(&ctx, EVP_sha256())) {
        fprintf(stderr, "EVP_SignInit: failed.\n");
        EVP_PKEY_free(pkey);
        return 7;
    }

    while ((len = fread(buffer, 1, sizeof buffer, dataFileFP)) > 0) {
        if (!EVP_VerifyUpdate(&ctx, buffer, len)) {
            fprintf(stderr, "EVP_SignUpdate: failed.\n");
            EVP_PKEY_free(pkey);
            return 8;
        }
    }

    if (ferror(dataFileFP)) {
        perror("input file");
        EVP_PKEY_free(pkey);
        return 9;
    }

    if (!EVP_VerifyFinal(&ctx, sig, siglen, pkey)) {
        fprintf(stderr, "EVP_VerifyFinal: failed.\n");
        free(sig);
        EVP_PKEY_free(pkey);
        return 10;
    }
    free(sig);
    EVP_PKEY_free(pkey);
    return 0;
}//






 
int main(int argc,char *argv[]){
  
  FILE *ptr;
  char* public_key;
  char* decrypt_sessionKey;
  char* enc;

  size_t size;
  size_t enc_size;
  int result;

   ptr = fopen(argv[1],"r");
	if(ptr==NULL){puts("File Error.\n"); exit(1);}

	//obtain file size
	fseek(ptr,0,SEEK_END);    
	enc_size = ftell(ptr);
	rewind(ptr);

	decrypt_sessionKey = malloc(sizeof(char)*(enc_size));
	if(decrypt_sessionKey==NULL){puts("Memory Error.\n"); exit(1);}
	result = fread(decrypt_sessionKey,1,(enc_size),ptr);
	if(result!=enc_size){puts("Memory Error.\n"); exit(1);}
  fclose(ptr);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
*                         Hash Session key to derive key/iv      
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

SHA256_CTX ctx;
u_int8_t results[SHA256_DIGEST_LENGTH];
char raw_session_key[8];

keyRead(decrypt_sessionKey,raw_session_key);

int n;
char sessionKey[8];
char iv[8];

n = 8;
SHA256_Init(&ctx);
SHA256_Update(&ctx, (u_int8_t *)raw_session_key, n);
SHA256_Final(results, &ctx);


memcpy(sessionKey,results,8);
memcpy(iv,results + 8,8);
printf("key:\n");

for (n = 0; n < 8; n++)
printf("%02x",sessionKey[n] & 0xff);

printf("\n");
printf("iv\n");
for (n = 0; n < 8; n++)
printf("%01x",iv[n] & 0xff);
printf("\n");

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
*                           Verify SHA Signagture  
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

         //original -> hash of ciphertext
         // data -> signature of ciphertext
          EVP_MD_CTX c;
          int ret;
  	 FILE *sign,*pub,*data;


	sign = fopen(argv[3],"r");
	pub = fopen(argv[4],"r");
	data = fopen(argv[2],"r");
 

	ret = ksignEvpVerify(pub, data, sign);

        switch(ret){


	case 0:
	printf("Signature Verified!\n\n");
	break;
	default:
	printf("Signature Verification Failed!\n");
	break;
	}



        fclose(sign);
	fclose(pub);
	fclose(data);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
*                          Decrypt ciphertext  DES-CBC
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

char *input_buffer;
ptr = fopen(argv[2],"r");
if(ptr==NULL){puts("File Error.\n"); exit(1);}

//obtain file size
fseek(ptr,0,SEEK_END);    
size = ftell(ptr);
rewind(ptr);

input_buffer = malloc(sizeof(char)*(size));
if(input_buffer==NULL){puts("Memory Error.\n"); exit(1);}
result = fread(input_buffer,1,(size),ptr);
if(result!=size){puts("Memory Error.\n"); exit(1);}
//printf("SIZE IS HERE: %zu\n",size);
CBC_DESDecryption(input_buffer,sessionKey,iv,size);
fclose(ptr);

free(input_buffer);


return 0;
 
}
