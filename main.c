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
 
int padding = RSA_NO_PADDING;
 
RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}
 
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
 
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}


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
  char* enc;

  size_t size;
  size_t enc_size;
  int result;


  	ptr = fopen(argv[1],"r");
	if(ptr==NULL){puts("File Error.\n"); exit(1);}

	//obtain file size
	fseek(ptr,0,SEEK_END);    
	size = ftell(ptr);
	rewind(ptr);

	public_key = malloc(sizeof(char)*(size));
	if(public_key==NULL){puts("Memory Error.\n"); exit(1);}
	result = fread(public_key,1,(size),ptr);
	if(result!=size){puts("Memory Error.\n"); exit(1);}
        fclose(ptr);

   ptr = fopen(argv[2],"r");
	if(ptr==NULL){puts("File Error.\n"); exit(1);}

	//obtain file size
	fseek(ptr,0,SEEK_END);    
	enc_size = ftell(ptr);
	rewind(ptr);

	enc = malloc(sizeof(char)*(enc_size));
	if(enc==NULL){puts("Memory Error.\n"); exit(1);}
	result = fread(enc,1,(enc_size),ptr);
	if(result!=enc_size){puts("Memory Error.\n"); exit(1);}
  fclose(ptr);


unsigned char decrypted[4098]={};
 
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
*                         Decrypt Encrypted Session key      
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
 
int decrypted_length = public_decrypt(enc,enc_size,public_key,decrypted);
if(decrypted_length == -1)
{
    printLastError("Public Decrypt failed");
    exit(0);
}
printf("Obtained Session Key: ");
int k;
for( k = 0; k < 8;k++)
printf("%02x",decrypted[k]);
printf("\n");

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
*                         Hash Session key to derive key/iv      
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

SHA256_CTX ctx;
u_int8_t results[SHA256_DIGEST_LENGTH];
char buf[16];
int n;

memcpy(buf,decrypted,8);
n = 8;
SHA256_Init(&ctx);
SHA256_Update(&ctx, (u_int8_t *)buf, n);
SHA256_Final(results, &ctx);


char sessionKey[8];
char iv[8];
//printf("\n----\n");
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
*                         DES-CBC Encrypt Plaintext using key/iv      
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
char *input_buffer;
ptr = fopen(argv[4],"r");
if(ptr==NULL){puts("File Error.\n"); exit(1);}

//obtain file size
fseek(ptr,0,SEEK_END);    
size = ftell(ptr);
rewind(ptr);

FILE *fp;
fp = fopen("ciphertext.bin","w"); // clears previous text
fclose(fp);

input_buffer = malloc(sizeof(char)*(size));
if(input_buffer==NULL){puts("Memory Error.\n"); exit(1);}
result = fread(input_buffer,1,(size),ptr);
if(result!=size){puts("Memory Error.\n"); exit(1);}
//printf("SIZE IS HERE: %zu\n",size);
CBC_DESEncryption(input_buffer,sessionKey,iv,size);
fclose(ptr);

input_buffer = NULL;


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
*                            Load Private Key    
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

EVP_PKEY *privkey;
   RSA *rsakey;

   /* ---------------------------------------------------------- *
    * Next function is essential to enable openssl functions     *
    ------------------------------------------------------------ */
   OpenSSL_add_all_algorithms();

   privkey = EVP_PKEY_new();

   fp = fopen (argv[3], "r");
   if(fp == NULL) {
	printf("Error reading file.\n");
	exit(0);
   }

   PEM_read_PrivateKey( fp, &privkey, NULL, NULL);

   fclose(fp);

   rsakey = EVP_PKEY_get1_RSA(privkey);

   if(RSA_check_key(rsakey)) {
     printf("RSA key is valid.\n");
   }
   else {
     printf("Error validating RSA key.\n");
   }

   //RSA_print_fp(stdout, rsakey, 3);

   //PEM_write_PrivateKey(stdout,privkey,NULL,NULL,0,0,NULL);


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
*                           Sign SHA256 Ciphertext   
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
   

   char *clearText;

    ptr = fopen("ciphertext.bin","r");
	if(ptr==NULL){puts("File Error.\n"); exit(1);}

	//obtain file size
	fseek(ptr,0,SEEK_END);    
	size = ftell(ptr);
	rewind(ptr);

	clearText = malloc(sizeof(char)*(size));
	if(clearText==NULL){puts("Memory Error.\n"); exit(1);}
	result = fread(clearText,1,(size),ptr);
	if(result!=size){puts("Memory Error.\n"); exit(1);}
  fclose(ptr);


   EVP_MD_CTX* rtx = 0;

	  rtx = EVP_MD_CTX_create();

	  EVP_SignInit_ex( rtx, EVP_sha256(), 0 );

	  EVP_SignUpdate( rtx, clearText, size );

	  const int MAX_LEN = 1024;
	  unsigned char sig[MAX_LEN];
	  unsigned int sigLen;
	  memset(sig, 0, MAX_LEN);

	  EVP_SignFinal( rtx, sig, &sigLen, privkey );

          ptr = fopen("ciphertext.bin.sha256","w");

	  printf( "Got signature\n" );
          fwrite(sig,sizeof(char),sigLen,ptr);

          fclose(ptr);

	  EVP_MD_CTX_destroy( rtx );
	  RSA_free( rsakey );

	  EVP_PKEY_free( privkey );

	  ERR_free_strings(); 
free(clearText);
   
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
*                           HASH SHA256 Ciphertext   
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


SHA256_CTX ctf;
char *cText;



ptr = fopen("ciphertext.bin","r");
if(ptr==NULL){puts("File Error.\n"); exit(1);}

//obtain file size
fseek(ptr,0,SEEK_END);    
size = ftell(ptr);
rewind(ptr);

cText = malloc(sizeof(char)*(size));
if(cText==NULL){puts("Memory Error.\n"); exit(1);}
result = fread(cText,1,(size),ptr);
if(result!=size){puts("Memory Error.\n"); exit(1);}
fclose(ptr);

SHA256_Init(&ctf);
SHA256_Update(&ctf, (u_int8_t *)cText, size);
SHA256_Final(results, &ctf);

/*
int j;
for(j = 0; j < 256/8; j++)
printf("%02x",results[j]);

printf("\n");*/

 ptr = fopen("hash.bin","w");

	  printf( "Got hash.\n" );
          fwrite(results,sizeof(char),256/8,ptr);

 fclose(ptr);

free(cText);
printf("signature -> ciphertext.bin.sha256\nencrypted file -> ciphertext.bin\n");
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


	sign = fopen("ciphertext.bin.sha256","r");
	pub = fopen("localPubKey.pub","r");
	data = fopen("ciphertext.bin","r");
 

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
ptr = fopen("ciphertext.bin","r");
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


	free(public_key);
	free(enc);
return 0;
 
}
