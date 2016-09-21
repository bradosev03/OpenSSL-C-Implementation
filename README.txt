####################################################################
#
#               Openssl Signature and Verification
#
####################################################################

The following program enables a user to sign and encrypt a file using 
DES-CBC-Mode Symmetric Cipher and SHA-256 signed ciphertext.

Both programs must be compiled in unison using the following command:

		         make clean
	          make verify && make sign

To use the signature program enter the following command:

  ./sign [public.key] [encrypted.key] [private key] [file]
  ./sign public.key encrypted.key privatekey.pem outgoing.txt

where public.key is a published public key, encrypted.key is RSA encrypted
session key, privateKey.pem is a locally generated RSA private key and any file
to be encrypted.


To use the verification program enter the following command:

  ./verify sessionKey.txt ciphertext.bin ciphertext.bin.sha256 localPubKey.pub
  ./verify sessionKey.txt ciphertext.bin ciphertext.bin.sha256 localPubKey.pub

where sessionKey.txt is the RSA public Decryption dervied session key, ciphertext.bin
is the encrypted DES-CBC file, ciphertext.bin.sha256 is the SHA256 signed ciphertext
and localPubKey is the locally gerneated RSA public key to verify the private signed 
signature.


You may expect the following output:

robert@kyber:~/Desktop/project 3$ ./sign public.key encrypted.key privatekey.pem outgoing.txt 
Obtained Session Key: d4c3270e00af9e3d
key:
cf3ff5f45d5c596a
iv
95d03f29408d4a80
RSA key is valid.
Got signature
Got hash.
signature -> ciphertext.bin.sha256
encrypted file -> ciphertext.bin


robert@kyber:~/Desktop/project 3$ ./verify sessionKey.txt ciphertext.bin ciphertext.bin.sha256 localPubKey.pub 
key:
cf3ff5f45d5c596a
iv
95d03f29408d4a80
Signature Verified!

**** This is the signed Document output *****





