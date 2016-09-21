COMPILER = gcc

sign:   BitPermutationFunctions.c DESEncrypt.c FileReader.c DataPrint.c CBCDESEncryption.c sign.c
	gcc -I. -o sign BitPermutationFunctions.c DESEncrypt.c FileReader.c DataPrint.c keyReader.c CBCDESEncryption.c sign.c -lcrypto

verify:   BitPermutationFunctions.c DESDecrypt.c FileReader.c DataPrint.c keyReader.c CBCDESDecryption.c verify.c
	gcc -I. -o verify BitPermutationFunctions.c DESDecrypt.c FileReader.c DataPrint.c keyReader.c CBCDESDecryption.c verify.c -lcrypto

clean:
	rm verify && rm sign 
	echo Clean Done




