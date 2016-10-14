

//PARA COMPILAR: gcc RSA.c -o RSA -fopenmp -lcrypto
//Para executar ./RSA x y ---->>> onde y=1 -->> chave de 1024 ou y=2 -->> chave de 2048; 10^(x-1) execuções


//#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <omp.h>

//=====================================================
///////////////////////FILES///////////////////////////

int verify_file (const char *file_name){

	FILE *file;
	file = fopen(file_name,"r");
	if(file){
		return 1;
		fclose(file);
	}else{
		return 0;
	}
}

char *read_file (const char *file_name){

	FILE *file;
	char *text, character;
	int cont = 0;
	if (verify_file(file_name) == 1){

		//Verifying size of file
		file = fopen(file_name, "r");
		while( (character = fgetc(file))!= EOF ){
			cont++;
		}
		fclose(file);

		//Defining string length
		cont++;
		text = (char*) malloc(cont * sizeof(char));

		cont = 0;
		//Reading file/home/pi/.ssh/known_hosts
		file = fopen(file_name, "r");
		while( (character = fgetc(file))!= EOF ){
			*(text + cont) = character;
			cont++;
		}
		fclose(file);
		return text;
	}
	else {
		printf("**ERROR --> Could not find %s **\n", file_name);
	}
}

void write_file (char *text, const char *file_name){

	FILE *file;
	//writing on file
	file = fopen(file_name, "w");
	fprintf(file, "%s", text);
	fclose(file);
}


//=====================================================
////////////////////ENCRYPTION///////////////////////

int generate_keys (int key_bits, const char *file_pub_key, const char *file_priv_key){

	int             ret = 0;
	RSA             *r = NULL;
	BIGNUM          *bne = NULL;
	BIO             *bp_public = NULL, *bp_private = NULL;
	//int             bits = 2048;
	unsigned long   e = RSA_F4;

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		goto free_all;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, key_bits, bne, NULL);
	if(ret != 1){
		goto free_all;
	}
	// 2. save public key
	bp_public = BIO_new_file(file_pub_key, "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
	if(ret != 1){
		//printf("QUALQUER COISA\n\n");
		goto free_all;
	}

	// 3. save private key
	bp_private = BIO_new_file(file_priv_key, "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

	if(ret != 1){
		printf("**ERROR generating symmetric keys**\n");
		goto free_all;
	}

	// 4. Free
	free_all:
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(r);
	BN_free(bne);
	return (ret == 1);
}


char *encrypt_string (char *message,  RSA *pubkey){

	char *encryptedText;




	//defining RSA file
	int size = RSA_size(pubkey);
	int size1;

	encryptedText = (char*)malloc(size);
	memset(encryptedText,'0',size);

	//public key encrypt
	if((size1=RSA_public_encrypt(size,(const unsigned char *)message,(unsigned char *)encryptedText,pubkey,RSA_NO_PADDING))<0){
		printf("**ERROR encrypting message**\n");
		return "ERROR";
	}

	return encryptedText;

	free(encryptedText);
	//free(base_64_encode);
	RSA_free(pubkey);
}

char *decrypt_b64_string (char *b64_encrypted_msg, RSA *privkey){

	char *decryptedText, *cript, *string_decode;

	//defining length
	int size;
	int size1 = RSA_size(privkey);;
	decryptedText=(char*)malloc(size1);
	memset(decryptedText,'0',size1);

	//decrypting message
	if((size=RSA_private_decrypt(size1,(unsigned char *) b64_encrypted_msg,(unsigned char *)decryptedText, privkey, RSA_NO_PADDING))<0)
	{
		printf("**ERROR  decrypting message**\n");
		return "ERROR";
	}

	return (decryptedText);

	free(decryptedText);
	free(cript);
	//free(string_decode);
	RSA_free(privkey);

}


double t_inicial=0, t_final=0;
double t_inicial2=0, t_final2=0;
int aux, repeticoes, cont, execucoes;


int main (int argc,char *argv[]){


	if (argc<2){
		execucoes =1;
	}
	else{
		execucoes=atoi(argv[1]);
	}

	generate_keys (1024, "./pub_1024.pem", "./priv_1024.pem");
	generate_keys(2048, "./pub_2048.pem", "./priv_2048.pem");

	//char *answer_2048, *decode_2048;
	char *answer_2048, *decode_2048;
	char *answer_1024, *decode_1024;
	char text[] =  "texto_simples123";

	if (argv[2][0] == '2'){
		//reading public key
		FILE *pub_2048;
		RSA *pubkey_2048 = NULL;

		pubkey_2048 = RSA_new();
		pub_2048 = fopen("./pub_2048.pem", "r");
		if(PEM_read_RSAPublicKey(pub_2048, &pubkey_2048, NULL, NULL) == NULL){
			printf("**ERROR reading public key**\n");
		}
		fclose(pub_2048);

		//reading private key
		RSA *privkey_2048 = NULL;
		FILE *priv_2048;


		//reading private key
		privkey_2048 = RSA_new();
		priv_2048 = fopen("./priv_2048.pem", "r");
		if(PEM_read_RSAPrivateKey(priv_2048, &privkey_2048, NULL, NULL) == NULL)
		{
			printf("**ERROR reading private key**\n");
		}
		fclose(priv_2048);






		for (aux = 0, cont = 1; aux < execucoes; cont*=10, aux++){
			t_inicial = omp_get_wtime();
			for(repeticoes = 0; repeticoes < cont; repeticoes++){
				answer_2048 =  encrypt_string(text, privkey_2048);
				decode_2048 = decrypt_b64_string(answer_2048, privkey_2048);
			}
			t_final = omp_get_wtime();


			printf("%d\t\t", cont);
			printf("%f\n", (t_final-t_inicial));
		}










	} else {
		//reading public key

		FILE *pub;
		RSA *pubkey = NULL;

		pubkey = RSA_new();
		pub = fopen("./pub_1024.pem", "r");
		if(PEM_read_RSAPublicKey(pub, &pubkey, NULL, NULL) == NULL){
			printf("**ERROR reading public key**\n");
		}
		fclose(pub);

		//reading private key
		RSA *privkey = NULL;
		FILE *priv;


		//reading private key
		privkey = RSA_new();
		priv = fopen("./priv_1024.pem", "r");
		if(PEM_read_RSAPrivateKey(priv, &privkey, NULL, NULL) == NULL)
		{
			printf("**ERROR reading private key**\n");
		}
		fclose(priv);


		for (aux = 0, cont = 1; aux < execucoes; cont*=10, aux++){
			t_inicial2 = omp_get_wtime();
			for(repeticoes = 0; repeticoes < cont; repeticoes++){
				answer_1024 =  encrypt_string(text, pubkey);
				decode_1024 = decrypt_b64_string(answer_1024, privkey);
			}
			t_final2 = omp_get_wtime();

			printf("%d\t\t", cont);
			printf("%f\n", (t_final2-t_inicial2));
		}

	}

	return 0;
}


