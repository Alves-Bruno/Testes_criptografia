/*
 * AES.c
 *
 *  Created on: Sep 1, 2016
 *      Author: bruno
 */



// para compilar: gcc -o AES AES.c -lcrypto -fopenmp
// se nao passar parametros: executa uma vez
// Para executar ./AES x y ---->>> onde y=1 -->> chave de 128 ou y=2 -->> chave de 256; 10^(x-1) execuções

#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <omp.h>

static const unsigned char key_256[] = "01234567891234560123456789123456";
static const unsigned char key_128[] = "0123456789123456";
int execucoes, cont;
double t_inicial=0, t_final=0;
int aux, repeticoes;

int main(int argc,char *argv[])
{
	if (argc<2){
		execucoes =1;
	}
	else{
		execucoes=atoi(argv[1]);
	}

	const unsigned char text[]="0123456789123456";
	unsigned char criptografado[17];
	unsigned char decriptografado[17];

	AES_KEY enc_key, dec_key;

	if (argv[2][0] == '1'){
		// setar chave
		AES_set_encrypt_key(key_128, 128, &enc_key);
		AES_set_decrypt_key(key_128, 128, &dec_key);

	}
	else {
		// setar chave
		AES_set_encrypt_key(key_256, 256, &enc_key);
		AES_set_decrypt_key(key_256, 256, &dec_key);

	}

	for (aux = 0, cont = 1; aux < execucoes; cont*=10, aux++){
		t_inicial = omp_get_wtime();
		//printf("************%d\n", cont);
		for(repeticoes = 0; repeticoes < cont; repeticoes++){

			//  criptogtrafar
			AES_encrypt(text, criptografado,&enc_key);
			criptografado[16]='\0';


			// decriptografar
			AES_decrypt(criptografado,decriptografado, &dec_key);
			decriptografado[16]='\0';

		}
		t_final = omp_get_wtime();
		printf("%d\t\t", cont);
		printf("%f\n", (t_final-t_inicial));

	}


	return 0;
}

