Este é um repositório destinado aos códigos de criptografia 
simétrica e assimétrica, ambos utilizam a biblioteca OpenSSL.


Os códigos foram elaborados com o intuito de executar testes 
de comparação entre os dois difentes tipos de criptografia.

Veja como compilar e executar os códigos:


	                    AES					 

+ para compilar: gcc -o AES AES.c -lcrypto -fopenmp              
+ se nao passar parametros: executa uma vez                      
+ Para executar ./AES x y ---->>> onde y=1 -->> chave de 128     
+ ou y=2 -->> chave de 256; 10^(x-1) execuções			 



                      RSA                                  

+ PARA COMPILAR: gcc RSA.c -o RSA -fopenmp -lcrypto              
+ Para executar ./RSA x y ---->>> onde y=1 -->> chave de 1024    
+ ou y=2 -->> chave de 2048; 10^(x-1) execuções                  


