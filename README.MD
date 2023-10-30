# Universidade de Brasília 
## Trabalho 2 - Segurança Computacional - Criptografia AES
## Alunos:
- Camila Frealdo Fraga (170007561)
- José Roberto Interaminense Soares (190130008)

## Descrição
Este projeto implementa o algoritmo de criptografia AES (Advanced Encryption Standard) em Python. O AES é um algoritmo de cifragem amplamente utilizado para proteger informações confidenciais. Ele opera em blocos de dados e suporta chaves de diferentes tamanhos (128, 192 e 256 bits).

## Arquivos e Estrutura do Projeto
As principais funções encontradas são:
- `main.py`: O arquivo principal contendo a implementação do AES e as funções de criptografia e descriptografia.
- `ctr_mode`: Função que implementa o modo de operação CTR.
- `cypher.txt`: Função que cifra com o AES.
Algumas funções auxiliares também foram implementadas:
- `to_hex`: Converte uma lista de inteiros para hexadecimal, utilizado no debug do programa.
- `transposed`: Transpõe uma matriz.
- `xor`: Realiza a operação XOR entre duas matrizes.
- `text_to_bytes`: Converte a entrada (texto) para bytes.

## Uso
Para cifrar/decifrar um arquivo de texto, execute o comando `python main.py`. O programa solicitará algumas informações:
- O tipo de operação (cifrar ou decifrar)
- O arquivo de entrada (se será do tipo `.txt` ou `.bmp`)
- O nome do arquivo que será cifrado/decifrado
- O número de rodadas a serem executadas
- Escolher a chave diretamente como texto (Ex: Thats my Kung Fu) ou em formato hexadecimal (Ex: 5468617473206d79204b756e67204675)
- Por fim, digitar a chave (o tamanho da chave não deve exceder 16 bytes).
 
O texto que você deseja cifrar ficará salvo no arquivo `cypher.txt`

O texto que você deseja decifrar ficará salvo no arquivo `decypher.txt`

IMPORTANTE: Caso queira se utilizar a função de decifrar, é necessário que o arquivo `.txt` contenha os bytes em hexadecimal, juntos. Caso contrário, o programa não funcionará.

Se você deseja cifrar uma imagem (formato BMP) o resultado será uma nova imagem cifrada, de saída `cypher-image.bmp`. Para verificar a corretude do programa, baixe o OpenSSL. Deve se comparar o resultado do arquivo `cypher.txt` com o resultado do arquivo gerado pelo OpenSSL, utilizando os valores obtidos dos hash de cada um, caso eles coincidam: EUREKA!

Para gerar o arquivo de imagem cifrado pelo OpenSSL, utilize o comando:
- openssl enc -aes-128-ctr -in nomeimagem.bmp -out cypher.enc -K suachaveemhexadecimal -iv 00000000000000000000000000000000 -p

Em cypher.enc teremos o arquivo cifrado pelo OpenSSL.

Para obter o hash do arquivo cypher.enc:
- get-filehash .\cypher.enc

Para obter o hash do arquivo `cypher.txt` (saída do nosso programa, quando ciframos uma imagem.bmp):
- get-filehash .\cypher.txt

## Nota
Este projeto é destinado apenas para fins educacionais e demonstrativos. O AES é um algoritmo de criptografia robusto, mas a segurança depende de várias outras considerações além do código-fonte.

## Referências
- [NIST FIPS PUB 197](https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf): Padrão oficial do AES do NIST (Inglês).
- [Implementação de AES em Python](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard): Página da Wikipedia com informações adicionais sobre o AES.