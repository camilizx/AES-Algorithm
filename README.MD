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
Para cifrar um arquivo de texto, execute o arquivo `main.py`. O programa solicitará informações, como o tipo de operação (cifrar ou decifrar), o arquivo de entrada e o número de rodadas a serem executadas. Você também pode escolher inserir a chave diretamente como texto ou em formato hexadecimal.

Se você deseja cifrar uma imagem (formato BMP), escolha a opção correspondente ao tipo de arquivo durante a execução do programa. O resultado será uma nova imagem cifrada, de saída `cypher-image.bmp`. Além disso, caso se queira comparar o hash gerado pelo OpenSSL, o binário estará em `cypher.txt`.

Após a conclusão da operação, o programa salvará o resultado no arquivo `cypher.txt`, `deciphered.txt` ou `cypher-image.bmp` dependendo da operação.

IMPORTANTE: Caso queira se utilizar a função de decifrar, é necessário que o arquivo txt contenha os bytes em hexadecimal, juntos. Caso contrário, o programa não funcionará.

## Nota
Este projeto é destinado apenas para fins educacionais e demonstrativos. O AES é um algoritmo de criptografia robusto, mas a segurança depende de várias outras considerações além do código-fonte.

## Referências
- [NIST FIPS PUB 197](https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf): Padrão oficial do AES do NIST (Inglês).
- [Implementação de AES em Python](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard): Página da Wikipedia com informações adicionais sobre o AES.

