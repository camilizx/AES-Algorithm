#   Universidade de Brasília 
#   Trabalho 2 - Segurança Computacional - Criptografia AES
#   Alunos: Camila Frealdo Fraga (170007561)
#           José Roberto Interaminense Soares (190130008)


from PIL import Image

#
######   TABELAS ÚTEIS ########
#

# Substituição de Bytes (parte da rodada - Cifração)
s_box_table = [                                
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
# Substituição de Bytes (parte da rodada - Decifração)
inverse_s_box_table = [                        
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]
# Substituição - Mix Column (parte da rodada que cifra)
mix_column_table = [        
  [2, 3, 1, 1],
  [1, 2, 3, 1],
  [1, 1, 2, 3],
  [3, 1, 1, 2]
]
# Substituição - Mix Column (parte da rodada que decifra)
inverse_mix_column_table = [
  [0x0E, 0x0B, 0x0D, 0x09],
  [0x09, 0x0E, 0x0B, 0x0D],
  [0x0D, 0x09, 0x0E, 0x0B],
  [0x0B, 0x0D, 0x09, 0x0E]
]
# Substituição de bits para expansão de chave
rcon_table = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39
]

#
############# FUNÇÕES AUXILIARES #############
#

# Recebe lista de inteiros e retorna lista de hexadecimais
def to_hex(val):
    if isinstance(val, list):
        return [to_hex(item) for item in val]
    elif isinstance(val, int):
        return hex(val)
    else:
        return val 
# Transpõe uma matriz
def transposed(matrix):
    return [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0]))]
# Xor entre duas listas
def xor(a, b):
    return [a[i] ^ b[i] for i in range(len(a))]
#
############# EXPANSÃO DA CHAVE #############
#

def rot_word(word):
	return word[1:] + word[:1]

def sub_word(word, table):
    return [table[b] for b in word]  

def rcon(word, round):
    rcon_table_round = [rcon_table[round], 0x00, 0x00, 0x00]
    for i in range(4):
        word[i] ^= rcon_table_round[i]
    return word

def key_expansion(key, rounds):
    w = [[] for _ in range(4 * (rounds + 1))]                  #Declarando lista de listas que armazena as chaves
    round = 0

    for i in range(4):
        w[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]   #Preenche as primeiras 4 chaves com a chave original

    for i in range(4, 4*(rounds+1)):
        if i % 4 == 0:
            round += 1
            temp = rcon(sub_word(rot_word(w[i-1]), s_box_table), round)
            for j in range(4):
                w[i].append(temp[j] ^ w[i-4][j])
        else:
            for j in range(4):
                w[i].append(w[i-4][j] ^ w[i-1][j])
    return w
#
############# RODADAS #############
#
def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def byte_sub(state):
    return [[s_box_table[b] for b in row] for row in state]

def inv_byte_sub(state):
    return [[inverse_s_box_table[b] for b in row] for row in state]
    
def shift_row(state):
    for i in range(4):
        state[i] = state[i][i:] + state[i][:i]
    return state

def inv_shift_row(state):
    for i in range(4):
        state[i] = state[i][-i:] + state[i][:-i]
    return state

def galois_field_multiplication(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B  # Este é o polinômio irredutível x^8 + x^4 + x^3 + x + 1 em hexadecimal
        b >>= 1
    return result

def mix_column(state):
    mixed_state = [[0 for _ in range(4)] for _ in range(4)]
    for row in range(4):
        for col in range(4):
            mixed_state[row][col] = (
                (galois_field_multiplication(mix_column_table[row][0], state[0][col])) ^
                (galois_field_multiplication(mix_column_table[row][1], state[1][col])) ^
                (galois_field_multiplication(mix_column_table[row][2], state[2][col])) ^
                (galois_field_multiplication(mix_column_table[row][3], state[3][col]))
            )
    return mixed_state

def inv_mix_column(state):
    mixed_state = [[0 for _ in range(4)] for _ in range(4)]
    for row in range(4):
        for col in range(4):
            mixed_state[row][col] = (
                (galois_field_multiplication(inverse_mix_column_table[row][0], state[0][col])) ^
                (galois_field_multiplication(inverse_mix_column_table[row][1], state[1][col])) ^
                (galois_field_multiplication(inverse_mix_column_table[row][2], state[2][col])) ^
                (galois_field_multiplication(inverse_mix_column_table[row][3], state[3][col]))
            )
    return mixed_state

def cypher(state, key, rounds):
    #rodada inicial
    state = add_round_key(transposed(state), transposed(key[0:4]))
    
    #rodadas (1 até n-1)
    for round in range (1,rounds):
        state = byte_sub(state)
        state = shift_row(state)
        state = mix_column(state)
        state = add_round_key(state, transposed(key[(round)*4:(round+1)*4]))
        
    #rodada final
    state = byte_sub(state)
    state = shift_row(state)
    state = add_round_key (state, transposed(key[(rounds)*4:(rounds+1)*4]))
    
    return [element for row in transposed(state) for element in row]

def decypher(state, key, rounds):
    #rodada inicial
    state = add_round_key(transposed(state), transposed(key[(rounds)*4:(rounds+1)*4]))

    #rodadas (1 até n-1)
    for round in range (rounds-1, 0, -1):
        state = inv_shift_row(state)
        state = inv_byte_sub(state)
        state = add_round_key(state, transposed(key[(round)*4:(round+1)*4]))
        state = inv_mix_column(state)

    #rodada final
    state = inv_shift_row(state)
    state = inv_byte_sub(state)
    state = add_round_key (state, transposed(key[0:4]))
    
    return [element for row in transposed(state) for element in row]

def increment_counter(counter):
    carry = 1
    for i in range(len(counter) - 1, -1, -1):
        counter[i] += carry
        carry = counter[i] >> 8  # Verifica se houve transporte
        counter[i] &= 0xFF  # Mantém apenas os 8 bits menos significativos
    return counter

def decrement_counter(counter):
    carry = 1
    for i in range(len(counter) - 1, -1, -1):
        counter[i] -= carry
        carry = counter[i] >> 8  # Verifica se houve transporte
        counter[i] &= 0xFF  # Mantém apenas os 8 bits menos significativos
    return counter

# [[84, 119, 111, 32, 79, 110, 101, 32, 78, 105, 110, 101, 32, 84, 119, 97], [84, 119, 111, 32, 79, 110, 101, 32, 78, 105, 110, 101, 32, 84, 119, 97]]
def ctr_mode(text_blocks, key, rounds):
    counter = [0] * 16  # Inicializa o contador como um bloco de 16 bytes com todos os bytes igual a 0
    cypher_result = []
    for block in text_blocks:
        counter_matrix = [counter[i:i+4] for i in range(0, len(counter), 4)]             
        counter_cypher = cypher(counter_matrix, key, rounds)
        cypher_block = xor(counter_cypher, block)
        counter = increment_counter(counter)
        cypher_result.append(cypher_block)
    return  cypher_result

def text_to_bytes(text):
    text = [text[i:i + 16] for i in range(0, len(text), 16)]
    if len(text[-1]) < 16:
        text[-1] += '\0' * (16 - len(text[-1]))
    text = [[ord(char) for char in block] for block in text]
    return text 

def main():
    #operation = input('Bem vindo ao AES! Escolha o modo de operação: \n 1 - Cifrar \n 2 - Decifrar \n')

    #rounds = int(input('Digite o número de rodadas: '))
    rounds = 10
    #key = input('Digite a chave: ')
    key = "Thats my Kung Fu"
    #plaintext = input('Digite o texto: ')
    plaintext = "Cestando o modo CTR para ver se da certo essa criptografia louca"

    key = text_to_bytes(key)                                            #key para bytes (hexadecimal)
    key_expanded = key_expansion(key[0], rounds)

    plaintext = text_to_bytes(plaintext)                                #plaintext para bytes (hexadecimal)
    #TESTE MODO NORMAL
    # print ("Test Normal Mode")           
    # plaintext_normalmode = [plaintext[0][i:i+4] for i in range(0, len(plaintext[0]), 4)]
    # cypher_text = cypher(plaintext_normalmode, key_expanded, rounds)   
    # print (to_hex(cypher_text))

    #TESTE MODO CTR
    print ("Test CTR Mode")
    cypher_text_ctr = ctr_mode(plaintext, key_expanded, rounds)             #modo ctr
    print (to_hex(cypher_text_ctr))

    # TESTE OPENSSL
    with open('cifra.enc', 'rb') as file:
       openssl_result = file.read()
    formatted_result = [f'0x{byte:02x}' for byte in openssl_result]
    print(formatted_result)

    # TESTE IMAGEM
    #image = Image.open('cinnamoroll-ctr.bmp')

    #rgb_values = list(image.getdata())

    #print (rgb_values)

    #flattened_values = [value for tup in rgb_values for value in tup]

    # #Cut plaintext in blocks of 16
    # formated_flattened_values = [flattened_values[i:i + 16] for i in range(0, len(flattened_values), 16)]

    # # Se o ultimo bloco tiver menos de 16 caracteres, preenche com 0
    # if len(formated_flattened_values[-1]) < 16:
    #     formated_flattened_values[-1] += '\0' * (16 - len(formated_flattened_values[-1]))

    #ciphered_text = ctr_mode(flattened_values, key_expanded, rounds)

    #print(ciphered_text)

    # Cifre os bytes da imagem
    #ciphertext = ctr_mode(image_bytes, key_expanded, rounds)

    # with open('imagem_cifrada.bin', 'wb') as file:
    #     file.write(ciphertext)

    # # Crie uma nova imagem a partir dos bytes cifrados
    # encrypted_image = Image.frombytes(image.mode, image.size, ciphertext)

    # # Salve a imagem cifrada
    # encrypted_image.save('imagem_cifrada.jpg')

    # # Feche a imagem original
    # image.close()

if __name__ == '__main__':
    while True:
        main()
        continue_execution = input('Continuar a execução? [y/n]? ').lower()
        if continue_execution != 'y':
            break                 
