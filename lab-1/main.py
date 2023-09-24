from functools import reduce

KEY = 'qwertyYTREWQ12345678()*&^%$#@!!~'
SYNC_MSG = 'fdsfTtew'
C1 = 0x1010101
C2 = 0x1010104
BLOCK_SIZE = 4

# Идентификатор: id-Gost28147-89-CryptoPro-D-ParamSet
EXCH_TAB = [
    [0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3],
    [0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1],
    [0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2],
    [0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8],
    [0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1],
    [0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6],
    [0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7],
    [0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE]
]

def parse_bits(bits: list) -> list:
    return [ bit.replace(' ', '0') if bit.__contains__(' ') else bit
        for bit in bits
    ]

def prepare_keys():

    keys = [
        [format(ord(j), '08b') for j in KEY[i:i+4]]
        for i in range(len(KEY)-4, -4, -4)
    ]
    keys = [
        f"{key[0]}{key[1]}{key[2]}{key[3]}"
        for key in keys
    ]

    return keys

def prepare_sync_msg(text: str):

    msg = [
        [format(ord(j), '08b') for j in text[i:i+4]]
        for i in range(len(text)-4, -4, -4)]

    msg = [
        f''.join(m)
        for m in msg]

    return msg 

def sum_bits_32(first: bin, second: bin):
    int_sum = int(first, 2) + int(second, 2)

    return format(int_sum, '32b')

def sum_bits_32_1(first: bin, second: bin):
    int_sum = int(first, 2) + int(second, 2)

    while int_sum >= (1 << 32):
        int_sum = (int_sum & 0xFFFFFFFF) + (int_sum >> 32)

    return format(int_sum, '32b')

def split_block(block: str) -> list: 
    return [block[i:i+4] for i in range(0, len(block), 4)]

def get_dec_key(index: int):
    return index % 8 if index < 8 else 7 - index % 8

def get_enc_key(index: int):
    return index % 8 if index < 24 else 7 - index % 8
        
def move_block_by_table(block: str) -> list:
    nums = split_block(block)

    for i in range(len(nums)):
        nums[i] = format(EXCH_TAB[i][int(nums[i], 2)], '04b')

    return ''.join(nums)

def xor_values(first: str, second: str) -> str:

    size = len(first)
    result = int(first, 2) ^ int(second, 2)
    result = format(result, f'{size}b')

    return result


def simple_change(text_block: list, keys: list, key_func) -> str:
    left, right = text_block[0], text_block[1]

    for i in range(32):
        key = keys[key_func(i)]
        
        enc = sum_bits_32(left, key)[-32:]
        enc = move_block_by_table(enc)

        enc = int(enc, 2)
        enc = format((enc << 11), '32b')[-32:]
        enc = xor_values(enc, right)

        if i < 31:
            right = left
            left = enc
        else:
            right = enc

    return left, right

def change_gamma(gamma: list) -> list:
    left, right = gamma[0], gamma[1]
    parsed_c1 = format(C1, '32b')
    parsed_c2 = format(C2, '32b')

    new_right = sum_bits_32(right, parsed_c2)[-32:]
    new_left = sum_bits_32_1(left, parsed_c1)[-32:]

    return new_left, new_right

def get_gamma(gamma: list, keys: list) -> list:
    if len(gamma) == 0:
        msg = prepare_sync_msg(SYNC_MSG)
        left_block, right_block = simple_change(msg, keys, get_enc_key)
    else:
        left_block, right_block = gamma[0], gamma[1]
    
    left_block, right_block = change_gamma([left_block, right_block])    
    left_block, right_block = simple_change([left_block, right_block], keys, get_enc_key)
        
    if left_block.__contains__(' '):
        left_block = left_block.replace(' ', '0')
    
    if right_block.__contains__(' '):
        right_block = right_block.replace(' ', '0')
    

    return left_block, right_block

def text_to_binary(text: str, encode=False) -> str:
    result = []

    if encode:
        bits = '08b'
    else:
        bits = '16b'

    for txt in text:
        for t in txt:
            result.append(
                format(ord(t), bits))

    if encode and len(result) > 1:
        new_result = []        

        for i in range(0, len(result), 2):
            new_result.append(
                result[i] + result[i+1])

        result = new_result

    return parse_bits(result)

def process_text(text: str, gamma: list, encode=False) -> str:
    keys = prepare_keys()
    
    new_text = ''.join(text_to_binary(text, encode))
    gamma = get_gamma(gamma, keys)
    gamma = f'{gamma[0]}{gamma[1]}'
    
    if encode and len(text) % 8 != 0:
        gamma = gamma[:8*len(text)]
    elif len(text) % 4 != 0:
        gamma = gamma[:16*len(text)]

    encoded_text = xor_values(new_text, gamma)

    return encoded_text.replace(' ', '0'), gamma

def binary_to_text(binary: str, bit_size=None) -> str:
    result_str = ''
    
    if bit_size is None:
        bit_size = 8

    for i in range(0, len(binary), bit_size):
        result_str += chr(int(binary[i:i+bit_size], 2))

    return result_str

def encode_file(filename: str, bit_size=None):
    encode = False
    gamma = []

    if bit_size is not None:
        encode = True

    with open(f'enc-{filename}.txt', 'w') as output_file:

        with open(f'{filename}.txt', 'r') as input_file:
            block_size = BLOCK_SIZE
            if encode:
              block_size *= 2

            text = input_file.read(block_size)

            while text:
                
                result, gamma = process_text(text, gamma, encode)

                output_file.write(binary_to_text(result, bit_size))
                text = input_file.read(block_size)

            input_file.close()

    output_file.close()


def main():
    encode_file('text')
    encode_file('enc-text', 16)

if __name__ == "__main__":
    main()