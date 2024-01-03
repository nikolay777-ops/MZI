import sys

import numpy as np
import encoder
import decoder
import keygen


def split_string_into_blocks(input_string):
    current_block = ""
    blocks = []

    for char in input_string:
        char_binary = bin(int(char, 16))[2:].zfill(16)
        current_block += char_binary

    block = []

    for i in range(len(current_block)):
        if len(block) == 4:
            blocks.append(block)
            block = []
        block.append(int(current_block[i]))
    blocks.append(block)

    return blocks


def blocks_into_string(blocks):
    proto_string = ''
    string = ''
    for i in range(len(blocks)):
        for j in range(4):
            proto_string += str(int(blocks[i][j]))

    for i in range(0, len(proto_string), 16):
        delta_string = proto_string[i:i+16]
        string += chr(int(hex(int(delta_string, 2)), 16))

    return string


def main():
    with open('input.txt', 'r', encoding='utf8') as file:
        source_text = file.read()
    bin_text = [hex(ord(elem)) for elem in source_text]
    blocks = split_string_into_blocks(bin_text)

    key_info = keygen.HammingKeygen(3)
    g_prime = key_info.Gcarat

    enc = []
    check = []
    for i in range(len(blocks)):
        encoded = encoder.Encoder(np.array(blocks[i]), g_prime)
        message = encoded.get_message()
        encrypted = encoded.get_encrypted()
        enc.append(encrypted)
        check.append(message)

    dec = []
    for i in range(len(enc)):
        decoded = decoder.Decoder(enc[i], key_info.S, key_info.P, key_info.paritycheck, check[i])
        dec.append(decoded.decrypted)

    dec_string = blocks_into_string(dec)

    enc_string = ''.join([''.join(map(str, map(int, sublist))) for sublist in enc])

    with open('output.txt', 'w', encoding='utf8') as file:
        file.write(enc_string)

    with open('second_output.txt', 'w', encoding='utf8') as file:
        file.write(dec_string)

    return 0


if __name__ == '__main__':
    main()
