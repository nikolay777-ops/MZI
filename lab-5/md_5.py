import math

rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

functions = 16 * [lambda b, c, d: (b & c) | (~b & d)] + \
            16 * [lambda b, c, d: (d & b) | (~d & c)] + \
            16 * [lambda b, c, d: b ^ c ^ d] + \
            16 * [lambda b, c, d: c ^ (b | ~d)]

index_functions = 16 * [lambda i: i] + \
                  16 * [lambda i: (5 * i + 1) % 16] + \
                  16 * [lambda i: (3 * i + 5) % 16] + \
                  16 * [lambda i: (7 * i) % 16]

CONSTANTS = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]

init_values = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF


def md5(message):
    message = bytearray(message.encode())

    orig_len_in_bits = (8 * len(message)) & 0xffffffffffffffff

    message.append(0x80)

    # дополняем длину сообщения
    while len(message) % 64 != 56:
        message.append(0)

    # шаг 2. Дописываем 64-битное представление длины данных до выравнивания
    message += orig_len_in_bits.to_bytes(8, byteorder='little')

    # задаём итоговый хэш-буффер
    hash_pieces = init_values[:]

    # проводим раунды хэширования, суммируем результаты каждого последующего раунда, добавляем константу для каждого шага
    for chunk_ofst in range(0, len(message), 64):
        a, b, c, d = hash_pieces
        chunk = message[chunk_ofst:chunk_ofst + 64]

        for i in range(64):
            f = functions[i](b, c, d)
            g = index_functions[i](i)
            to_rotate = a + f + CONSTANTS[i] + int.from_bytes(chunk[4 * g:4 * g + 4], byteorder='little')
            new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF
            a, b, c, d = d, new_b, b, c

        for i, val in enumerate([a, b, c, d]):
            hash_pieces[i] += val
            hash_pieces[i] &= 0xFFFFFFFF

    raw = sum(x << (32 * i) for i, x in enumerate(hash_pieces)).to_bytes(16, byteorder='little')
    return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))
