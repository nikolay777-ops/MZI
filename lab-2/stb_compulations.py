
def g_convert(n, proto, change_table):
    protos = [(proto >> (8 * i)) & 0xFF for i in range(4)]
    protos.reverse()

    for i in range(4):
        delta = format(protos[i], '02X')
        protos[i] = change_table[int(delta[0], 16)][int(delta[1], 16)]

    proto = (protos[0] << 24) | (protos[1] << 16) | (protos[2] << 8) | protos[3]
    proto = (proto << n) | (proto >> (32 - n))
    return proto


def minus_square(a, b, n):
    return (a - b) % 2**n


def plus_square(a, b, n):
    return (a + b) % 2**n


def encrypt_cycle(key, block, change_table):
    blocks = [(block >> (32 * i)) & 0xFFFFFFFF for i in range(4)]
    keys = [(key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]

    blocks.reverse()
    keys.reverse()

    a = blocks[0]
    b = blocks[1]
    c = blocks[2]
    d = blocks[3]

    for i in range(1, 9):
        b = b ^ g_convert(5, plus_square(a, keys[(7*i - 6) % 8], 32), change_table)
        c = c ^ g_convert(21, plus_square(d, keys[(7*i - 5) % 8], 32), change_table)
        a = minus_square(a, g_convert(13, plus_square(b, keys[(7*i - 4) % 8], 32), change_table), 32)
        e = g_convert(21, plus_square(plus_square(b, c,  32), keys[(7*i - 3) % 8], 32), change_table) ^ i
        b = plus_square(b, e, 32)
        c = minus_square(c, e, 32)
        d = plus_square(d, g_convert(13, plus_square(c, keys[(7*i - 2) % 8], 32), change_table), 32)
        b = b ^ g_convert(21, plus_square(a, keys[(7*i - 1) % 8], 32), change_table)
        c = c ^ g_convert(5, plus_square(d, keys[(7*i) % 8], 32), change_table)
        a, b = b, a
        c, d = d, c
        b, c = c, b
    y = (b << 96) | (d << 64) | (a << 32) | c
    return y


def decrypt_cycle(key, block, change_table):
    blocks = [(block >> (32 * i)) & 0xFFFFFFFF for i in range(4)]
    keys = [(key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]

    blocks.reverse()
    keys.reverse()

    a = blocks[0]
    b = blocks[1]
    c = blocks[2]
    d = blocks[3]

    for i in range(8, 0, -1):
        b = b ^ g_convert(5, plus_square(a, keys[(7 * i) % 8], 32), change_table)
        c = c ^ g_convert(21, plus_square(d, keys[(7 * i - 1) % 8 - 1], 32), change_table)
        a = minus_square(a, g_convert(13, plus_square(b, keys[(7 * i - 2) % 8 - 1], 32), change_table), 32)
        e = g_convert(21, plus_square(plus_square(b, c, 32), keys[(7 * i - 3) % 8 - 1], 32), change_table) ^ i
        b = plus_square(b, e, 32)
        c = minus_square(c, e, 32)
        d = plus_square(d, g_convert(13, plus_square(c, keys[(7 * i - 4) % 8 - 1], 32), change_table), 32)
        b = b ^ g_convert(21, plus_square(a, keys[(7 * i - 5) % 8 - 1], 32), change_table)
        c = c ^ g_convert(5, plus_square(d, keys[(7 * i - 6) % 8 - 1], 32), change_table)
        a, b = b, a
        c, d = d, c
        a, d = d, a
    y = (c << 96) | (a << 64) | (d << 32) | b
    return y


def get_bit_length(number):
    if number < 0:
        number = abs(number)
    return number.bit_length()


def stb_block_couple_encrypt(key, sync_mail, blocks, change_table, rec, sizes):
    y = [encrypt_cycle(key, sync_mail, change_table)]
    bl_end = len(blocks) - 1
    length = sizes[-1]

    for i in range(len(blocks)):
        if length < 128:
            if i <= bl_end - 2:
                y.append(encrypt_cycle(key, blocks[i] ^ y[i], change_table))
            else:
                proto = encrypt_cycle(key, blocks[bl_end - 1] ^ y[bl_end - 1], change_table)
                diff = 128 - get_bit_length(blocks[i])
                proto = (proto << diff) | (rec & ((1 << diff) - 1))
                y.append(0)
                y.append(proto)

                delta = blocks[bl_end] ^ y[bl_end + 1]
                diff = 128 - get_bit_length(delta)
                delta = (delta << diff) | (rec & ((1 << diff) - 1))
                y[bl_end] = encrypt_cycle(key, delta, change_table)

                break
        else:
            y.append(encrypt_cycle(key, blocks[i] ^ y[i], change_table))

    return y[1:]


def stb_block_couple_decrypt(key, sync_mail, blocks, change_table, rec, sizes):
    y = []
    bl_end = len(blocks)
    blocks.insert(0, encrypt_cycle(key, sync_mail, change_table))
    length = sizes[-1]

    for i in range(1, bl_end + 1):
        if length < 128:
            if i <= bl_end - 2:
                y.append(decrypt_cycle(key, blocks[i], change_table) ^ blocks[i - 1])
            else:
                diff = 128 - get_bit_length(blocks[i])
                proto = (decrypt_cycle(key, blocks[bl_end - 1], change_table) ^ (blocks[bl_end] << diff)
                         | (0 & ((1 << diff) - 1)))
                y.insert(bl_end, (proto << diff) | (rec & ((1 << diff) - 1)))

                diff = 128 - get_bit_length(blocks[bl_end])
                delta = (blocks[bl_end] << diff) | (rec & ((1 << diff) - 1)) ^ blocks[bl_end - 2]

                y.insert(bl_end - 1, decrypt_cycle(key, delta, change_table))

                break
        else:
            y.append((decrypt_cycle(key, blocks[i], change_table)) ^ blocks[i - 1])
    return y
