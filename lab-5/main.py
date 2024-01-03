import sys

from gost import split_string_into_blocks, hash_gost, CHANGE_TABLE
from md_5 import md5


def main():
    with open('in.txt', 'r', encoding='utf8') as file:
        source_text = file.read()

    bin_text = [hex(ord(elem)) for elem in source_text]
    blocks, last_len = split_string_into_blocks(bin_text, 256)

    print(f'Gost: {hex(hash_gost(blocks, CHANGE_TABLE, last_len))}')

    resp = md5(source_text)

    print(f'MD 5: {resp}')


if __name__ == '__main__':
    main()
