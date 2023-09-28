from cbc import EncryptFile, DecryptFile

KEY = 0xAAAABBBBCCCCDDDD

def main():
    EncryptFile('README.md', 'enc-README.md', KEY.to_bytes(256, 'little'))
    DecryptFile('enc-README.md', 'dec-README.md', KEY.to_bytes(256, 'little'))

main()