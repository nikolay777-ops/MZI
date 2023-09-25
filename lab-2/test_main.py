from main import encrypt, decrypt

key = 'key'
block = 4

with open('source.txt', 'r') as file:
    source_text = file.read()

encrypted_text = encrypt(source_text, key)
decrypted_text = decrypt(encrypted_text, key)

print('Source text: ', source_text)
print('Encrypted text: ', encrypted_text)
print('Decrypted text: ', decrypted_text)