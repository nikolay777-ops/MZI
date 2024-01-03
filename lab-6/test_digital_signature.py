import digital_signature

p = 17
q = 19
public_key, private_key = digital_signature.generate_key_pair(p, q)
print('Open Key: ', public_key)

with open('source.txt', 'r') as file:
    source_text = file.read()

hash = digital_signature.hash_function(source_text)
encrypted = digital_signature.encrypt(private_key, hash)
decrypted = digital_signature.decrypt(public_key, encrypted)
print('Encrypted hash ', encrypted)
print('Decrypted hash: ', decrypted)

if digital_signature.verify(public_key, encrypted, hash):
    print('Accept')
else:
    print('Not accept')