import Crypto.Util.number
import Crypto.Random

def generate_prime_number(bits: int) -> int:
    while True:
        prime_num = Crypto.Util.number.getPrime(bits)
        if prime_num % 4 == 3:
            break

    return prime_num

def get_keys(bits: int) -> tuple:
    p = generate_prime_number(bits)
    q = generate_prime_number(bits)

    while p == q:
        q = generate_prime_number(bits)

    return p, q

def text_to_int(text: str) -> int:
    res = 0

    for i in range(len(text)):
        res = (res + ord(text[i])) << 16

    return res

def int_to_text(value: int) -> str:
    res = []
    while value != 0:
        res.append(chr((value) & 0xFFFF))
        value >>= 16

    res = res[1:]
    return ''.join(res[::-1])

def encrypt_text(p, n):
    p <<= 8
    p |= 0xFF
    return pow(p, 2, n)

def extended_euclidean(p, q):
    if p == 0:
        return q, 0, 1
    else:
        gcd, y, x = extended_euclidean(q % p, p)
        return gcd, x - (q // p) * y, y


def decrpyt_text(c, p, q, n):
    ext_eucl = extended_euclidean(p, q)

    a, b = ext_eucl[1], ext_eucl[2]

    r = pow(c, (p+1) // 4, p) 
    s = pow(c, (q+1) // 4, q) 

    x = int((a * p * s + b * q * r) % n)
    x_1 = n - x 
    y = int((a * p * s - b * q * r) % n)
    y_1 = n - y

    return x, x_1, y, y_1

def find_correct_solution(solutions: list) -> int:

    bit_mask = (1 << 8) - 1
    for sol in solutions:
        n = sol & bit_mask
        if n == 0xFF:
            return sol
        
    return None