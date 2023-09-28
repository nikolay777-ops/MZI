from const import pTable

## TODO
# probably create function for sum by 2**32 modulo, but this slows down
# runtime i guess

## NOTES
# The priorities of the binary bitwise operations are all lower than the
#   numeric operations and higher than the comparisons

# Following functions don't encounter bits beyond first 32 and also don't
# return values beyond [0; 2**32-1]

#performs permutation of 32-bit unsigned integer
def gPermutate(b: int) -> int:
    return pTable[b&0xFF] | pTable[b>>8&0xFF]<<8 | \
            pTable[b>>16&0xFF]<<16 | pTable[b>>24&0xFF]<<24

#performs G5 operation on 32-bit unsigned integer
def gTransform5(w: int) -> int:
    wp = gPermutate(w)
    return wp << 5 | wp >> 32-5

#performs G13 operation on 32-bit unsigned integer
def gTransform13(w: int) -> int:
    wp = gPermutate(w)
    return wp << 13 | wp >> 32-13
    
#performs G21 operation on 32-bit unsigned integer
def gTransform21(w: int) -> int:
    wp = gPermutate(w)
    return wp << 21 | wp >> 32-21


## NOTE
# In following functions addition operations correspond to sum by mod 2**32
#   operations, but it doesn't give different effect, as long as bytes beyond
#   32th can be easily just not encountered.

#encrypts 128-bit block (passed as unsigned int)
def encryptBlock(block: int, subkeys: list) -> int:
    a = block       & 0xFFFFFFFF
    b = block >> 32 & 0xFFFFFFFF
    c = block >> 64 & 0xFFFFFFFF
    d = block >> 96 & 0xFFFFFFFF

    for i in range(8):
        b ^= gTransform5(a + subkeys[8-i & 7])
        c ^= gTransform21(d + subkeys[9-i & 7])
        a -= gTransform13(b + subkeys[10-i & 7])

        e = gTransform21(b + c + subkeys[11-i & 7]) ^ i+1
        b += e
        c -= e

        d += gTransform13(c + subkeys[12-i & 7])
        b ^= gTransform21(a + subkeys[13-i & 7])
        c ^= gTransform5(d + subkeys[14-i & 7])

        a, b, c, d = b, d, a, c

    return (b&0xFFFFFFFF) | (d&0xFFFFFFFF)<<32 | \
            (a&0xFFFFFFFF)<<64 | (c&0xFFFFFFFF)<<96


#decrypts 128-bit block (passed as unsigned int)
def decryptBlock(block: int, subkeys: list) -> int:
    a = block       & 0xFFFFFFFF
    b = block >> 32 & 0xFFFFFFFF
    c = block >> 64 & 0xFFFFFFFF
    d = block >> 96 & 0xFFFFFFFF

    for i in range(7, -1, -1):
        b ^= gTransform5(a + subkeys[14-i & 7])
        c ^= gTransform21(d + subkeys[13-i & 7])
        a -= gTransform13(b + subkeys[12-i & 7])

        e = gTransform21(b + c + subkeys[11-i & 7]) ^ i+1
        b += e
        c -= e

        d += gTransform13(c + subkeys[10-i & 7])
        b ^= gTransform21(a + subkeys[9-i & 7])
        c ^= gTransform5(d + subkeys[8-i & 7])

        a, b, c, d = c, a, d, b

    return (c&0xFFFFFFFF) | (a&0xFFFFFFFF)<<32 | \
            (d&0xFFFFFFFF)<<64 | (b&0xFFFFFFFF)<<96