import const
import core

## NOTE
# int.from_bytes defaults to "big"

# Encrypts file named ifname and stores result into file named ofname
#   using given key
def EncryptFile(ifname: str,  ofname: str, key: bytes) -> bytes:
    
    keynum = int.from_bytes(key, "little")
    subkeys =  [keynum >> 32*i & 0xFFFFFFFF for i in range(8)]

    with open(ifname, "rb") as ifile, open(ofname, "wb") as ofile:
        fb = ifile.read()
        lastBlkSize = len(fb) % 16

        blocks = [int.from_bytes(fb[16*i:16*(i+1)], "little") for i in range(len(fb) // 16)]
        if lastBlkSize:
            blocks.append(int.from_bytes(fb[-lastBlkSize:], "little"))

        result = []

        size = len(blocks)
        if lastBlkSize:
            size -= 2
        
        # call this temp register
        treg = const.IV

        # processing all blocks (except for two last ones)
        for i in range(size):
            treg = core.encryptBlock(blocks[i] ^ treg, subkeys)
            result.append(treg)
        
        # processing two last blocks (when the last one is not full)
        if lastBlkSize: 
            YN_2 = result[-3] if len(result) > 2 else const.IV 
            temp = core.encryptBlock(blocks[-2] ^ YN_2, subkeys)
            ofs = len(blocks[-1].to_bytes(16, "little"))
            YN, r = temp & ((1 << ofs) -1), temp >> ofs
            YN_1 = core.encryptBlock(((blocks[-1] ^ YN) << (128-ofs)) | r, subkeys)
            result.append(YN_1)
            result.append(YN)

        response = bytes()
        # There is method that is definitely faster. bytes objects are immutable, so this is absolutely insane
        for i in range(len(result)):
            bit_len = result[i].bit_length() 
            rbytes = (bit_len // 16 + (bit_len % 16 != 0)) * 2
            response += result[i].to_bytes(rbytes, "little")


        ofile.write(response)


# Decrypts file named ifname and stores result into file named ofname
#   using given key
def DecryptFile(ifname: str,  ofname: str, key: bytes) -> bytes:
    
    keynum = int.from_bytes(key, "little")
    subkeys =  [keynum >> 32*i & 0xFFFFFFFF for i in range(8)]

    with open(ifname, "rb") as ifile, open(ofname, "wb") as ofile:
        fb = ifile.read()
        lastBlkSize = len(fb) % 16
        
        blocks = [int.from_bytes(fb[16*i:16*(i+1)], "little") for i in range(len(fb) // 16)]
        if lastBlkSize:
            blocks.append(int.from_bytes(fb[-lastBlkSize:], "little"))

        result = []

        size = len(blocks)
        if lastBlkSize:
            size -= 2
        
        
        # processing all blocks (except for two last ones)
        blocks.append(const.IV) #index -1
        for i in range(size):
            result.append(core.decryptBlock(blocks[i], subkeys) ^ blocks[i-1])
        blocks = blocks[:-1] #removing const.IV from the end

            
        # processing two last blocks (when the last one is not full)
        if lastBlkSize:
            XN_2 = blocks[-3] if len(blocks) > 2 else const.IV
            ofs = len(blocks[-1].to_bytes(16, "little"))
            temp = core.decryptBlock(blocks[-2], subkeys) ^ (blocks[-1] << (128 - ofs))
            YN, r = temp & ((1 << ofs) -1), temp >> ofs
            YN_1 = core.decryptBlock((blocks[-1] << (128 - ofs)) | r, subkeys) ^ XN_2
            result.append(YN_1)
            result.append(YN)

        response = bytes()
        # There is method that is definitely faster. bytes objects are immutable, so this is absolutely insane
        for i in range(len(result)):
            bit_len = result[i].bit_length() 
            rbytes = (bit_len // 16 + (bit_len % 16 != 0)) * 2
            response += result[i].to_bytes(rbytes, "little")


        ofile.write(response)
