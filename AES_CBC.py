from os import wait

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad

def xor(x,y):
    result=[]
    r2=bytearray()
    for i in range(0, len(x)):
        result.append(x[i] ^ y[i])
    r2.extend(result)
    return r2


if __name__ == '__main__':
    BLOCK_SIZE = 16
    key = 'abcdefghijklmnop'
    key_bytes = bytes(key)
    iv = "0000000000000000"
    plaintext = "ConfusionInHerEyesThatSaysItAllShe'sLostControll"
    print (len(plaintext))
    data = bytearray()
    data.extend(plaintext)
    prev_chunk = bytearray()
    prev_chunk.extend(iv)
    encrypted = []
    for i in range(0, len(data), BLOCK_SIZE):
        chunk = data[i:i + BLOCK_SIZE]
        cipher = AES.new(key, AES.MODE_ECB)
        xored = xor(chunk,prev_chunk)
        encrypted_block = cipher.encrypt(xored)
        encrypted += encrypted_block
        prev_chunk = bytearray()
        prev_chunk.extend(encrypted_block)
    print("Encrypted: ", encrypted)

    prev_chunk = bytearray()
    prev_chunk.extend(iv)
    decrypted=[]
    dec=""
    for i in range(0,len(encrypted), BLOCK_SIZE):
        chunk=encrypted[i:i+BLOCK_SIZE]
        str=''
        for a in range(0,len(chunk),1):
            str+=chunk[a]
        decipher=AES.new(key, AES.MODE_ECB)
        decrypted_block=decipher.decrypt(str)
        temp=bytearray()
        temp.extend(decrypted_block)
        xored=xor(temp,prev_chunk)
        decrypted+=xored
        prev_chunk = bytearray()
        prev_chunk.extend(chunk)
    for i in range(0, len(decrypted)):
        dec+=chr(decrypted[i])
    print ("Decrypted: ",dec)