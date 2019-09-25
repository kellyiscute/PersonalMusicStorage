import rsa
import os
import byteStreamIO
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

filename = input('Filepath: ')
password = input('Password: ')
with open('publicKey.pem', 'rb') as pem:
    publicKey = rsa.PublicKey.load_pkcs1(pem.read())

aes_key = get_random_bytes(32)
aes = AES.new(aes_key, AES.MODE_CFB)
aes_iv = aes.iv
file_size = os.path.getsize(filename)
filename = os.path.basename(filename)
filename_length = len(filename)

# save encrypted password
with open('pwd', 'wb') as p:
    p.write(rsa.encrypt(password.encode('utf-8'), publicKey))
# save aes info
with open('aes.key', 'wb') as k:
    k.write(rsa.encrypt(aes_key, publicKey))
with open('aes.iv', 'wb') as v:
    v.write(rsa.encrypt(aes_iv, publicKey))
# build header
writer = byteStreamIO.BytesStreamWriter()
writer.write_int(filename_length, 64)
writer.write_str(filename)
writer.write_int(file_size, 64)
# encrypt and write
with open('header', 'wb') as h:
    h.write(aes.encrypt(writer.baseByteArray))
with open('header.len', 'wb') as hl:
    hl.write(len(writer.baseByteArray).to_bytes(8, 'little'))
