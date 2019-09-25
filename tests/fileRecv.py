import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket
import os
import byteStreamIO
import hashlib

if __name__ == '__main__':
	f = 'G:\CloudMusic\Aimer - broKen NIGHT.flac'
	publicKey: rsa.PublicKey
	with open('publicKey.pem', 'rb') as pk:
		publicKey = rsa.PublicKey.load_pkcs1(pk.read())
	aes_key = get_random_bytes(32)
	aes = AES.new(aes_key, AES.MODE_CFB)
	# prepare header
	w = byteStreamIO.BytesStreamWriter()
	filename = f
	filesize = os.path.getsize(filename)
	filename = os.path.basename(filename)
	w.write_int(len(filename), 64)
	w.write_str(filename)
	w.write_int(filesize, 64)
	header = w.baseByteArray
	header_len = len(header).to_bytes(8, 'little')
	header = aes.encrypt(header)
	aes_key = rsa.encrypt(aes_key, publicKey)
	aes_iv = rsa.encrypt(aes.iv, publicKey)

	sock = socket.socket()
	sock.connect(('localhost', 6746))
	print(sock.recv(1)[0])
	sock.send(b'\x03')
	print(sock.recv(1)[0])
	sock.send(rsa.encrypt(b'123456', publicKey))
	print(sock.recv(1)[0])
	sock.send(b'\x0B')
	print(sock.recv(1024).decode())
	sock.send(aes_key)
	print(sock.recv(1024).decode())
	sock.send(aes_iv)
	print(sock.recv(1024).decode())
	sock.send(header_len)
	print(sock.recv(1024).decode())
	sock.send(header)
	recv = sock.recv(1024)
	if recv.decode() == 'override?':
		sock.send(b'\x01')
	print(sock.recv(1024).decode())
	block_size = 1024 ** 2
	send_count = 0
	file = open(f, 'rb')
	while send_count < filesize:
		enc = aes.encrypt(file.read(block_size))
		sock.send(enc)
		send_count += block_size
		print(send_count, '/', filesize)
	print(sock.recv(1024))
	# check file
	file = open(f, 'rb')
	md5_checksum = hashlib.md5()
	while True:
		data = file.read(1024**2)
		if not data:
			break
		md5_checksum.update(data)
	file.close()
	md5 = md5_checksum.digest()
	sock.send(md5)
	recv = sock.recv(1)
	sock.close()
	print('Transfer:', recv == b'\xFF')
	input('Press Enter to exit...')
