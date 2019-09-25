import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket
import os
import byteStreamIO

if __name__ == '__main__':
	publicKey: rsa.PublicKey
	with open('publicKey.pem', 'rb') as pk:
		publicKey = rsa.PublicKey.load_pkcs1(pk.read())
	aes_key = get_random_bytes(32)
	aes = AES.new(aes_key, AES.MODE_CFB)
	# prepare header
	w = byteStreamIO.BytesStreamWriter()
	filename = 'D:\CloudMusic\Chouchou - sign 0.flac'
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
	block_size = 1024 ** 2
	send_count = 0
	file = open('D:\CloudMusic\Chouchou - sign 0.flac', 'rb')
	while send_count < filesize:
		enc = aes.encrypt(file.read(block_size))
		sock.send(enc)
		send_count += block_size
		print(send_count)
