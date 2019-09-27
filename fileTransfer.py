import socket
import rsa
import os
import byteStreamIO
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# header structure
# filename length  Int64
# filename         UTF-8
# file length      Int64


def recv(sock: socket.socket, priv: rsa.PrivateKey):
	# recv encrypted password & filename
	sock.send(b'aes_pwd')
	# aes password is rsa encrypted, length unknown
	aes_password = rsa.decrypt(sock.recv(10240), priv)
	# ask for aes iv, encrypted with rsa
	sock.send(b'iv')
	aes_iv = rsa.decrypt(sock.recv(10240), priv)
	# ask for header length, not encrypted
	sock.send(b'header_len')
	header_size = int.from_bytes(sock.recv(8), 'little')
	# ask for header, encrypted by aes
	sock.send(b'header')
	# decrypt header
	aes_cipher = AES.new(aes_password, AES.MODE_CFB, iv=aes_iv)
	header_binary = sock.recv(header_size)
	header_binary = aes_cipher.decrypt(header_binary)
	# read header
	reader = byteStreamIO.BytesStreamReader(header_binary)
	filename = reader.read_str(reader.read_int(64))
	file_size = reader.read_int(64)
	# check if exist
	if os.path.isfile(filename):
		sock.send(b'override?')
		if sock.recv(1)[0] == 0:
			sock.send(b'cancel')
			return
	# open file for writing
	try:
		file = open(filename, 'wb')
	except Exception:
		sock.send(b'err')
		return
	# request block send
	sock.send(b'block')
	block_size = 1024 ** 2
	write_counter = 0
	recv_bin = b''
	while write_counter < file_size:
		recv_bin = sock.recv(block_size)
		if (len(recv_bin) == 1 and recv_bin == b'\00') or len(recv_bin) == 0:
			file.close()
			os.remove(filename)
			return

		file.write(aes_cipher.decrypt(recv_bin))
		file.flush()
		write_counter += len(recv_bin)
	file.close()
	sock.send(b'md5')
	# check transfer
	md5_checksum = hashlib.md5()
	file = open(filename, 'rb')
	while True:
		data = file.read(1024**2)
		if not data:
			break
		md5_checksum.update(data)
	file.close()
	md5 = md5_checksum.digest()
	r = sock.recv(1024)
	if r != md5:
		# Tell client transfer failed
		sock.send(b'\xFE')
		sock.close()
		# delete broken file
		os.remove(filename)
	else:
		sock.send(b'\xFF')


def send(sock: socket.socket):
	sock.send(b'header_len?')
	header_len = sock.recv(8)

	if not os.path.isfile(file_path):
		pass
