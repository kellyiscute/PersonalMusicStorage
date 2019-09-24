import socket
import rsa
import time
import os
from typing import Union
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def recv(sock: socket.socket, priv: rsa.PrivateKey):
	# recv encrypted password & filename
	sock.send(b'recv')
	recv_data = sock.recv(10240)
	recv_data = rsa.decrypt(recv_data, priv)
	filename: Union[bytearray, str] = bytearray()
	recv_read_seek = 0
	while recv_data[recv_read_seek] != 3:
		filename.append(recv_data[recv_read_seek])
		recv_read_seek += 1
	filename = filename.decode()
	print(f'filename: {filename}')
	if os.path.isfile(filename):
		sock.send(b'override?')
		recv_data = sock.recv(1)
		if recv_data[0] == 0:
			sock.send(b'cancel')
			return
	# read file_size (Int64)
	recv_read_seek += 1
	file_size: Union[bytearray, int] = bytearray()
	for i in range(recv_read_seek, recv_read_seek + 8):
		# 8 bit of int
		file_size.append(recv_data[recv_read_seek])
		recv_read_seek += 1
	# Little Endian encoding
	file_size = int.from_bytes(file_size, 'little')
	print(f'file_size: {file_size}')
	# Read AES key (16 bytes)
	key: bytearray = bytearray()
	for i in range(0, 16):
		key.append(recv_data[recv_read_seek])
		recv_read_seek += 1
	# Read AES iv (16 bytes)
	iv: bytearray = bytearray()
	for i in range(0, 16):
		iv.append(recv_data[recv_read_seek])
		recv_read_seek += 1
	# Init Cipher object
	cipher = AES.new(key, AES.MODE_CFB, iv=iv)
	# Header stream end
	print(key)
	print(len(key))
	print(iv)
	print(iv.__len__())
	# Request file send
	sock.send(b'file')
	# open for write
	f = open(os.path.basename(filename), 'wb')
	# 1MB block
	read_counter = 0
	start_time = time.time()
	while read_counter < file_size:
		recv_data = bytearray(sock.recv(1024**2))
		recv_data = cipher.decrypt(recv_data)
		f.write(recv_data)
		f.flush()
		read_counter += recv_data.__len__()
		print(f'recv: {read_counter}')
		sock.send(b'next')
	f.close()
	print(f'Total time: {time.time() - start_time}, Avg. Speed: {file_size / (time.time() - start_time)}')
	print('Write done')


def send(sock: socket.socket, pub: rsa.PublicKey, filename: str):
	# Prepare Header
	header: bytearray = bytearray()
	header.extend(filename.encode())
	header.append(3)
	file_size = int(os.path.getsize(filename))
	header.extend(file_size.to_bytes(8, 'little'))
	# Prepare AES key
	aes_key = get_random_bytes(16)
	header.extend(aes_key)
	# Initiate Cipher object
	cipher = AES.new(aes_key, AES.MODE_CFB)
	# Prepare AES iv
	header.extend(cipher.iv)
	print(aes_key)
	print(len(aes_key))
	print(cipher.iv)
	print(len(cipher.iv))
	# rsa encrypt header
	header = rsa.encrypt(header, pub)
	# Wait for recv command
	recv_data = sock.recv(1024)
	print(f'Command: {recv_data.decode()}')
	if recv_data.decode() == 'recv':
		pass
	elif recv_data.decode() == 'cancel':
		return
	else:
		return
	sock.send(header)
	recv_data = sock.recv(1024)
	print(f'Command: {recv_data.decode()}')
	print('Start sending file')
	f = open(filename, 'rb')
	send_counter = 0
	while send_counter < file_size or len(recv_data) != 0:
		fb = bytearray(f.read(1024 ** 2))
		# encrypt
		fb = cipher.encrypt(fb)
		sock.send(fb)
		recv_data = sock.recv(1024)
		send_counter += len(fb)
		print(f'Command: {recv_data.decode()}')
	f.close()
