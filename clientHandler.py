import socket
import confMan
import threading
import os
import rsa
import typing
import dbMan
import binaryEncoder
import fileTransfer
from typing import Union


dispatcher_server_public_key: Union[rsa.PublicKey, None] = None

# CONSTANTS
NULL_RESPONSE = b'\x00'
WHO_ARE_YOU = b'\x01'
DISPATCHER_SERVER_CONN = b'\x02'  # Should be signed
CLIENT_CONNECTION = b'\x03'
AUTHED_CLIENT = b'\x04'
UNAUTHED_CLIENT = b'\x05'
CLIENT_AUTH = b'\x06'
CLIENT_RETRY_AUTH = b'\x07'
AUTH_BANNED = b'\x67'
AUTH_CANCEL = b'\x09'
AUTH_COMPLETE = b'\xCA'  # Http response 202 Accepted
ACCESS_DENIED = b'\x65'
LIST_FILE = b'\x0A'
UPLOAD_FILE = b'\x0B'
FILE_SIZE = b'\x0C'


def verify_dispatcher_server(sig) -> bool:
	"""
	Verify if the DISPATCHER_SERVER_CONN is real
	:param sig: signature
	:return: True if real, False if fake or public key not found
	"""
	global dispatcher_server_public_key
	if dispatcher_server_public_key is None:
		if os.path.isfile('dispatcherServerPub.pem'):
			with open('dispatcherServerPub.pem', 'rb') as pem:
				dispatcher_server_public_key = rsa.PublicKey.load_pkcs1(pem.read())
			pem.close()
		else:
			return False
		try:
			rsa.verify(DISPATCHER_SERVER_CONN, sig, dispatcher_server_public_key)
		except rsa.VerificationError:
			return False


def send_message(sock: socket.socket, message: Union[str, bytes]) -> None:
	"""
	Send message through socket
	:param sock: socket obj
	:param message: message
	:return: None
	"""
	if type(message) == bytes:
		sock.send(message)
	elif type(message) == str:
		sock.send(message.encode('utf-8'))


class ClientHandler:
	def __init__(self, conf):
		"""
		init a ClientHandler instance
		:param conf: loaded Config class
		"""
		self.config: confMan.Config = conf
		self.stopIndicator: bool = False
		self.listenSck: socket.socket = socket.socket(socket.AF_INET)
		self.banned_ip: typing.List[str] = []

	def verify_client_password(self, enc_pwd: bytes) -> bool:
		"""
		Verify the password that the client provide
		:param enc_pwd: rsa encrypted password
		:return:True/False
		"""
		try:
			pwd = rsa.decrypt(enc_pwd, self.config.privateKey)
			if pwd.decode() == self.config.password:
				return True
			else:
				return False
		except rsa.DecryptionError:
			return False

	def client_thread(self, sock: socket.socket, remote_addr: str) -> None:
		"""
		method for handling connections
		:param remote_addr: remote address, for fail2ban
		:param sock: socket obj
		:return: None
		"""
		password_retries = 0
		conn_type = 0
		# Ask for connection type
		send_message(sock, WHO_ARE_YOU)
		recv = sock.recv(1024)
		if len(recv) > 1:
			# Dispatcher server connection, signed message
			if verify_dispatcher_server(recv):
				conn_type = DISPATCHER_SERVER_CONN
			else:
				sock.close()
				return
		elif recv == CLIENT_CONNECTION:
			# Client connection
			conn_type = CLIENT_CONNECTION
		elif len(recv) == 0:
			# Connection closed
			sock.close()
			return

		# Client Connection Auth
		if conn_type == CLIENT_CONNECTION:
			# Ask for password
			send_message(sock, CLIENT_AUTH)
		# Wait for response
		while True:
			recv = sock.recv(10240)
			if len(recv) == 0:
				# Connection closed
				sock.close()
				return

			if len(recv) == 1:
				if recv == AUTH_CANCEL:
					conn_type = UNAUTHED_CLIENT
					send_message(sock, UNAUTHED_CLIENT)
					break
			else:
				if self.verify_client_password(recv):
					conn_type = AUTHED_CLIENT
					send_message(sock,AUTH_COMPLETE)
					break
				else:
					password_retries += 1
					if self.config.fail2ban != 0 and password_retries >= self.config.fail2ban:
						# If fail2ban is on (non-zero value), ban if password retries >= fail2ban's count
						self.banned_ip.append(remote_addr)
						send_message(sock, AUTH_BANNED)
						sock.close()
						break
					else:
						send_message(sock, CLIENT_RETRY_AUTH)

		# Command Response
		while True:
			# Wait for command
			recv = sock.recv(10240)

			# Test if connection closed
			if len(recv) == 0:
				sock.close()
				return

			# request file list  All clients has permission if shareLib is on
			if recv == LIST_FILE:
				if self.config.shareLib or conn_type == AUTHED_CLIENT or conn_type == DISPATCHER_SERVER_CONN:
					file_list = dbMan.list_file()
					bin_file_list = binaryEncoder.encode_fileinfo(file_list)  # Binary encoded FileList object
					# send bin size
					send_message(sock, bytes((bin_file_list.__len__(),)))
					recv = sock.recv(20)
					if recv.__len__() == 0:
						# connection closed
						sock.close()
						return
					else:
						send_message(sock, bin_file_list)
				else:
					send_message(sock, ACCESS_DENIED)
			# Request file upload
			elif recv == UPLOAD_FILE:
				# only authorized client has permission
				if conn_type == AUTHED_CLIENT:
					fileTransfer.recv(sock, self.config.privateKey)
				else:
					send_message(sock, ACCESS_DENIED)

	def listen(self) -> None:
		"""
		Start listening for connections
		:return: None
		"""
		self.listenSck.bind(('0.0.0.0', self.config.port))
		self.listenSck.listen()
		while not self.stopIndicator:
			(sck, addr) = self.listenSck.accept()  # Notice: Thread stuck here
			t = threading.Thread(target=ClientHandler.client_thread(self, sck, addr[0]))
			t.start()
