import socket
import confMan
import threading
import os
import rsa
import typing
import dbMan
import binaryEncoder
from typing import Union


dispatcher_server_public_key: rsa.PublicKey

# CONSTANTS
NULL_RESPONSE = bytes((0,))
WHO_ARE_YOU = bytes((1,))
DISPATCHER_SERVER_CONN = bytes((2,))  # Should be signed
CLIENT_CONNECTION = bytes((3,))
AUTHED_CLIENT = bytes((4,))
UNAUTHED_CLIENT = bytes((5,))
CLIENT_AUTH = bytes((6,))
CLIENT_RETRY_AUTH = bytes((7,))
AUTH_BANNED = bytes((403,))  # Http response 403 Forbidden
AUTH_CANCEL = bytes((9,))
AUTH_COMPLETE = bytes((202,))  # Http response 202 Accepted
ACCESS_DENIED = bytes((401,))  # Http response 400 Access denied
LIST_FILE = bytes((10,))
UPLOAD_FILE = bytes((11,))


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
	if type(message) == int:
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
			if pwd == self.config.password:
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
		elif int(recv) == CLIENT_CONNECTION:
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
		recv = sock.recv(10240)
		if len(recv) == 0:
			# Connection closed
			sock.close()
			return
		else:
			while True:
				if len(recv) == 1:
					if recv == AUTH_CANCEL:
						conn_type = UNAUTHED_CLIENT
						break
				else:
					if self.verify_client_password(recv):
						conn_type = AUTHED_CLIENT
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

					pass
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
