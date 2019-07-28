import socket
import confMan
import threading
import os
import rsa
from typing import Union

dispatcher_server_public_key: rsa.PublicKey
NULL_RESPONSE = 0
WHO_ARE_YOU = 1
DISPATCHER_SERVER_CONN = 2  # Should be signed
CLIENT_CONNECTION = 3
GET_FILE_LIST = 4


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


def send_message(sock: socket.socket, message: Union[int, str]):
	if type(message) == int:
		sock.send(bytes((message,)))
	elif type(message) == str:
		sock.send(message.encode('utf-8'))


class ClientHandler:
	def __init__(self, conf):
		self.config: confMan.Config = conf
		self.stopIndicator: bool = False
		self.listenSck: socket.socket = socket.socket(socket.AF_INET)

	@staticmethod
	def client_thread(sock: socket.socket):
		conn_status = 0
		send_message(sock, WHO_ARE_YOU)
		recv = sock.recv(1024)
		if len(recv) != 1:
			if verify_dispatcher_server(recv):
				conn_status = DISPATCHER_SERVER_CONN
			else:
				sock.close()
				return
		elif(int(recv) == CLIENT_CONNECTION):
			conn_status = CLIENT_CONNECTION


	def listen(self):
		self.listenSck.bind(('0.0.0.0', self.config.port))
		self.listenSck.listen()
		while not self.stopIndicator:
			(sck, addr) = self.listenSck.accept()
			t = threading.Thread(target=ClientHandler.client_thread(sck))
			t.start()
