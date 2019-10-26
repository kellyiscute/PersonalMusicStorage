import configparser
import rsa
import os
import dbMan


def gen_config():
	print('Hi, we are now going to help you generate your config file')
	print('First, let\'s determine the key size of the encryption key')
	print('The value of 2048 is recommended as the maximum and it will be the default')
	print('\n=============================================================================')
	key_size = input('RSA key size(2048 as default): ')
	if not key_size.isdigit():
		key_size = 2048
	key_size = int(key_size)
	if key_size not in [128, 256, 384, 512, 1024, 2048, 3072, 4096]:
		key_size = 2048
	print(f'generating keys of size {key_size}......')
	# gen key
	(pub_key, private_key) = rsa.newkeys(key_size)
	pub_key = pub_key.save_pkcs1()
	private_key = private_key.save_pkcs1()
	# Save key to file
	with open('publicKey.pem', 'w+b') as pubKeyFile:
		pubKeyFile.write(pub_key)
	pubKeyFile.close()
	with open('privateKey.pem', 'w+b') as privateKeyFile:
		privateKeyFile.write(private_key)
	privateKeyFile.close()
	print('Key pair saved')
	print('=============================================================================')
	share_lib = input('would you like to share you library with others? (Y/n): ')
	if not share_lib.lower() == 'n':
		share_lib = 'True'
	else:
		share_lib = 'False'
	port = input('which port would you like to run on(6746 as default): ')
	if not port.isdigit():
		port = 6746
	manage_pwd = input('Set a client password: ')
	# Save Config File
	conf = configparser.ConfigParser()
	conf.add_section('KEYS')
	conf.add_section('FAIL2BAN')
	conf['FAIL2BAN']['Password Retries'] = '10'
	conf['KEYS']['Private'] = 'privateKey.pem'
	conf['KEYS']['Public'] = 'publicKey.pem'
	conf['DEFAULT']['ShareLib'] = share_lib
	conf['DEFAULT']['Port'] = str(port)
	conf['DEFAULT']['Password'] = manage_pwd
	# Write File
	with open('config.conf', 'w') as confFile:
		conf.write(confFile)
	confFile.close()
	dbMan.create_database()
	print('\n===============================Config Saved==================================')


class Config:

	def __init__(self, file: str):
		self.privateKey: rsa.PrivateKey
		self.publicKey: rsa.PublicKey
		self.shareLib: bool = False
		self.port: int = 0
		self.password: str = ''
		self.fail2ban: int = 0

		conf = configparser.ConfigParser()
		conf.read(file)
		# Check Config File
		if 'DEFAULT' not in conf.keys() or 'KEYS' not in conf.keys():
			raise Exception('Invalid Configuration')
		if 'ShareLib' not in conf['DEFAULT'].keys() or 'Port' not in conf['DEFAULT'].keys() or 'Password' not in conf[
			'DEFAULT'].keys():
			raise Exception('Invalid Configuration')
		if 'Private' not in conf['KEYS'].keys() or 'Public' not in conf['KEYS'].keys():
			raise Exception('Invalid Configuration')
		# Check KeyFiles
		if os.path.isfile(conf['KEYS']['Private']) and os.path.isfile(conf['KEYS']['Public']):
			# Load Keys
			with open(conf['KEYS']['Private'], 'rb') as pk:
				self.privateKey = rsa.PrivateKey.load_pkcs1(pk.read())
			pk.close()
			with open(conf['KEYS']['Public'], 'rb') as pk:
				self.publicKey = rsa.PublicKey.load_pkcs1(pk.read())
			pk.close()
		else:
			raise Exception('One or both key files not found')
		# Load fail2ban
		if 'FAIL2BAN' in conf.keys():
			if 'Password Retries' in conf['FAIL2BAN']:
				self.fail2ban = int(conf['FAIL2BAN']['Password Retries'])
		# Load other values
		if conf['DEFAULT']['ShareLib'] == 'True':
			self.shareLib = True
		elif conf['DEFAULT']['ShareLib'] == 'False':
			self.shareLib = False
		else:
			raise Exception('Invalid value for "ShareLib"')
		if str(conf['DEFAULT']['Port']).isdigit() and int(conf['DEFAULT']['Port']) > 0 and int(
			conf['DEFAULT']['Port']) < 65535:
			self.port = int(conf['DEFAULT']['Port'])
		else:
			raise Exception('Invalid value for "Port"')
		self.password = conf['DEFAULT']['Password']
