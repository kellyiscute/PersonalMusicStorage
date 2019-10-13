import os
import confMan
import clientHandler

CONFIG: confMan.Config


def main():
	global CONFIG

	if not os.path.isfile('config.conf'):
		confMan.gen_config()
	else:
		CONFIG = confMan.Config('config.conf')
		hdl = clientHandler.ClientHandler(CONFIG)
		hdl.listen()

if __name__ == '__main__':
	main()
