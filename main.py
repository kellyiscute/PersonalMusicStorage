import os
import confMan

CONFIG: confMan.Config


def main():
	global CONFIG

	if not os.path.isfile('config.conf'):
		confMan.gen_config()
	else:
		CONFIG = confMan.Config('config.conf')


if __name__ == '__main__':
	main()
