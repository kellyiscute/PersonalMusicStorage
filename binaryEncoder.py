import dbMan
from typing import Union, List

# int byteorder: little Endian
ASCII_END_OF_TEXT = 3


def encode_fileinfo_element(fi: dbMan.FileInfo) -> bytes:
	result_list: List[int] = []
	# id
	result_list.extend(fi.id.to_bytes(8, 'little'))
	# path
	result_list.extend(fi.path.encode('utf-8'))
	result_list.append(ASCII_END_OF_TEXT)
	# title
	result_list.extend(fi.title.encode('utf-8'))
	result_list.append(ASCII_END_OF_TEXT)
	# artist
	result_list.extend(fi.artist.encode('utf-8'))
	result_list.append(ASCII_END_OF_TEXT)
	# album
	result_list.extend(fi.album.encode('utf-8'))
	result_list.append(ASCII_END_OF_TEXT)
	# bitrate
	result_list.extend(fi.bitrate.to_bytes(8, 'little'))
	# length
	result_list.extend(fi.length.to_bytes(8, 'little'))
	
	return bytes(result_list)

def encode_fileinfo(fi: Union[dbMan.FileInfo, List[dbMan.FileInfo]]) -> Union[List[bytes], bytes]:
	"""
	All integer is 8 bytes in length, ETX(003) at every end of string
	:param fi: FileInfo class
	:return: byte encoded data stream, ready to be transferred
	"""
	if type(fi) == dbMan.FileInfo:
		return bytes(encode_fileinfo_element(fi))

	elif type(fi) == list and type(fi[0]) == dbMan.FileInfo:
		result: List[bytes] = []
		for f in fi:
			result.append(encode_fileinfo_element(f))
	else:
		raise Exception('Invalid Type')
