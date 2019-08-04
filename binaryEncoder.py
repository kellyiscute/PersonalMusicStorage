import dbMan
from typing import Union, List

# int byteorder: little Endian
ASCII_END_OF_TEXT = 3
ASCII_FILE_SEPARATOR = 28
ASCII_END_OF_TRANSMISSION = 4


def encode_fileinfo_element(fi: dbMan.FileInfo) -> bytearray:
	result_list: bytearray = bytearray()
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
	# ASCII_FS
	result_list.append(ASCII_FILE_SEPARATOR)

	return result_list


def encode_fileinfo(fi: Union[dbMan.FileInfo, List[dbMan.FileInfo]]) -> bytes:
	"""
	All integer is 8 bytes in length, ETX(003) at every end of string, file separator at every end of file info
	:param fi: FileInfo class
	:return: byte encoded data stream, ready to be transferred
	"""
	if type(fi) == dbMan.FileInfo:
		r = encode_fileinfo_element(fi)
		r.append(ASCII_END_OF_TRANSMISSION)
		return bytes(r)

	elif type(fi) == list and type(fi[0]) == dbMan.FileInfo:
		result: bytearray = bytearray()
		for f in fi:
			result.extend(encode_fileinfo_element(f))
		result.append(ASCII_END_OF_TRANSMISSION)
		return bytes(result)
	else:
		raise Exception('Invalid Type')
