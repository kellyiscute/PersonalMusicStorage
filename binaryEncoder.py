import dbMan
from typing import Union, List
from byteStreamIO import BytesStreamWriter

# int byteorder: little Endian
ASCII_END_OF_TEXT = '\x03'
ASCII_FILE_SEPARATOR = '\x1C'
ASCII_END_OF_TRANSMISSION = '\x04'


def encode_fileinfo_element(fi: dbMan.FileInfo) -> bytearray:

	w = BytesStreamWriter()
	# id
	w.write_int(fi.id, 64)
	# path
	w.write_str(fi.path, ASCII_END_OF_TEXT)
	# title
	w.write_str(fi.title, ASCII_END_OF_TEXT)
	# artist
	w.write_str(fi.artist, ASCII_END_OF_TEXT)
	# album
	w.write_str(fi.album, ASCII_END_OF_TEXT)
	# bitrate
	w.write_int(fi.bitrate, 64)
	# length
	w.write_int(fi.length, 64)
	# ASCII_FS
	w.write_str(ASCII_FILE_SEPARATOR)


	# result_list: bytearray = bytearray()
	# # id
	# result_list.extend(fi.id.to_bytes(8, 'little'))
	# # path
	# result_list.extend(fi.path.encode('utf-8'))
	# result_list.append(ASCII_END_OF_TEXT)
	# # title
	# result_list.extend(fi.title.encode('utf-8'))
	# result_list.append(ASCII_END_OF_TEXT)
	# # artist
	# result_list.extend(fi.artist.encode('utf-8'))
	# result_list.append(ASCII_END_OF_TEXT)
	# # album
	# result_list.extend(fi.album.encode('utf-8'))
	# result_list.append(ASCII_END_OF_TEXT)
	# # bitrate
	# result_list.extend(fi.bitrate.to_bytes(8, 'little'))
	# # length
	# result_list.extend(fi.length.to_bytes(8, 'little'))
	# # ASCII_FS
	# result_list.append(ASCII_FILE_SEPARATOR)

	return w.baseByteArray


def encode_fileinfo(fi: Union[dbMan.FileInfo, List[dbMan.FileInfo]]) -> bytes:
	"""
	All integer is 8 bytes in length, ETX(003) at every end of string, file separator at every end of file info
	:param fi: FileInfo class
	:return: byte encoded data stream, ready to be transferred
	"""
	w = BytesStreamWriter()
	if type(fi) == dbMan.FileInfo:
		r = encode_fileinfo_element(fi)
		r.append(3)
		return bytes(r)

	elif type(fi) == list and type(fi[0]) == dbMan.FileInfo:
		result: bytearray = bytearray()
		for f in fi:
			result.extend(encode_fileinfo_element(f))
		result.append(3)
		return bytes(result)
	else:
		raise Exception('Invalid Type')
