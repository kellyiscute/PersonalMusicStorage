from typing import Union


class IndexOverflowException(Exception):
	pass


class BytesStreamReader:

	def __init__(self, b: Union[bytes, bytearray]):
		if type(b) is bytes:
			b = bytearray(b)
		self.baseByteArray: bytearray = b
		self.seek: int = 0
		self.length = b.__len__()

	def read_bytes(self, length: int, throw_exception_when_length_exceeds=False) -> bytearray:
		result = bytearray()
		for i in range(self.seek, self.seek + length):
			if i < self.length:
				result.append(self.baseByteArray[i])
				self.seek += 1
			else:
				if throw_exception_when_length_exceeds:
					raise IndexOverflowException('Index overflow')
				break

		return result

	def read_str(self, length: int, encoding = 'utf-8') -> str:
		b = self.read_bytes(length).decode('utf-8', 'ignore')
		if b.encode('utf-8').__len__() < length:
			raise IndexOverflowException('Index overflow')
		return b

	def read_str_until_char_appear(self, char: str, include=False, seek_back=False):
		result = ''
		read = ''
		while self.seek < self.length:
			read = self.read_bytes(1).decode()
			if read == char:
				if include:
					result += read
				if seek_back:
					self.seek -= 1
			else:
				result += read
		return result

	def read_int(self, int_type: int, byte_order='little') -> int:
		b = self.read_bytes(int(int_type / 8))
		return int.from_bytes(b, byte_order)

	def read_bool(self) -> bool:
		b = self.read_bytes(1)
		if b[0] == 1:
			return True
		else:
			return False


class BytesStreamWriter:

	def __init__(self):
		self.baseByteArray = bytearray()

	def __len__(self):
		return self.baseByteArray.__len__()

	def write_int(self, num: int, int_type: int, byte_order='little'):
		b = int.to_bytes(num, int(int_type/8), byte_order)
		self.baseByteArray.extend(b)

	def write_str(self, s: str, end=''):
		b = str.encode(s+end, 'utf-8')
		self.baseByteArray.extend(b)

	def write_bool(self, b: bool):
		if b:
			self.baseByteArray.append(1)
		else:
			self.baseByteArray.append(0)
