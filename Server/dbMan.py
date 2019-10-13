import sqlite3
from typing import List
import random


class FileInfo:
	def __init__(self, id: int, path: str, title: str, artist: str, album: str, bitrate: int, length: int):
		self.id: int = id
		self.path: str = path
		self.title: str = title
		self.artist: str = artist
		self.album: str = album
		self.bitrate: int = bitrate
		self.length: int = length


def connect():
	return sqlite3.connect('data.db')


def create_database():
	conn = connect()
	cur = conn.cursor()
	cur.execute(
		"CREATE TABLE files (id INTEGER PRIMARY KEY, path TEXT, title TEXT, artist TEXT, album TEXT, bitrate INTEGER, length INTEGER)")
	cur.execute("CREATE TABLE fail2ban (ipAddr TEXT)")
	conn.commit()
	conn.close()


def list_file() -> List[FileInfo]:
	conn = connect()
	cur = conn.execute('select * from files')
	r = cur.fetchall()
	result: List[FileInfo] = []
	if r.__len__() > 0:
		for row in r:
			f = FileInfo(row[0], row[1], row[2], row[3], row[4], row[5], row[6])
			result.append(f)
	return result


def random_file_info() -> FileInfo:
	id = random.randint(0,10000000)
	path = str(random.randint(0,11111111))
	title = str(random.randint(0,11111111))
	album = str(random.randint(0,11111111))
	artist = str(random.randint(0,11111111))
	bitrate = random.randint(0,10000000)
	length = random.randint(0,10000000)
	return FileInfo(id,path,title,album,artist,bitrate,length)
