import sqlite3
from typing import List


class FileInfo:
	def __init__(self, id: int, path: str, title: str, artist: str, album: str, bitrate: int, length: int):
		self.id = id
		self.path = path
		self.title = title
		self.artist = artist
		self.album = album
		self.bitrate = bitrate
		self.length = length


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
