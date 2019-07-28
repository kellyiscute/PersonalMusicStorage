import sqlite3


def connect():
	return sqlite3.connect('files.db')


def create_database():
	conn = connect()
	cur = conn.cursor()
	cur.execute("CREATE TABLE files (path TEXT, title TEXT, artist TEXT, album TEXT, bitrate INTEGER, length INTEGER)")
	conn.commit()
	conn.close()
