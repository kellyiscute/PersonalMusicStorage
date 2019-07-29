import sqlite3


def connect():
	return sqlite3.connect('data.db')


def create_database():
	conn = connect()
	cur = conn.cursor()
	cur.execute("CREATE TABLE files (id INTEGER PRIMARY KEY, path TEXT, title TEXT, artist TEXT, album TEXT, bitrate INTEGER, length INTEGER)")
	cur.execute("CREATE TABLE fail2ban (ipAddr TEXT)")
	conn.commit()
	conn.close()
