import sqlite3


def lookup(connection: sqlite3.Connection, name: str):
    cursor = connection.cursor()
    cursor.execute("SELECT id, name FROM account WHERE name = '%s'" % name)
    return cursor.fetchall()
