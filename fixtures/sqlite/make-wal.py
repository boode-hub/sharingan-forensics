# Produces notes.db and notes.db-wal with SQLite itself (Python's sqlite3),
# copied while the connection is still open, so the write-ahead log still
# holds the second transaction, as it does in a live collection.
#
#   python fixtures/sqlite/make-wal.py
#
# The main file holds the schema and rows 1-2 (checkpointed). The WAL holds
# a committed transaction that adds rows 3-5 and changes row 1. SQLite picks
# fresh salts each time, so the bytes differ run to run; the contents do not.
# Not run by CI for that reason: the committed files are the fixture.
import os
import shutil
import sqlite3
import tempfile

here = os.path.dirname(os.path.abspath(__file__))
tmp = tempfile.mkdtemp()
db = os.path.join(tmp, "notes.db")
con = sqlite3.connect(db, isolation_level=None)
con.execute("PRAGMA journal_mode=WAL")
con.execute("PRAGMA wal_autocheckpoint=0")
con.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, data BLOB, big INTEGER)")
con.execute("INSERT INTO notes VALUES (1, 'first', x'00ff10', 1)")
con.execute("INSERT INTO notes VALUES (2, 'second', NULL, 2)")
con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
con.execute("BEGIN")
con.execute("UPDATE notes SET body = 'first, edited' WHERE id = 1")
con.execute("INSERT INTO notes VALUES (3, 'third', x'cafe', 1152921504606846976)")
con.execute("INSERT INTO notes VALUES (4, 'fourth', NULL, -5)")
con.execute("INSERT INTO notes VALUES (5, 'fifth', NULL, 3.5)")
con.execute("COMMIT")
shutil.copyfile(db, os.path.join(here, "notes.db"))
shutil.copyfile(db + "-wal", os.path.join(here, "notes.db-wal"))
con.close()
print(os.path.getsize(os.path.join(here, "notes.db")), os.path.getsize(os.path.join(here, "notes.db-wal")))
