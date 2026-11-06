"""Disk backed flow state, with a bounded LRU for active conversations."""
import json
import sqlite3
from collections import OrderedDict


class FlowStore:
    def __init__(self, path, cache_size=256):
        self.db = sqlite3.connect(str(path))
        self.db.execute('PRAGMA journal_mode=OFF')
        self.db.execute('PRAGMA cache_size=-4096')
        self.db.execute('CREATE TABLE flows (id INTEGER PRIMARY KEY, state TEXT NOT NULL)')
        self.db.execute('CREATE TABLE current (key TEXT PRIMARY KEY, id INTEGER NOT NULL)')
        self.cache = OrderedDict()
        self.cache_size = cache_size
        self.count = 0

    @staticmethod
    def key(key):
        return json.dumps(key, separators=(',', ':'))

    def _flush(self, key):
        row_id, state = self.cache.pop(key)
        self.db.execute('UPDATE flows SET state=? WHERE id=?',
                        (json.dumps(state, default=str, separators=(',', ':')), row_id))

    def _bound(self):
        if len(self.cache) > self.cache_size:
            self._flush(next(iter(self.cache)))

    def get(self, key):
        key = self.key(key)
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key][1]
        row = self.db.execute('SELECT flows.id, state FROM current JOIN flows ON current.id=flows.id '
                              'WHERE key=?', (key,)).fetchone()
        if row is None:
            return None
        state = json.loads(row[1])
        self.cache[key] = (row[0], state)
        self._bound()
        return state

    def __setitem__(self, key, state):
        key = self.key(key)
        if key in self.cache:
            self._flush(key)
        row_id = self.db.execute('INSERT INTO flows (state) VALUES (?)',
                                 (json.dumps(state, default=str, separators=(',', ':')),)).lastrowid
        self.db.execute('INSERT OR REPLACE INTO current (key,id) VALUES (?,?)', (key, row_id))
        self.cache[key] = (row_id, state)
        self.count += 1
        self._bound()

    def iter_flows(self):
        for key in list(self.cache):
            self._flush(key)
        self.db.commit()
        for row in self.db.execute('SELECT state FROM flows ORDER BY id'):
            yield json.loads(row[0])

    def close(self):
        self.db.close()
