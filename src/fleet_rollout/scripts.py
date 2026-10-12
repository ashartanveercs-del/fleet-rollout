"""Small Python programs the engine runs *inside* a target with `python3 -c`.

They are constants, written by us. Nothing from a patch spec is ever interpolated into
their source: every input arrives as `argv` or as JSON on stdin, so a hostile value can
change what they operate on (within the validated jail) but never what they do.
"""

from __future__ import annotations

# Byte-compile files in memory to prove they parse. Unlike `python -m py_compile`, this
# writes no __pycache__ next to the file, so a syntax check has no side effects.
COMPILE_PYTHON = """\
import sys
for path in sys.argv[1:]:
    with open(path, "rb") as handle:
        compile(handle.read(), path, "exec", dont_inherit=True)
"""

# GET a URL from inside the target's network namespace and print "<status>\\n<body>".
# Probing from inside the container talks to the agent itself, not to whatever reverse
# proxy sits in front of it (a proxy's catch-all route happily answers 200).
HTTP_PROBE = """\
import sys, urllib.error, urllib.request
url, timeout = sys.argv[1], float(sys.argv[2])
try:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        status, body = response.status, response.read(65536)
except urllib.error.HTTPError as err:
    status, body = err.code, err.read(65536)
sys.stdout.buffer.write(str(status).encode("ascii") + b"\\n" + body)
"""

# One row of a SQLite table: read it, upsert it, or put it back. A live agent keeps
# writing to its database, so a patch changes, and a restore undoes, exactly one row's
# patched columns and nothing else.
# Input: JSON on stdin {op, db, table, key_column, key, values, previous?, force?}, where
# `values` are the columns the patch writes (their names are the columns read), and
# `previous` is the row before the patch (null: there was no such row).
#   read     print the row's current values (null if the row does not exist)
#   upsert   write `values`; with `previous` given, only if the row still holds it
#   restore  put `previous` back (delete the row if null), only if the row still holds
#            `values` (what the patch wrote) unless `force`; a no-op if already restored
# Identifiers were allowlisted when the patch was loaded; they are re-checked here (the
# script must be safe on its own) and double-quoted. Every key and value is a bound `?`
# parameter. Each op is one transaction, and the read-back happens inside it.
# Exit codes: 0 ok, 3 database file missing, 4 table missing, 5 bad identifier or op,
# 6 read-back mismatch (nothing committed), 7 the row is not in the expected state
# (nothing written), 8 a value that is neither text nor a number.
SQL_ROW = """\
import json, re, sqlite3, sys, urllib.parse
p = json.load(sys.stdin)
ident = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
cols = list(p["values"])
names = [p["table"], p["key_column"], *cols]
if p.get("op") not in ("read", "upsert", "restore") or not cols or any(
        not isinstance(n, str) or not ident.fullmatch(n) or n.lower().startswith("sqlite_")
        for n in names):
    sys.exit(5)
q = lambda name: '"' + name + '"'
table, key_col, key = q(p["table"]), q(p["key_column"]), p["key"]
try:
    con = sqlite3.connect("file:" + urllib.parse.quote(p["db"]) + "?mode=rw", uri=True,
                          isolation_level=None)
except sqlite3.OperationalError:
    sys.exit(3)
def row():
    found = con.execute("SELECT " + ", ".join(q(c) for c in cols) + " FROM " + table
                        + " WHERE " + key_col + " = ?", (key,)).fetchone()
    return dict(zip(cols, found)) if found else None
def put(target):
    if target is None:
        con.execute("DELETE FROM " + table + " WHERE " + key_col + " = ?", (key,))
    elif row() is None:
        con.execute("INSERT INTO " + table + " (" + ", ".join([key_col] + [q(c) for c in cols])
                    + ") VALUES (" + ", ".join(["?"] * (len(cols) + 1)) + ")",
                    (key, *(target[c] for c in cols)))
    else:
        con.execute("UPDATE " + table + " SET " + ", ".join(q(c) + " = ?" for c in cols)
                    + " WHERE " + key_col + " = ?", (*(target[c] for c in cols), key))
code, result = 0, None
try:
    con.execute("BEGIN" if p["op"] == "read" else "BEGIN IMMEDIATE")
    if con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                   (p["table"],)).fetchone() is None:
        code = 4
    else:
        current = result = row()
        if current is not None and any(isinstance(v, bytes) for v in current.values()):
            code, result = 8, None
        elif p["op"] == "upsert":
            if "previous" in p and current != p["previous"]:
                code = 7
            else:
                put(p["values"])
                result = row()
                code = 0 if result == p["values"] else 6
        elif p["op"] == "restore" and current != p["previous"]:
            if current != p["values"] and not p.get("force"):
                code = 7
            else:
                put(p["previous"])
                result = row()
                code = 0 if result == p["previous"] else 6
    con.execute("COMMIT" if code == 0 else "ROLLBACK")
finally:
    con.close()
sys.stdout.write(json.dumps({"ok": code == 0, "row": result}))
sys.exit(code)
"""
