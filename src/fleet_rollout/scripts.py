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

# Parameterised upsert of one row into a SQLite table, read back in the same process.
# Input: JSON on stdin {db, table, key_column, key, values}. Identifiers were
# allowlisted when the patch was loaded; they are re-checked here (the script must be
# safe on its own) and double-quoted. Every key and value is a bound `?` parameter.
# Exit codes: 0 ok, 3 database file missing, 4 table missing, 5 bad identifier,
# 6 read-back mismatch.
SQL_UPSERT = """\
import json, re, sqlite3, sys, urllib.parse
p = json.load(sys.stdin)
ident = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
names = [p["table"], p["key_column"], *p["values"]]
if any(not isinstance(n, str) or not ident.fullmatch(n) or n.lower().startswith("sqlite_")
       for n in names):
    sys.exit(5)
q = lambda name: '"' + name + '"'
try:
    con = sqlite3.connect("file:" + urllib.parse.quote(p["db"]) + "?mode=rw", uri=True,
                          isolation_level=None)
except sqlite3.OperationalError:
    sys.exit(3)
try:
    con.execute("BEGIN IMMEDIATE")
    found = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (p["table"],)).fetchone()
    if found is None:
        con.execute("ROLLBACK")
        sys.exit(4)
    cols = list(p["values"])
    vals = [p["values"][c] for c in cols]
    table, key_col = q(p["table"]), q(p["key_column"])
    exists = con.execute("SELECT 1 FROM " + table + " WHERE " + key_col + " = ?",
                         (p["key"],)).fetchone()
    if exists:
        con.execute("UPDATE " + table + " SET " + ", ".join(q(c) + " = ?" for c in cols)
                    + " WHERE " + key_col + " = ?", (*vals, p["key"]))
    else:
        con.execute("INSERT INTO " + table + " (" + ", ".join([key_col] + [q(c) for c in cols])
                    + ") VALUES (" + ", ".join(["?"] * (len(cols) + 1)) + ")",
                    (p["key"], *vals))
    con.execute("COMMIT")
    row = con.execute("SELECT " + ", ".join(q(c) for c in cols) + " FROM " + table
                      + " WHERE " + key_col + " = ?", (p["key"],)).fetchone()
finally:
    con.close()
got = dict(zip(cols, row)) if row else None
if got != p["values"]:
    sys.stdout.write(json.dumps({"ok": False, "row": got}))
    sys.exit(6)
sys.stdout.write(json.dumps({"ok": True, "row": got}))
"""
