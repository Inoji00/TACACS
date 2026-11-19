"""Bounded UDP device syslog collection and read-only search."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import re
import socket
import sqlite3
from threading import Thread
import time
from urllib.parse import parse_qs

DATABASE = Path("/var/lib/tnac-syslog/events.sqlite3")
RETENTION_SECONDS = 30 * 86400
MAX_MESSAGE = 8192
PRI = re.compile(r"^<([0-9]{1,3})>")
CISCO = re.compile(r"%([A-Za-z0-9_]+)-([0-7])-([A-Za-z0-9_]+):")


def parse_message(data):
    message = data.decode("utf-8", errors="replace").rstrip("\x00\r\n")
    prefix = PRI.match(message)
    priority = int(prefix[1]) if prefix else 192
    if 0 <= priority <= 191:
        return priority // 8, priority % 8, message
    cisco = CISCO.search(message)
    return None, int(cisco[2]) if cisco else None, message


def writer(path):
    db = sqlite3.connect(path, timeout=5)
    if not path.stat().st_size:
        db.execute("PRAGMA auto_vacuum=INCREMENTAL")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA wal_autocheckpoint=256")
    db.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, received INTEGER NOT NULL, source TEXT NOT NULL,
        facility INTEGER, severity INTEGER, message TEXT NOT NULL
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS events_received ON events(received, id)")
    db.execute("CREATE INDEX IF NOT EXISTS events_source ON events(source, received, id)")
    db.commit()
    return db


def prune(db, now):
    with db:
        deleted = db.execute(
            "DELETE FROM events WHERE id IN "
            "(SELECT id FROM events WHERE received < ? ORDER BY received, id LIMIT 500)",
            (now - RETENTION_SECONDS,),
        ).rowcount
        db.execute("PRAGMA incremental_vacuum(64)")
    return deleted


def ready():
    with closing(sqlite3.connect(DATABASE.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
        db.execute("SELECT id FROM events LIMIT 1").fetchone()


def search(query, path=DATABASE):
    fields = parse_qs(query, keep_blank_values=True, max_num_fields=6)
    if not fields.keys() <= {"source", "severity", "since", "until", "q", "before"}:
        raise ValueError("unknown filter")
    if any(len(values) != 1 or len(values[0]) > 256 for values in fields.values()):
        raise ValueError("invalid filter")
    values = {key: items[0] for key, items in fields.items() if items[0]}
    where = ["received >= ?"]
    args = [int(time.time()) - RETENTION_SECONDS]
    if "source" in values:
        where.append("source = ?")
        args.append(str(ipaddress.IPv4Address(values["source"])))
    if "severity" in values:
        if values["severity"] not in "01234567" or len(values["severity"]) != 1:
            raise ValueError("invalid severity")
        where.append("severity = ?")
        args.append(int(values["severity"]))
    for key, op in (("since", ">="), ("until", "<=")):
        if key in values:
            stamp = datetime.fromisoformat(values[key])
            if stamp.tzinfo is None:
                raise ValueError("timezone required")
            where.append(f"received {op} ?")
            args.append(int(stamp.timestamp()))
    if "q" in values:
        where.append("instr(lower(message), lower(?)) > 0")
        args.append(values["q"])
    if "before" in values:
        before = int(values["before"])
        if not 1 <= before < 2**63:
            raise ValueError("invalid cursor")
        where.append("id < ?")
        args.append(before)
    if not path.is_file():
        return {"items": [], "next_before": None, "collector_ready": False}
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
        db.row_factory = sqlite3.Row
        deadline = time.monotonic() + 2
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        rows = db.execute("SELECT * FROM events WHERE " + " AND ".join(where)
                          + " ORDER BY id DESC LIMIT 101", args).fetchall()
    return {"items": [{**dict(row), "received": datetime.fromtimestamp(
                row["received"], timezone.utc).isoformat()} for row in rows[:100]],
            "next_before": rows[99]["id"] if len(rows) > 100 else None, "collector_ready": True}


def collect(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("0.0.0.0", port))
        listener.settimeout(0.25)
        db = writer(DATABASE)
        from .syslog_archive import run
        Thread(target=run, args=(DATABASE, RETENTION_SECONDS),
               name="device-syslog-archive", daemon=True).start()
        pending = []
        maintenance = 0
        flush = time.monotonic() + 0.25
        while True:
            try:
                data, peer = listener.recvfrom(MAX_MESSAGE + 1)
            except TimeoutError:
                data = b""
            now = int(time.time())
            if 0 < len(data) <= MAX_MESSAGE:
                pending.append((now, peer[0], *parse_message(data)))
            if pending and (len(pending) >= 128 or time.monotonic() >= flush):
                with db:
                    db.executemany("INSERT INTO events(received,source,facility,severity,message) VALUES (?,?,?,?,?)", pending)
                pending.clear()
                flush = time.monotonic() + 0.25
            if now >= maintenance:
                deleted = prune(db, now)
                maintenance = now + (1 if deleted == 500 else 3600)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=1514)
    collect(parser.parse_args().port)
