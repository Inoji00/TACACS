"""Daily, regenerable text archives of the Device Syslog database."""

from contextlib import closing
from datetime import date, datetime, time, timedelta, timezone
import ipaddress
from itertools import chain
import logging
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time as clock

VIETNAM_TIME = timezone(timedelta(hours=7))
INTERVAL = 60
BATCH_SIZE = 1000
DAY_FILE = re.compile(r"\d{4}-\d{2}-\d{2}\.log\Z")
LOG = logging.getLogger(__name__)


def day_for(stamp):
    return datetime.fromtimestamp(stamp, VIETNAM_TIME).date()


def day_start(day):
    return int(datetime.combine(day, time.min, VIETNAM_TIME).timestamp())


def valid_source(value):
    try:
        return str(ipaddress.IPv4Address(value)) == value
    except ValueError:
        return False


def write_day(db, directory, source, day, cutoff, high_id):
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink():
        raise OSError("invalid archive directory")
    target = directory / f"{day.isoformat()}.log"
    rows = db.execute(
        "SELECT received, message FROM events "
        "WHERE source = ? AND received >= ? AND received < ? AND id <= ? "
        "ORDER BY received, id",
        (
            source,
            max(cutoff, day_start(day)),
            day_start(day + timedelta(days=1)),
            high_id,
        ),
    )
    first = rows.fetchone()
    if first is None:
        target.unlink(missing_ok=True)
        return
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        prefix=".writing-",
        dir=directory,
        delete=False,
    ) as temp:
        try:
            for stamp, message in chain((first,), rows):
                # Preserve readable payload and keep every event on exactly one line.
                safe = (
                    message
                    if message.isprintable()
                    else "".join(
                        c if c.isprintable() else f"\\u{ord(c):04x}" for c in message
                    )
                )
                stamp_text = datetime.fromtimestamp(stamp, VIETNAM_TIME).isoformat()
                temp.write(f"{stamp_text} {source} {safe}\n")
            temp.close()
            os.replace(temp.name, target)
        finally:
            Path(temp.name).unlink(missing_ok=True)


def refresh_archives(db, root, cursor, now, retention):
    # Capture an upper bound so another thread can keep ingesting while files are built.
    high_id = db.execute("SELECT coalesce(max(id), 0) FROM events").fetchone()[0]
    cutoff = now - retention
    earliest_day = day_for(cutoff)
    root.mkdir(mode=0o700, exist_ok=True)
    if root.is_symlink():
        raise OSError("invalid archive root")
    rebuild = cursor == 0 or cursor > high_id
    if rebuild:
        cursor = 0
    affected = set()
    while cursor < high_id:
        rows = db.execute(
            "SELECT id, source, received FROM events "
            "WHERE id > ? AND id <= ? AND received >= ? ORDER BY id LIMIT ?",
            (cursor, high_id, cutoff, BATCH_SIZE),
        ).fetchall()
        if not rows:
            break
        for row_id, source, received in rows:
            if valid_source(source):
                affected.add((source, day_for(received)))
        cursor = rows[-1][0]
    for directory in root.iterdir():
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or not valid_source(directory.name)
        ):
            continue
        for path in directory.iterdir():
            if rebuild and path.name.startswith(".writing-") and path.is_file():
                path.unlink()
                continue
            if not DAY_FILE.fullmatch(path.name):
                continue
            try:
                day = date.fromisoformat(path.stem)
            except ValueError:
                continue
            if day < earliest_day:
                path.unlink()
            elif day == earliest_day or rebuild:
                affected.add((directory.name, day))
    for source, day in sorted(affected):
        write_day(db, root / source, source, day, cutoff, high_id)
    return high_id


def run(database, retention):
    cursor = 0
    root = database.parent / "archive"
    while True:
        try:
            with closing(
                sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=2)
            ) as db:
                cursor = refresh_archives(
                    db, root, cursor, int(clock.time()), retention
                )
        except (OSError, sqlite3.Error):
            LOG.warning("Device Syslog archive sync failed; will retry")
        clock.sleep(INTERVAL)
