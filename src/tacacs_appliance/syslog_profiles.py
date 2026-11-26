"""Operator-maintained Syslog labels, independent of TACACS+ inventory."""

from contextlib import closing
import ipaddress
from pathlib import Path
import sqlite3

PATH = Path("/run/tnac-alerts/syslog-profiles.sqlite3")
KINDS = {"switch", "router", "firewall"}
MAX_PROFILES = 500


def read_profiles(path=PATH):
    if not path.exists():
        return {}
    with closing(
        sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)
    ) as db:
        return {
            source: {"name": name, "profile": profile}
            for source, name, profile in db.execute(
                "SELECT source, name, profile FROM profiles ORDER BY name, source"
            )
        }


def validate_change(values):
    if not isinstance(values, dict):
        raise ValueError("invalid profile")
    action = values.get("action")
    fields = (
        {"action", "source"}
        if action == "remove"
        else {"action", "source", "name", "profile"}
    )
    if set(values) != fields or not all(isinstance(v, str) for v in values.values()):
        raise ValueError("invalid profile")
    source = str(ipaddress.IPv4Address(values["source"]))
    if action == "remove":
        return action, source, None, None
    name = values["name"].strip()
    if (
        action != "save"
        or values["profile"] not in KINDS
        or not 1 <= len(name) <= 80
        or not name.isprintable()
    ):
        raise ValueError("invalid name or profile")
    return action, source, name, values["profile"]


def change_profile(change, path=PATH):
    action, source, name, profile = change
    with closing(sqlite3.connect(path, timeout=2, isolation_level=None)) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute(
                "CREATE TABLE IF NOT EXISTS profiles (source TEXT PRIMARY KEY, name TEXT NOT NULL, profile TEXT NOT NULL)"
            )
            if action == "remove":
                db.execute("DELETE FROM profiles WHERE source = ?", (source,))
            else:
                existing = db.execute(
                    "SELECT 1 FROM profiles WHERE source = ?", (source,)
                ).fetchone()
                count = db.execute("SELECT count(*) FROM profiles").fetchone()[0]
                if not existing and count >= MAX_PROFILES:
                    raise ValueError("too many profiles")
                db.execute(
                    "INSERT INTO profiles(source,name,profile) VALUES(?,?,?) "
                    "ON CONFLICT(source) DO UPDATE SET name=excluded.name, profile=excluded.profile",
                    (source, name, profile),
                )
            db.commit()
        except BaseException:
            db.rollback()
            raise
