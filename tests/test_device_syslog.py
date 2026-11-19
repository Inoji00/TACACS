import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
import tempfile
import time
import unittest

from tacacs_appliance.device_syslog import parse_message, prune, search, writer, RETENTION_SECONDS
from tacacs_appliance.syslog_archive import refresh_archives


class DeviceSyslogTests(unittest.TestCase):
    def test_daily_archive_backfills_escapes_and_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            now = int(datetime.fromisoformat('2026-11-19T00:10:00+07:00').timestamp())
            earlier = now - 20 * 60
            with closing(writer(root / 'events.sqlite3')) as db:
                def insert(stamp, source, message):
                    with db:
                        db.execute("INSERT INTO events(received,source,message) VALUES (?,?,?)",
                                   (stamp, source, message))
                insert(earlier, '192.0.2.10', 'link up')
                insert(now, '192.0.2.10', 'line\nwith control')
                insert(now, '192.0.2.11', 'other switch')
                insert(now, '../unexpected', 'invalid source')
                insert(now - RETENTION_SECONDS - 1, '192.0.2.10', 'expired')
                archive = root / 'archive'
                cursor = refresh_archives(db, archive, 0, now, RETENTION_SECONDS)
                previous = archive / '192.0.2.10' / '2026-11-18.log'
                today = archive / '192.0.2.10' / '2026-11-19.log'
                self.assertIn('23:50:00+07:00', previous.read_text())
                self.assertEqual(today.read_text().splitlines(), [
                    '2026-11-19T00:10:00+07:00 192.0.2.10 line\\u000awith control',
                ])
                self.assertEqual(len(list(archive.glob('*/*.log'))), 3)
                insert(now, '192.0.2.10', 'new')
                refresh_archives(db, archive, cursor, now, RETENTION_SECONDS)
                refresh_archives(db, archive, 0, now, RETENTION_SECONDS)
                self.assertEqual(len(today.read_text().splitlines()), 2)
                refresh_archives(db, archive, 0, now + RETENTION_SECONDS + 1, RETENTION_SECONDS)
                self.assertFalse(list(archive.glob('*/*.log')))
    def test_cisco_and_rfc5424_priority_and_unknown_input(self):
        self.assertEqual(parse_message(b'<189>%LINK-5-CHANGED: lab link up')[:2], (23, 5))
        self.assertEqual(parse_message(b'<134>1 - sw app - - - ready')[:2], (16, 6))
        self.assertEqual(parse_message(b'%LINK-3-UPDOWN: lab link down')[:2], (None, 3))
        self.assertEqual(parse_message(b'<999>invalid')[:2], (None, None))

    def test_retention_filter_and_literal_search(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'logs.sqlite3'
            self.assertFalse(search('', path)['collector_ready'])
            db = writer(path)
            try:
                now = int(time.time())
                rows = [(now, '192.0.2.1', 23, 5, 'Link_100% up'),
                        (now, '192.0.2.2', 23, 4, 'other'),
                        (now - RETENTION_SECONDS - 10, '192.0.2.1', 23, 5, 'old')]
                with db:
                    db.executemany('INSERT INTO events(received,source,facility,severity,message) VALUES (?,?,?,?,?)', rows)
                result = search('source=192.0.2.1&severity=5&q=link_100%25', path)
                self.assertEqual([row['message'] for row in result['items']], ['Link_100% up'])
                self.assertEqual(len(search('', path)['items']), 2)
                prune(db, now)
                self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0], 2)
                for invalid in ('severity=8', 'source=not-ip', 'source=a&source=b', 'since=2026-01-01', 'unknown=x'):
                    with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                        search(invalid, path)
            finally:
                db.close()
