"""History per computer: each upload, and every indicator ever seen, kept in one local SQLite file (never in git).

Plain SQL, no classes. Nothing here uses the network.
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import read_log

HISTORY_DB = Path(__file__).parent / "history.db"  # local only: listed in .gitignore

TABLES = """
CREATE TABLE IF NOT EXISTS uploads (computer TEXT, fingerprint TEXT, added_at TEXT, first_event TEXT, last_event TEXT,
                                    counts TEXT, PRIMARY KEY (computer, fingerprint));
CREATE TABLE IF NOT EXISTS sightings (computer TEXT, kind TEXT, value TEXT, first_seen TEXT, last_seen TEXT,
                                      uploads INTEGER, PRIMARY KEY (computer, kind, value));
CREATE TABLE IF NOT EXISTS answers (kind TEXT, value TEXT, checked_at TEXT, label TEXT, score NUMERIC, reasons TEXT);
"""


def connect():
    """Open the history file, creating the three tables the first time."""
    db = sqlite3.connect(HISTORY_DB)
    db.executescript(TABLES)
    return db


def now():
    """The time now, in UTC, to the second."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fingerprint(file_bytes):
    """A SHA-256 of the whole file: the same file always gives the same fingerprint."""
    return hashlib.sha256(file_bytes).hexdigest()


def indicators(events):
    """Per computer: {(kind, value): (first time, last time)} for programs, SHA-256s, launches, IPs and domains."""
    found = {}
    for event in events:
        fields = event["fields"]
        items = []
        if event["id"] == 1:
            image, parent = fields.get("Image", ""), fields.get("ParentImage", "")
            items.append(("program", image))
            hashes = read_log.split_hashes(fields.get("Hashes", ""))
            items.append(("hash", hashes.get("SHA256", "")))  # never the IMPHASH
            if parent and image:
                items.append(("launch", f"{parent} -> {image}"))
        elif event["id"] == 3:
            items.append(("ip", fields.get("DestinationIp", "")))
        elif event["id"] == 22:
            items.append(("domain", fields.get("QueryName", "").lower().rstrip(".")))
        seen = found.setdefault(event["computer"], {})  # setdefault: this computer's dictionary, created if missing
        for item in items:
            if item[1]:  # skip empty values
                first, last = seen.get(item, (event["time"], event["time"]))
                seen[item] = (min(first, event["time"]), max(last, event["time"]))
    return found


def add_upload(file_bytes, events):
    """Add a log to each of its computers' history. Gives back, per computer: how many uploads it now has, whether this
    file was already there, whether it is the computer's first upload, and the indicators that are new for it."""
    file_id, added_at = fingerprint(file_bytes), now()
    results = {}
    db = connect()
    with db:  # saves every change together at the end, or none of them if something fails
        for computer, seen in indicators(events).items():
            already = db.execute("SELECT 1 FROM uploads WHERE computer = ? AND fingerprint = ?",
                                 (computer, file_id)).fetchone()
            known = set(db.execute("SELECT kind, value FROM sightings WHERE computer = ?", (computer,)).fetchall())
            if not already:
                summary = read_log.summarize([event for event in events if event["computer"] == computer])
                db.execute("INSERT INTO uploads VALUES (?, ?, ?, ?, ?, ?)",
                           (computer, file_id, added_at, summary["first"], summary["last"],
                            json.dumps(summary["by_type"])))
                for (kind, value), (first, last) in seen.items():
                    db.execute("""INSERT INTO sightings VALUES (?, ?, ?, ?, ?, 1)
                                  ON CONFLICT (computer, kind, value) DO UPDATE SET uploads = uploads + 1,
                                      first_seen = min(first_seen, excluded.first_seen),
                                      last_seen = max(last_seen, excluded.last_seen)""",
                               (computer, kind, value, first, last))
            count = db.execute("SELECT COUNT(*) FROM uploads WHERE computer = ?", (computer,)).fetchone()[0]
            results[computer] = {"uploads": count, "already": bool(already), "first": not known,
                                 "new": [] if already else sorted(set(seen) - known)}
    db.close()
    return results


def save_answer(found):
    """Keep one portal answer with the time it was checked. Only real answers: a failure is tried again next time."""
    if found["status"] != "answered":
        return
    db = connect()
    with db:
        db.execute("INSERT INTO answers VALUES (?, ?, ?, ?, ?, ?)",
                   (found["portal"], found["value"], now(), found["label"], found["score"],
                    json.dumps(found["reasons"])))
    db.close()


def latest_answers(kind):
    """The newest answer for each value of one kind ("ip", "domain" or "hash"), as {value: answer} in portals.result's shape."""
    db = connect()
    rows = db.execute("SELECT value, checked_at, label, score, reasons FROM answers WHERE kind = ? "
                      "ORDER BY checked_at, rowid", (kind,)).fetchall()
    db.close()
    # Rows come oldest first, so a newer answer for the same value replaces the older one in the dictionary.
    return {value: {"portal": kind, "value": value, "status": "answered", "score": score, "label": label,
                    "reasons": json.loads(reasons), "message": "", "checked_at": checked_at}
            for value, checked_at, label, score, reasons in rows}


def read(sql, params=()):
    """Run one SELECT and give back its rows as dictionaries ({column name: value})."""
    db = connect()
    db.row_factory = sqlite3.Row  # rows that know their column names
    rows = [dict(row) for row in db.execute(sql, params)]
    db.close()
    return rows


def computers():
    """Every computer that has history, by name."""
    return [row["computer"] for row in read("SELECT DISTINCT computer FROM uploads ORDER BY computer")]


def uploads_of(computer):
    """One computer's uploads, oldest events first."""
    return read("SELECT * FROM uploads WHERE computer = ? ORDER BY first_event", (computer,))


def sightings_of(computer):
    """Everything ever seen on one computer."""
    return read("SELECT * FROM sightings WHERE computer = ? ORDER BY kind, value", (computer,))


def changes():
    """Every value whose two newest answers have different labels, with both answers: "before" and "now"."""
    answers = {}  # (kind, value) -> its answers, oldest first
    for row in read("SELECT kind, value, checked_at, label, score FROM answers ORDER BY checked_at, rowid"):
        answers.setdefault((row["kind"], row["value"]), []).append(row)
    return [{"kind": kind, "value": value, "before": found[-2], "now": found[-1]}
            for (kind, value), found in answers.items() if len(found) > 1 and found[-2]["label"] != found[-1]["label"]]


def seen_on(kind, value):
    """Which computers saw one value, and when last."""
    return read("SELECT computer, last_seen FROM sightings WHERE kind = ? AND value = ? ORDER BY computer", (kind, value))
