"""Tests for history.py. Every test gets its own empty history file in a temporary folder; the events are hand-made."""

import pytest

import history


@pytest.fixture(autouse=True)
def fresh_history(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "HISTORY_DB", tmp_path / "history.db")


def event(event_id, time, computer="PC-1", **fields):
    return {"id": event_id, "time": time, "computer": computer, "fields": fields}


START = event(1, "2026-01-01 09:00", Image="C:\\Tools\\a.exe", ParentImage="C:\\Windows\\explorer.exe",
              Hashes="SHA256=AA11,IMPHASH=BB22")
LOOKUP = event(22, "2026-01-01 09:05", QueryName="Example.com.")


def test_a_first_upload_says_everything_is_new():
    found = history.add_upload(b"log one", [START, LOOKUP])["PC-1"]
    assert found["uploads"] == 1 and found["first"] and not found["already"]
    assert found["new"] == [("domain", "example.com"), ("hash", "aa11"),
                            ("launch", "C:\\Windows\\explorer.exe -> C:\\Tools\\a.exe"), ("program", "C:\\Tools\\a.exe")]


def test_a_second_upload_lists_only_what_is_new_and_updates_the_dates():
    history.add_upload(b"log one", [START, LOOKUP])
    later = event(22, "2026-01-02 10:00", QueryName="example.com")
    found = history.add_upload(b"log two", [later, event(3, "2026-01-02 10:01", DestinationIp="93.184.215.14")])["PC-1"]
    assert found["uploads"] == 2 and not found["first"]
    assert found["new"] == [("ip", "93.184.215.14")]
    db = history.connect()
    assert db.execute("SELECT first_seen, last_seen, uploads FROM sightings WHERE kind = 'domain'").fetchone() == (
        "2026-01-01 09:05", "2026-01-02 10:00", 2)


def test_the_same_file_twice_is_counted_once():
    history.add_upload(b"log one", [START])
    found = history.add_upload(b"log one", [START])["PC-1"]
    assert found["already"] and found["uploads"] == 1 and found["new"] == []
    db = history.connect()
    assert db.execute("SELECT uploads FROM sightings WHERE kind = 'program'").fetchone() == (1,)


def test_two_computers_in_one_log_keep_separate_histories():
    found = history.add_upload(b"log one", [START, event(22, "2026-01-01 09:06", "PC-2", QueryName="example.org")])
    assert found["PC-1"]["first"] and found["PC-2"]["first"]
    assert found["PC-2"]["new"] == [("domain", "example.org")]


def test_only_the_sha256_is_kept_never_the_imphash():
    history.add_upload(b"log one", [START])
    db = history.connect()
    assert db.execute("SELECT value FROM sightings WHERE kind = 'hash'").fetchall() == [("aa11",)]


def answer(value, label, status="answered", portal="domain"):
    return {"portal": portal, "value": value, "status": status, "score": 10, "label": label, "reasons": ["a reason"],
            "message": ""}


def test_only_real_answers_are_kept_and_the_newest_wins(monkeypatch):
    times = iter(["2026-01-01T09:00:00+00:00", "2026-01-02T09:00:00+00:00"])
    monkeypatch.setattr(history, "now", lambda: next(times))
    history.save_answer(answer("example.com", "Likely safe"))
    history.save_answer(answer("example.com", "", status="error"))  # a failure is not saved, so it is tried again
    history.save_answer(answer("example.com", "Likely malware"))
    found = history.latest_answers("domain")["example.com"]
    assert found["label"] == "Likely malware" and found["checked_at"] == "2026-01-02T09:00:00+00:00"
    assert found["reasons"] == ["a reason"]
    db = history.connect()
    assert db.execute("SELECT COUNT(*) FROM answers").fetchone() == (2,)  # the older answer is kept, for retro-hunting


def test_answers_are_kept_apart_by_kind():
    history.save_answer(answer("93.184.215.14", "no_known_bad", portal="ip"))
    assert history.latest_answers("domain") == {}
    assert list(history.latest_answers("ip")) == ["93.184.215.14"]


def test_the_dashboard_reads_one_computers_history():
    history.add_upload(b"log one", [START, event(22, "2026-01-01 09:06", "PC-2", QueryName="example.org")])
    assert history.computers() == ["PC-1", "PC-2"]
    assert [u["first_event"] for u in history.uploads_of("PC-1")] == ["2026-01-01 09:00"]
    assert [s["kind"] for s in history.sightings_of("PC-2")] == ["domain"]
