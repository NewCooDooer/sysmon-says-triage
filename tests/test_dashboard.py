"""Tests for the dashboard's logic (not its drawing). The uploads and sightings are hand-made, in history's shape."""

import dashboard
import history

UPLOADS = [{"first_event": "2026-01-01 09:00", "last_event": "2026-01-01 10:00"},
           {"first_event": "2026-01-02 09:00", "last_event": "2026-01-02 10:00"}]


def sighting(kind, value, first, last):
    return {"kind": kind, "value": value, "first_seen": first, "last_seen": last, "uploads": 1}


STAYED = sighting("program", "a.exe", "2026-01-01 09:10", "2026-01-02 09:10")  # in both uploads
QUIET = sighting("program", "agent.exe", "2026-01-01 09:20", "2026-01-01 09:20")  # only in the first
ARRIVED = sighting("domain", "example.com", "2026-01-02 09:30", "2026-01-02 09:30")  # only in the latest


def test_new_gone_quiet_and_new_per_upload():
    new, gone, per_upload = dashboard.compare(UPLOADS, [STAYED, QUIET, ARRIVED])
    assert new == [ARRIVED]
    assert gone == [QUIET]
    assert per_upload == [2, 1]  # a.exe and agent.exe first appeared in upload 1; example.com in upload 2


def test_only_the_portals_own_bad_labels_are_flagged():
    answers = {"domain": {"example.com": {"label": "Likely malware"}, "example.org": {"label": "Undetermined"}},
               "ip": {"93.184.215.14": {"label": "no_known_bad"}}}
    assert dashboard.verdict(ARRIVED, answers) in dashboard.FLAGGED
    assert dashboard.verdict(sighting("domain", "example.org", "", ""), answers) not in dashboard.FLAGGED
    assert dashboard.verdict(sighting("ip", "93.184.215.14", "", ""), answers) not in dashboard.FLAGGED
    assert dashboard.verdict(STAYED, answers) == ""  # never checked: no verdict, never flagged


def change(kind, value, before, now):
    return {"kind": kind, "value": value, "before": {"label": before}, "now": {"label": now}}


def test_the_dashboard_keeps_only_this_computers_changes():
    changed = [change("domain", "example.com", "Likely safe", "Likely malware"), change("ip", "198.51.100.7", "a", "b")]
    assert dashboard.mine(changed, [ARRIVED, STAYED]) == [changed[0]]


def test_newly_flagged_means_it_was_not_flagged_before():
    worse = change("domain", "example.com", "Likely safe", "Likely malware")
    better = change("domain", "example.org", "Likely malware", "Undetermined")
    still = change("hash", "aa11", "suspicious", "malicious")  # flagged before and now: not new
    assert dashboard.newly_flagged([worse, better, still]) == [worse]


def test_a_hash_row_names_its_program_and_other_rows_do_not():
    rows = dashboard.table([sighting("hash", "aa11", "", ""), ARRIVED], {}, {"aa11": "C:\\Tools\\a.exe"})
    assert [row["Program"] for row in rows] == ["C:\\Tools\\a.exe", ""]


def item(kind, value, computers, first_seen="2026-01-01 09:00"):
    return {"kind": kind, "value": value, "computers": computers, "first_seen": first_seen}


def test_the_overview_puts_widespread_flags_and_rare_items_in_order():
    answers = {"domain": {"bad.example": {"label": "Likely malware"}, "worse.example": {"label": "Definitely malware"},
                          "odd.example": {"label": "Likely malware"}}}
    items = [item("domain", "bad.example", 2), item("domain", "worse.example", 5), item("domain", "fine.example", 3),
             item("program", "old.exe", 1, "2026-01-01"), item("program", "new.exe", 1, "2026-01-03"),
             item("domain", "odd.example", 1, "2026-01-02"), item("launch", "a -> b", 1)]
    spread, rare = dashboard.fleet(items, answers)
    assert [i["value"] for i in spread] == ["worse.example", "bad.example"]  # flagged and on several, most widespread first
    assert [i["value"] for i in rare] == ["odd.example", "new.exe", "old.exe"]  # flagged first, then newest; no launches


def test_computers_are_listed_most_flagged_first(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "HISTORY_DB", tmp_path / "history.db")
    events = [{"id": 22, "time": "2026-01-01 09:00", "computer": computer, "fields": {"QueryName": name}}
              for computer, name in [("PC-1", "fine.example"), ("PC-2", "bad.example"), ("PC-2", "worse.example")]]
    history.add_upload(b"log one", events)
    answers = {"domain": {"bad.example": {"label": "Likely malware"}, "worse.example": {"label": "Likely malware"}}}
    rows = dashboard.computer_rows(answers, [])
    assert [(row["Computer"], row["Flagged"]) for row in rows] == [("PC-2", 2), ("PC-1", 0)]


def test_a_flagged_row_says_why_in_the_portals_own_words():
    reasons = ["dns: short lifetimes (+20)", "crtsh: new (+25)"]  # in the portal's own words
    answers = {"domain": {"example.com": {"label": "Likely malware", "reasons": reasons}}}
    assert dashboard.why(ARRIVED, answers) == "dns: short lifetimes (+20); crtsh: new (+25)"
    assert dashboard.why(STAYED, answers) == ""  # never checked: no reasons
    assert dashboard.table([ARRIVED], answers, {})[0]["Why"] == "dns: short lifetimes (+20); crtsh: new (+25)"
