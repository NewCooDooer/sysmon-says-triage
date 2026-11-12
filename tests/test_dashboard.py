"""Tests for the dashboard's logic (not its drawing). The uploads and sightings are hand-made, in history's shape."""

import dashboard

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
