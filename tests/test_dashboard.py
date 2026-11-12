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
