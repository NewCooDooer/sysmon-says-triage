"""Tests for export.py. Every test gets its own empty key file in a temporary folder; the events are hand-made."""

import json

import pytest

import export


@pytest.fixture(autouse=True)
def fresh_key(monkeypatch, tmp_path):
    monkeypatch.setattr(export, "KEY_FILE", tmp_path / "pseudonym_key.json")


def event(event_id, computer="PC-7.corp.example", **fields):
    return {"id": event_id, "time": "2026-01-01 09:00", "computer": computer, "fields": fields}


START = event(1, Image="C:\\Users\\alice\\Desktop\\tool.exe", User="PC-7\\alice",
              CommandLine="tool.exe --password hunter2", ParentUser="NT AUTHORITY\\SYSTEM")
REGISTRY = event(13, TargetObject="HKU\\S-1-5-21-1-2-3-1001\\Software\\Run")
TALK = event(3, SourceIp="10.1.2.3", DestinationIp="93.184.215.14", DestinationHostname="example.com")
LOOKUP = event(22, QueryName="fileserver", QueryResults="10.1.2.9;")


def test_each_kind_of_private_value_is_found_and_windows_own_accounts_are_not():
    found = export.find_private([START, REGISTRY, TALK, LOOKUP])
    assert found == {"pc-7.corp.example": "COMPUTER", "pc-7": "COMPUTER", "alice": "USER",
                     "s-1-5-21-1-2-3-1001": "ACCOUNT-ID", "10.1.2.3": "PRIVATE-IP", "10.1.2.9": "PRIVATE-IP",
                     "fileserver": "INTERNAL-NAME"}  # not "nt authority", "system", example.com or 93.184.215.14


def test_scrub_ignores_capitals_and_replaces_whole_names_only():
    key = {"alice": "USER-1", "10.0.0.1": "PRIVATE-IP-1"}
    assert export.scrub("C:\\Users\\ALICE\\x; alicea; 10.0.0.1 and 10.0.0.15", key) == (
        "C:\\Users\\USER-1\\x; alicea; PRIVATE-IP-1 and 10.0.0.15")


def test_the_key_is_saved_and_a_name_keeps_its_stand_in():
    first = export.key_for({"alice": "USER"})
    second = export.key_for({"bob": "USER", "alice": "USER"})
    assert first == {"alice": "USER-1"} and second == {"alice": "USER-1", "bob": "USER-2"}
    assert json.loads(export.KEY_FILE.read_text()) == second


def test_a_whole_name_left_blocks_but_one_inside_a_longer_word_is_only_listed():
    key = {"user": "USER-1", "alice": "USER-2"}
    whole, inside = export.leftovers("C:\\Users\\USER-1\\x and Alice wrote", key)
    assert whole == ["alice"]  # a real leak
    assert list(inside) == ["user"] and "Users" in inside["user"]  # only inside "Users"; "USER-1" is a stand-in


def test_the_share_safe_log_has_no_names_and_leaves_command_lines_out_unless_asked():
    text, whole, inside = export.share_safe_log([START, REGISTRY, TALK, LOOKUP])
    assert whole == [] and inside == {}
    for name in ("alice", "pc-7", "10.1.2.3", "s-1-5-21", "fileserver", "hunter2"):
        assert name not in text.lower()
    assert "USER-1" in text and "example.com" in text  # stand-ins in, public names kept
    with_free_text = export.share_safe_log([START], free_text=True)[0]
    assert "--password hunter2" in with_free_text  # included only when asked: no rule can recognise a password


def test_the_report_is_scrubbed_escaped_and_checked():
    found = export.find_in_history("PC-7", [{"kind": "program", "value": "C:\\Users\\alice\\tool.exe"},
                                            {"kind": "domain", "value": "fileserver"}])
    page, whole, inside = export.share_safe_report("PC-7: report", [("Programs", [{"Value": "C:\\Users\\alice\\<b>"}])],
                                                   found)
    assert whole == [] and "alice" not in page.lower() and "pc-7" not in page.lower()
    assert "&lt;b&gt;" in page  # escaped: text from a log can never act as code in a browser


def test_field_names_are_never_scrubbed_even_for_a_user_called_user():
    folder = event(11, computer="PC-7", TargetFilename="C:\\Users\\user\\notes.txt", User="PC-7\\user")
    text, whole, inside = export.share_safe_log([folder])
    fields = json.loads(text)[0]["fields"]
    assert set(fields) == {"TargetFilename", "User"}  # the field names are untouched
    assert fields["User"] == "COMPUTER-1\\USER-1" and whole == []
    assert "Users" in inside["user"]  # "user" inside "Users" is listed for a check by hand, not blocked
