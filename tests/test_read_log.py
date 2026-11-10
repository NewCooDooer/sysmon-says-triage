"""Tests for read_log.py. The events are HAND-MADE in the same shape as real Sysmon events, so no real log is committed."""

import os

import pytest

import read_log


def make_xml(event_id, fields, provider="Microsoft-Windows-Sysmon", computer="TEST-PC", time="2026-01-01 10:00:00"):
    """One event's XML, built by hand in the shape Windows writes (System part, then EventData part)."""
    data = "".join(f'<Data Name="{name}">{value}</Data>' for name, value in fields.items())
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{provider}"/><EventID>{event_id}</EventID><TimeCreated SystemTime="{time}"/>'
        f"<Computer>{computer}</Computer></System><EventData>{data}</EventData></Event>"
    )


def test_a_sysmon_event_becomes_a_plain_dictionary():
    event = read_log.event_from_xml(make_xml(3, {"DestinationIp": "93.184.215.14", "DestinationPort": "443"}))
    assert event == {"id": 3, "time": "2026-01-01 10:00:00", "computer": "TEST-PC",
                     "fields": {"DestinationIp": "93.184.215.14", "DestinationPort": "443"}}


def test_an_event_from_another_program_is_ignored():
    assert read_log.event_from_xml(make_xml(4624, {}, provider="Microsoft-Windows-Security-Auditing")) is None


def test_an_empty_field_becomes_an_empty_text():
    assert read_log.event_from_xml(make_xml(1, {"CommandLine": ""}))["fields"]["CommandLine"] == ""


def test_hashes_are_split_by_type_and_lowercased():
    assert read_log.split_hashes("SHA1=AB12,MD5=CD34,SHA256=EF56,IMPHASH=00") == {
        "SHA1": "ab12", "MD5": "cd34", "SHA256": "ef56", "IMPHASH": "00"}
    assert read_log.split_hashes("") == {}
    assert read_log.split_hashes("-") == {}


def test_event_names_have_a_fallback():
    assert read_log.event_name(22) == "DNS query"
    assert read_log.event_name(999) == "Sysmon event 999"


def test_the_summary_counts_types_and_collects_names_and_addresses():
    events = [read_log.event_from_xml(x) for x in [
        make_xml(1, {"Image": "C:\\Windows\\System32\\cmd.exe", "Hashes": "MD5=AA,SHA256=BB"}, time="2026-01-01 10:00:02"),
        make_xml(1, {"Image": "C:\\Windows\\System32\\cmd.exe", "Hashes": "MD5=AA,SHA256=BB"}, time="2026-01-01 10:00:01"),
        make_xml(3, {"DestinationIp": "10.0.0.5"}),
        make_xml(22, {"QueryName": "Example.COM."}),
    ]]
    summary = read_log.summarize(events)
    assert summary["events"] == 4
    assert summary["by_type"] == {"Process started": 2, "Network connection": 1, "DNS query": 1}
    assert summary["programs"] == ["C:\\Windows\\System32\\cmd.exe"]  # the same program twice counts once
    assert summary["hash_types"] == ["MD5", "SHA256"]
    assert summary["domains"] == ["example.com"]  # lowercased, trailing dot dropped
    assert summary["addresses"] == ["10.0.0.5"]
    assert summary["first"] == "2026-01-01 10:00:00" and summary["last"] == "2026-01-01 10:00:02"


def test_an_empty_log_has_an_empty_summary():
    summary = read_log.summarize([])
    assert summary["events"] == 0 and summary["first"] is None and summary["domains"] == []


# A REAL log is never committed. To also test one, run:  SAMPLE_LOG=/path/to/events.evtx python -m pytest
@pytest.mark.skipif(not os.environ.get("SAMPLE_LOG"), reason="set SAMPLE_LOG to a real .evtx file to run this test")
def test_a_real_log_reads_without_errors():
    events = read_log.read_events(os.environ["SAMPLE_LOG"])
    assert len(events) > 0
    assert all(isinstance(event["id"], int) and event["time"] for event in events)
