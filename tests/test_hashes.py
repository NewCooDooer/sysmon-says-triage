"""Tests for hashes.py: the five ordinary-file checks and the lookup order. The events are hand-made."""

import hashes

ORDINARY = {"Image": "C:\\Windows\\System32\\notepad.exe", "Company": "Microsoft Corporation",
            "OriginalFileName": "NOTEPAD.EXE", "Hashes": "SHA256=AA11,IMPHASH=BB22"}


def start(sha256="AA11", **changes):
    """A program start (event 1): the ordinary one above, with some fields changed."""
    fields = dict(ORDINARY, Hashes=f"SHA256={sha256},IMPHASH=BB22", **changes)
    return {"id": 1, "time": "2026-01-01 09:00", "computer": "PC-1", "fields": fields}


def test_an_ordinary_windows_program_passes_all_five():
    assert hashes.checks_failed(ORDINARY, created=set(), networked=set()) == []


def test_each_check_fails_on_its_own():
    image = ORDINARY["Image"].lower()
    assert hashes.checks_failed(dict(ORDINARY, Company="Evil Ltd"), set(), set()) == ["not labelled Microsoft"]
    moved = dict(ORDINARY, Image="C:\\Users\\Public\\notepad.exe")
    assert hashes.checks_failed(moved, set(), set()) == ["outside the Windows folder"]
    renamed = dict(ORDINARY, Image="C:\\Windows\\System32\\svchost.exe")
    assert hashes.checks_failed(renamed, set(), set()) == ["run under another name"]
    assert hashes.checks_failed(ORDINARY, created={image}, networked=set()) == ["created during the log"]
    assert hashes.checks_failed(ORDINARY, created=set(), networked={image}) == ["used the network"]


def test_the_queue_puts_unusual_programs_first_and_lists_each_hash_once():
    created = {"id": 11, "time": "", "computer": "PC-1", "fields": {"TargetFilename": "C:\\Users\\Public\\tool.exe"}}
    talked = {"id": 3, "time": "", "computer": "PC-1", "fields": {"Image": "C:\\Users\\Public\\tool.exe"}}
    events = [start(), start(), start("CC33", Image="C:\\Users\\Public\\tool.exe", Company=""), created, talked]
    found = hashes.queue(events)
    assert [item["value"] for item in found] == ["cc33", "aa11"]  # lowercase, once each, the unusual one first
    assert len(found[0]["failed"]) == 5 and found[1]["failed"] == []


def test_only_the_sha256_is_queued_never_the_imphash():
    no_sha256 = start()
    no_sha256["fields"]["Hashes"] = "MD5=DD44,IMPHASH=BB22"
    assert hashes.queue([no_sha256]) == []
