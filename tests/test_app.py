"""Tests for app.py: importing it draws nothing (main() runs only under Streamlit), and the rows the gate lets out are
split into already checked, new, and waiting. The rows and answers are hand-made."""

import app

ANSWERS = {"IP address": {"8.8.8.8": {"value": "8.8.8.8", "label": "no_known_bad"}}, "Domain name": {}, "File hash": {}}


def row(kind, value, waits=False):
    """One row the privacy gate let out, as gate_rows makes it."""
    return {"kind": kind, "value": value, "allowed": True, "reason": "", "waits": waits}


def test_rows_split_into_checked_new_and_waiting():
    to_send = [row("IP address", "8.8.8.8"), row("Domain name", "example.com"),
               row("File hash", "AA11"), row("File hash", "BB22", waits=True)]
    checked, unchecked, waiting = app.split_by_history(to_send, ANSWERS)
    assert checked == [ANSWERS["IP address"]["8.8.8.8"]]  # history's verdict, so it is not sent again
    assert [r["value"] for r in unchecked] == ["example.com", "AA11"]
    assert [r["value"] for r in waiting] == ["BB22"]


def test_a_waiting_program_already_checked_counts_as_checked():
    answers = dict(ANSWERS, **{"File hash": {"BB22": {"value": "BB22", "label": "safe"}}})
    checked, unchecked, waiting = app.split_by_history([row("File hash", "BB22", waits=True)], answers)
    assert (len(checked), unchecked, waiting) == (1, [], [])
