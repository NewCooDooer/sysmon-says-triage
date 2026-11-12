"""Tests for portals.py. The portals' answers are FAKED with the `responses` library, so no portal needs to be running,
and the waits between requests are recorded instead of slept."""

import re

import pytest
import requests
import responses

import portals

IP_URL = re.compile(r"http://127\.0\.0\.1:5001/api/ip/.*")
DOMAIN_URL = re.compile(r"http://127\.0\.0\.1:8010/api/v1/domain/.*")
HASH_URL = re.compile(r"http://127\.0\.0\.1:8000/api/v1/hash/.*")


@pytest.fixture(autouse=True)
def quiet(monkeypatch, tmp_path):
    """Every test: a fresh sent record in a temporary folder, no previous sends, and no real sleeping."""
    monkeypatch.setattr(portals, "SENT_RECORD", tmp_path / "sent_record.csv")
    monkeypatch.setattr(portals, "last_sent", {})
    slept = []
    monkeypatch.setattr(portals.time, "sleep", slept.append)  # record each wait instead of waiting
    return slept


@pytest.fixture
def mock():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as fake_web:
        yield fake_web


def record_lines():
    return portals.SENT_RECORD.read_text().strip().split("\n")


def test_an_ip_answer_is_translated_into_the_common_shape(mock):
    mock.add(responses.GET, IP_URL, json={"verdict": {"level": "no_known_bad", "score": 12, "reasons": ["a", "b"]}})
    assert portals.ask_ip("93.184.215.14") == {"portal": "ip", "value": "93.184.215.14", "status": "answered", "score": 12,
                                               "label": "no_known_bad", "reasons": ["a", "b"], "message": ""}


def test_ip_refused_and_unavailable_are_answers_not_crashes(mock):
    mock.add(responses.GET, IP_URL, status=400, json={"error": "unsupported_ip_version", "message": "IPv6 is not supported yet."})
    assert portals.ask_ip("2606:4700::1111")["status"] == "refused"
    mock.replace(responses.GET, IP_URL, status=503, json={"error": "sources_unavailable", "message": "..."})
    assert portals.ask_ip("93.184.215.14")["status"] == "unavailable"


def test_a_domain_answer_uses_the_assessment_and_each_sources_reason(mock):
    mock.add(responses.GET, DOMAIN_URL, json={
        "sources": {"dns": {"score_reason": "resolves to an address (-10)"}, "rdap": {"score_reason": "registered 5 years or more ago (-40)"}},
        "assessment": {"average": 25, "verdict_label": "Likely safe", "verdict_note": "only 2 of 3 sources gave a score"}})
    found = portals.ask_domain("example.com")
    assert found["status"] == "answered" and found["score"] == 25 and found["label"] == "Likely safe"
    assert found["reasons"] == ["dns: resolves to an address (-10)", "rdap: registered 5 years or more ago (-40)",
                                "only 2 of 3 sources gave a score"]


def test_a_portal_that_is_not_running_gives_an_error_result(mock):
    mock.add(responses.GET, DOMAIN_URL, body=requests.ConnectionError("refused"))
    assert portals.ask_domain("example.com")["message"] == "the portal could not be reached: is it running?"
    mock.replace(responses.GET, DOMAIN_URL, body=requests.Timeout("slow"))
    assert portals.ask_domain("example.com")["message"] == "no answer within 100 seconds"


def test_the_value_is_recorded_before_it_is_sent(mock):
    seen_in_record = []

    def answer(request):  # runs at the moment the request is "sent", so it shows what the record held by then
        seen_in_record.append(portals.SENT_RECORD.read_text())
        return 200, {}, '{"verdict": {}}'

    mock.add_callback(responses.GET, IP_URL, callback=answer)
    portals.ask_ip("93.184.215.14")
    assert "93.184.215.14" in seen_in_record[0]
    assert record_lines()[0] == "sent_at_utc,portal,value" and record_lines()[1].endswith(",ip,93.184.215.14")


def test_ip_and_domain_lookups_share_one_gap_because_both_reach_rdap_org(mock, quiet, monkeypatch):
    clock = iter([100.0, 100.0, 100.5, 101.5])  # the times time.monotonic() will give, one per call
    monkeypatch.setattr(portals.time, "monotonic", lambda: next(clock))
    mock.add(responses.GET, IP_URL, json={"verdict": {}})
    mock.add(responses.GET, DOMAIN_URL, json={"assessment": {}})
    portals.ask_ip("93.184.215.14")      # first request towards rdap.org: no wait
    portals.ask_domain("example.com")    # 0.5 s later, also towards rdap.org: must wait the rest of the 1.5 s gap
    assert quiet == [1.0]


def test_readiness_uses_a_private_address_for_the_ip_portal(mock):
    mock.add(responses.GET, "http://127.0.0.1:5001/api/ip/10.0.0.1", json={"verdict": {"level": "not_applicable"}})
    mock.add(responses.GET, "http://127.0.0.1:8010/api/v1/health", body=requests.ConnectionError("down"))
    assert portals.is_ready("ip") is True
    assert portals.is_ready("domain") is False
    assert not portals.SENT_RECORD.exists()  # a readiness check sends nothing from the log, so nothing is recorded


def test_a_hash_answer_uses_the_portals_verdict_and_a_refusal_is_not_a_crash(mock):
    mock.add(responses.GET, HASH_URL, json={"sources": {}, "verdict": {"score": 90, "label": "malicious", "reasons": ["a"]}})
    found = portals.ask_hash("aa11")
    assert (found["status"], found["score"], found["label"], found["reasons"]) == ("answered", 90, "malicious", ["a"])
    mock.replace(responses.GET, HASH_URL, status=400, json={"error": "Expected 32, 40 or 64 hex characters"})
    assert portals.ask_hash("aa11")["message"] == "Expected 32, 40 or 64 hex characters"
    mock.replace(responses.GET, HASH_URL, body=requests.ConnectionError("down"))
    assert portals.ask_hash("aa11")["status"] == "error"


def test_hash_lookups_keep_the_virustotal_gap(mock, quiet):
    mock.add(responses.GET, HASH_URL, json={"verdict": {}})
    portals.ask_hash("aa11")
    portals.ask_hash("cc33")
    assert len(quiet) == 1 and quiet[0] > 14  # the second hash waited about 15 seconds; the first did not wait
