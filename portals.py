"""Talks to the three portals (their contracts, unchanged) and turns each answer into one common shape.

Only send() sends a value from the log, and it writes the value to the local sent record BEFORE sending it.
"""

import csv
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

# Where each portal's backend runs. Change with an environment variable if a portal uses another port.
URLS = {
    "hash": os.environ.get("HASH_PORTAL_URL", "http://127.0.0.1:8000"),
    "domain": os.environ.get("DNS_PORTAL_URL", "http://127.0.0.1:8010"),
    "ip": os.environ.get("IP_PORTAL_URL", "http://127.0.0.1:5001"),
}
# How long to wait for an answer, in seconds. A fresh domain lookup asks crt.sh, which can take about a minute.
WAIT = {"hash": 30, "domain": 100, "ip": 30}

SENT_RECORD = Path(__file__).parent / "sent_record.csv"  # local only: listed in .gitignore

# Requests that end up at the same outside service share one minimum gap, in seconds. The IP and domain portals both ask
# rdap.org, which allows 10 requests in 10 seconds; a burst made rdap.org refuse, and the refusals raised the portals' scores.
# VirusTotal (behind the hash portal) allows 4 requests a minute.
SHARED_SERVICE = {"ip": "rdap.org", "domain": "rdap.org", "hash": "VirusTotal"}
GAP = {"rdap.org": 1.5, "VirusTotal": 15}
last_sent = {}  # outside service -> when we last sent towards it (time.monotonic(), a clock that only counts forward)


def wait_turn(portal):
    """Sleep, if needed, until the minimum gap since the last request towards the same outside service has passed."""
    service = SHARED_SERVICE[portal]
    waited = time.monotonic() - last_sent.get(service, float("-inf"))  # -inf: "never sent", so no waiting the first time
    if waited < GAP[service]:
        time.sleep(GAP[service] - waited)
    last_sent[service] = time.monotonic()


def is_ready(portal):
    """True if the portal answers. The IP portal has no health route, so it is asked about a private address,
    which its contract answers without contacting any outside service."""
    path = "/api/ip/10.0.0.1" if portal == "ip" else "/api/v1/health"
    try:
        return requests.get(URLS[portal] + path, timeout=3).status_code == 200
    except requests.RequestException:
        return False


def write_record(portal, value):
    """Add one line to the sent record: when (UTC), which portal, and what was sent."""
    new_file = not SENT_RECORD.exists()
    with open(SENT_RECORD, "a", newline="") as file:
        writer = csv.writer(file)
        if new_file:
            writer.writerow(["sent_at_utc", "portal", "value"])
        writer.writerow([datetime.now(timezone.utc).isoformat(timespec="seconds"), portal, value])


def send(portal, path, value):
    """Wait for our turn, record the value, then ask the portal. Gives back (HTTP status, JSON body), or (None, problem)."""
    wait_turn(portal)
    write_record(portal, value)
    try:
        response = requests.get(URLS[portal] + path, timeout=WAIT[portal])
    except requests.Timeout:
        return None, f"no answer within {WAIT[portal]} seconds"
    except requests.RequestException:
        return None, "the portal could not be reached: is it running?"
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, {}


def result(portal, value, status, score=None, label=None, reasons=(), message=""):
    """The common shape every lookup result has, whichever portal answered."""
    return {"portal": portal, "value": value, "status": status, "score": score, "label": label,
            "reasons": list(reasons), "message": message}


def ask_ip(ip):
    """Ask the IP portal about one address (GET /api/ip/<ip>)."""
    code, body = send("ip", "/api/ip/" + ip, ip)
    if code == 200:
        verdict = body.get("verdict", {})
        return result("ip", ip, "answered", verdict.get("score"), verdict.get("level"), verdict.get("reasons", []))
    if code == 400:
        return result("ip", ip, "refused", message=body.get("message", "not accepted"))
    if code == 503:
        return result("ip", ip, "unavailable", message="every source behind the IP portal failed: try again later")
    return result("ip", ip, "error", message=body if code is None else f"unexpected answer (HTTP {code})")


def ask_domain(name):
    """Ask the domain portal about one name (GET /api/v1/domain/<name>)."""
    code, body = send("domain", "/api/v1/domain/" + name, name)
    if code == 200:
        assessment = body.get("assessment", {})
        reasons = [f"{source}: {block.get('score_reason', '')}" for source, block in body.get("sources", {}).items()]
        if assessment.get("verdict_note"):
            reasons.append(assessment["verdict_note"])
        return result("domain", name, "answered", assessment.get("average"), assessment.get("verdict_label"), reasons)
    if code == 400:
        return result("domain", name, "refused", message=body.get("error", "not accepted"))
    return result("domain", name, "error", message=body if code is None else f"unexpected answer (HTTP {code})")


def ask_hash(sha256):
    """Ask the hash portal about one program's SHA-256 (GET /api/v1/hash/<hash>)."""
    code, body = send("hash", "/api/v1/hash/" + sha256, sha256)
    if code == 200:
        verdict = body.get("verdict", {})
        return result("hash", sha256, "answered", verdict.get("score"), verdict.get("label"), verdict.get("reasons", []))
    if code == 400:
        return result("hash", sha256, "refused", message=body.get("error", "not accepted"))
    return result("hash", sha256, "error", message=body if code is None else f"unexpected answer (HTTP {code})")
