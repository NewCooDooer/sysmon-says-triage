"""Reads a Sysmon log (.evtx file) and turns each event into a plain Python dictionary. Nothing here uses the network."""

import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx

# Every tag in the event's XML lives in this "namespace" (a long name prefix), so searches must include it.
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

SYSMON = "Microsoft-Windows-Sysmon"

# The Sysmon event types this app talks about, by number. Any other number is shown as "Sysmon event N".
EVENT_NAMES = {
    1: "Process started",
    3: "Network connection",
    4: "Sysmon started or stopped",
    5: "Process ended",
    7: "Image (DLL) loaded",
    8: "Remote thread created",
    11: "File created",
    12: "Registry key created or deleted",
    13: "Registry value set",
    15: "File stream created (download marker)",
    22: "DNS query",
    255: "Sysmon's own error",
}


def event_name(event_id):
    """A readable name for a Sysmon event number."""
    return EVENT_NAMES.get(event_id, f"Sysmon event {event_id}")


def event_from_xml(xml_text):
    """Turn one event's XML into {"id", "time", "computer", "fields"}, or None if Sysmon did not write it."""
    root = ET.fromstring(xml_text)
    system = root.find("e:System", NS)
    if system.find("e:Provider", NS).get("Name") != SYSMON:
        return None
    fields = {}
    for data in root.findall("e:EventData/e:Data", NS):
        fields[data.get("Name")] = data.text or ""  # an empty field comes back as None, so use "" instead
    return {
        "id": int(system.find("e:EventID", NS).text),
        "time": system.find("e:TimeCreated", NS).get("SystemTime"),
        "computer": system.find("e:Computer", NS).text or "",
        "fields": fields,
    }


def read_events(path):
    """Every Sysmon event in the .evtx file at `path`, oldest first."""
    events = []
    with Evtx(path) as log:
        for record in log.records():
            event = event_from_xml(record.xml())
            if event is not None:
                events.append(event)
    return events


def split_hashes(text):
    """Sysmon's "SHA1=AB..,MD5=CD..,SHA256=EF.." becomes {"SHA1": "ab..", "MD5": "cd..", "SHA256": "ef.."}."""
    hashes = {}
    for part in text.split(","):
        name, equals, value = part.partition("=")
        if equals and value:
            hashes[name.strip().upper()] = value.strip().lower()
    return hashes


def summarize(events):
    """What was learned from a log: counts per event type, computers, time span, programs, names and addresses."""
    by_type, computers, programs, hash_types = {}, set(), set(), set()
    domains, addresses = set(), set()
    for event in events:
        name = event_name(event["id"])
        by_type[name] = by_type.get(name, 0) + 1
        computers.add(event["computer"])
        fields = event["fields"]
        if event["id"] == 1:
            programs.add(fields.get("Image", ""))
            hash_types.update(split_hashes(fields.get("Hashes", "")))  # update() with a dict adds its keys
        elif event["id"] == 3:
            addresses.add(fields.get("DestinationIp", ""))
        elif event["id"] == 22:
            domains.add(fields.get("QueryName", "").lower().rstrip("."))
    times = sorted(event["time"] for event in events)
    return {
        "events": len(events),
        "by_type": by_type,
        "computers": sorted(computers),
        "first": times[0] if times else None,
        "last": times[-1] if times else None,
        "programs": sorted(programs - {""}),
        "hash_types": sorted(hash_types),
        "domains": sorted(domains - {""}),
        "addresses": sorted(addresses - {""}),
    }
