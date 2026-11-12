"""Program hashes, and the five "ordinary file" checks that decide which are looked up first. Nothing here uses the network.

VirusTotal allows only 4 lookups a minute, so a program that looks like an ordinary Windows file waits for a second button.
Each check alone can be faked, so a program waits only if it passes all five; failing one puts it in the first lookup.
"""

import read_log

WINDOWS_FOLDER = "c:\\windows\\"


def checks_failed(fields, created, networked):
    """Which of the five checks this program start (event 1) fails. An empty list means it looks like an ordinary file."""
    image = fields.get("Image", "").lower()
    run_name = image.rsplit("\\", 1)[-1]  # the part after the last backslash: the file's name
    passed = {
        "not labelled Microsoft": fields.get("Company", "") == "Microsoft Corporation",
        "outside the Windows folder": image.startswith(WINDOWS_FOLDER),
        "run under another name": run_name == fields.get("OriginalFileName", "").lower(),
        "created during the log": image not in created,
        "used the network": image not in networked,
    }
    return [check for check, ok in passed.items() if not ok]


def queue(events):
    """Each program's SHA-256 once, with the program and the checks it fails: most failed first. Never the IMPHASH."""
    created = {e["fields"].get("TargetFilename", "").lower() for e in events if e["id"] == 11}  # 11: File created
    networked = {e["fields"].get("Image", "").lower() for e in events if e["id"] in (3, 22)}  # a connection or a DNS query
    found = {}
    for event in events:
        sha256 = read_log.split_hashes(event["fields"].get("Hashes", "")).get("SHA256", "")
        if event["id"] == 1 and sha256 and sha256 not in found:
            found[sha256] = {"value": sha256, "program": event["fields"].get("Image", ""),
                             "failed": checks_failed(event["fields"], created, networked)}
    return sorted(found.values(), key=lambda item: -len(item["failed"]))  # minus: the most failed checks first
