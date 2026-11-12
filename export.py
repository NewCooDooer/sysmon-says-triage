"""Share-safe export: every internal name is replaced by a stand-in (COMPUTER-1, USER-1, ...), then the result is checked.

The stand-ins are kept in a local key file (never in git), so the same name always gets the same stand-in, and the analyst can
translate a reply back. Nothing here uses the network: an export is a file the analyst downloads and decides to send.
"""

import html
import json
import re
from pathlib import Path

import gate
import read_log

KEY_FILE = Path(__file__).parent / "pseudonym_key.json"  # local only: listed in .gitignore

# Windows' own accounts and folders, and generic account names: they identify nobody, and keeping them helps the reader.
# A generic name would also set off the self-check's "inside a longer word" note everywhere ("user" inside "Users").
BUILT_IN = {"nt authority", "window manager", "font driver host", "public", "default", "default user", "all users", "-", "",
            "user", "admin", "administrator", "guest", "test", "owner"}
USER_FIELDS = ("User", "ParentUser", "SourceUser", "TargetUser")  # each holds "COMPUTER\user"
FREE_TEXT = ("CommandLine", "ParentCommandLine", "Contents")  # can hold anything, so left out unless the analyst asks


def add(found, value, kind):
    """Note one value to replace, unless it is one of Windows' own. A full computer name also adds its first part."""
    if value.lower() not in BUILT_IN:
        found.setdefault(value.lower(), kind)
        if kind == "COMPUTER" and "." in value:
            add(found, value.split(".")[0], kind)


def add_from_text(found, text):
    """User folders (C:\\Users\\<name>) and Windows account IDs (S-1-5-21-...) anywhere in a text."""
    for folder in re.findall(r"(?i)\\users\\([^\\\"\s]+)", text):
        add(found, folder, "USER")
    for account_id in re.findall(r"S-1-5-21-[\d-]+", text):
        add(found, account_id, "ACCOUNT-ID")


def add_if_private(found, value, kind):
    """A domain name the gate keeps local, or an address that is not on the public internet."""
    address = gate.as_address(value)
    if address is not None and not address.is_global:
        add(found, str(address), "PRIVATE-IP")
    elif address is None and kind == "domain" and not gate.may_send_name(value)[0]:
        add(found, value, "INTERNAL-NAME")


def find_private(events):
    """Every value in a log to replace, as {original in lowercase: kind}, using the gate's own rules."""
    found = {}
    for event in events:
        fields = event["fields"]
        add(found, event["computer"], "COMPUTER")
        for name in USER_FIELDS:
            computer, slash, user = fields.get(name, "").rpartition("\\")
            if slash and computer.lower() not in BUILT_IN:
                add(found, computer, "COMPUTER")
                add(found, user, "USER")
        for text in fields.values():
            add_from_text(found, text)
        for name in ("SourceIp", "DestinationIp"):
            add_if_private(found, fields.get(name, ""), "ip")
        for name in ("SourceHostname", "DestinationHostname"):
            if fields.get(name):
                add_if_private(found, fields[name].lower(), "domain")
    for name, answers in read_log.name_answers(events).items():
        if not gate.may_send_name(name, answers)[0]:
            add(found, name, "INTERNAL-NAME")
        for address in gate.answers_of(answers):
            add_if_private(found, str(address), "ip")
    return found


def find_in_history(computer, sightings):
    """The same, for one computer's history: its name, user folders in program paths, and private names and addresses."""
    found = {}
    add(found, computer, "COMPUTER")
    for s in sightings:
        add_from_text(found, s["value"])
        add_if_private(found, s["value"], s["kind"])
    return found


def key_for(found):
    """The saved key, plus a new stand-in for every value not seen before. Saved again, so stand-ins never change."""
    key = json.loads(KEY_FILE.read_text()) if KEY_FILE.exists() else {}
    for original, kind in sorted(found.items()):  # sorted, so the same log always numbers its names the same way
        if original not in key:
            number = sum(standin.rsplit("-", 1)[0] == kind for standin in key.values()) + 1
            key[original] = f"{kind}-{number}"
    KEY_FILE.write_text(json.dumps(key, indent=1, sort_keys=True))
    # A name saved before it joined BUILT_IN keeps its line in the file, so its number is never given to someone else,
    # but it is no longer replaced or checked.
    return {original: standin for original, standin in key.items() if original not in BUILT_IN}


def scrub(text, key):
    """The text with each original replaced by its stand-in: whole names only, ignoring capitals, longest first."""
    if not key:
        return text
    names = "|".join(re.escape(original) for original in sorted(key, key=len, reverse=True))
    # (?<![a-z0-9]) and (?![a-z0-9]): no letter or digit just before or after, so "10.0.0.1" never matches inside "10.0.0.15"
    return re.sub(rf"(?<![a-z0-9])({names})(?![a-z0-9])", lambda m: key[m.group(1).lower()], text, flags=re.IGNORECASE)


def leftovers(text, key):
    """The self-check, on the finished text: originals still there as whole names (a leak, so no download), and originals
    found only inside a longer word, such as "user" inside "Users", each with an example, for the analyst to check by hand."""
    lower = text.lower()
    for standin in sorted(set(key.values()), key=len, reverse=True):  # the stand-ins out first: "user" is inside "USER-3"
        lower = lower.replace(standin.lower(), "#" * len(standin))  # the same length, so positions still match `text`
    whole, inside = [], {}
    for original in sorted(key):
        if re.search(rf"(?<![a-z0-9]){re.escape(original)}(?![a-z0-9])", lower):
            whole.append(original)
        elif original in lower:
            at = lower.index(original)
            inside[original] = text[max(0, at - 25):at + len(original) + 25]
    return whole, inside


def share_safe_log(events, free_text=False):
    """The log's events as JSON text with every value scrubbed, and what the self-check found (no whole names = safe).
    Only values are scrubbed and checked, never field names such as "User": a user called "user" must not rename them."""
    key = key_for(find_private(events))
    kept = [{"id": event["id"], "time": event["time"], "computer": scrub(event["computer"], key),
             "fields": {name: scrub(value, key) for name, value in event["fields"].items()
                        if free_text or name not in FREE_TEXT}} for event in events]
    values = "\n".join(event["computer"] + "\n" + "\n".join(event["fields"].values()) for event in kept)
    return (json.dumps(kept, indent=1, ensure_ascii=False), *leftovers(values, key))  # the text, whole names, inside words


def share_safe_report(title, sections, found):
    """A plain HTML page, one table per section, every value scrubbed and then escaped; and what the self-check found.
    Our own headings and column names are not scrubbed or checked: they come from this code, not from a log."""
    key = key_for(found)
    title = scrub(title, key)
    sections = [(heading, [{column: scrub(str(value), key) for column, value in row.items()} for row in rows])
                for heading, rows in sections]
    def cell(text, tag="td"):
        return f"<{tag}>{html.escape(text)}</{tag}>"  # escaped, so no text from a log can act as code in a browser
    parts = [f"<h1>{html.escape(title)}</h1>"]
    for heading, rows in sections:
        parts.append(f"<h2>{html.escape(heading)}</h2>")
        if rows:
            parts.append("<table><tr>" + "".join(cell(column, "th") for column in rows[0]) + "</tr>")
            parts += ["<tr>" + "".join(cell(value) for value in row.values()) + "</tr>" for row in rows]
            parts.append("</table>")
        else:
            parts.append("<p>None.</p>")
    page = ("<!doctype html><meta charset='utf-8'><title>Share-safe report</title><style>body{font-family:sans-serif} "
            "td,th{border:1px solid #999;padding:4px;text-align:left}</style>" + "\n".join(parts))
    values = "\n".join([title] + [value for _, rows in sections for row in rows for value in row.values()])
    return (page, *leftovers(values, key))
