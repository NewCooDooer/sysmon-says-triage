"""The privacy gate: decides, for each IP address and domain name, whether it may leave this computer.

Every rule gives back (True or False, reason). True means "may be sent to a portal". Nothing here uses the network.
"""

import ipaddress

# Name endings that are internal by convention, or are reverse lookups (an address written as a name, ending in .arpa).
INTERNAL_ENDINGS = (".local", ".lan", ".internal", ".corp", ".home", ".localdomain", ".intranet", ".arpa")

# The address ranges set aside for an organisation's own network. Only an answer in one of these makes a name internal:
# 127.0.0.1 or 0.0.0.0 is where malware operators often park a dormant domain, so those names are still checked.
COMPANY_NETWORKS = [ipaddress.ip_network(text) for text in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def as_address(text):
    """The text as an IP address, or None if it is not one. "::ffff:1.2.3.4" is an IPv4 address written in IPv6 style."""
    text = text.strip().removeprefix("::ffff:")
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def may_send_ip(text):
    """Rule 1: only a public IPv4 address may be sent (the IP portal cannot look up IPv6)."""
    address = as_address(text)
    if address is None:
        return False, "not an IP address"
    if not address.is_global:  # is_global: reachable on the public internet; private, loopback and special ones are not
        return False, "private or special address: stays on this computer"
    if address.version == 6:
        return False, "IPv6: the IP portal cannot look it up"
    return True, "public address"


def answers_of(query_results):
    """The addresses in Sysmon's DNS answer text, such as "type: 5 other.name;::ffff:1.2.3.4;" (aliases are skipped)."""
    addresses = []
    for part in query_results.split(";"):
        address = as_address(part)
        if address is not None:
            addresses.append(address)
    return addresses


def may_send_name(name, query_results=""):
    """Rules 2, 3 and 4 for a domain name; query_results is Sysmon's recorded answer for it (may be empty)."""
    if "." not in name:
        return False, "a single word: a computer's local name"
    if name.endswith(INTERNAL_ENDINGS):  # endswith() accepts a group of endings and is True if any one matches
        return False, "an internal or reverse-lookup ending"
    if any(address in network for address in answers_of(query_results) for network in COMPANY_NETWORKS):
        return False, "it resolved to a company-network address, so it is internal"
    return True, "an internet name"
