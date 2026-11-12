"""Tests for gate.py, the privacy gate. The addresses and names are made up or are well-known public examples."""

import gate


def test_only_public_ipv4_addresses_may_be_sent():
    assert gate.may_send_ip("93.184.215.14") == (True, "public address")
    for local in ("10.0.0.5", "192.168.1.20", "172.16.4.4", "127.0.0.1", "169.254.1.1", "0.0.0.0"):
        assert gate.may_send_ip(local)[0] is False, local


def test_ipv6_is_never_sent_and_says_why():
    assert gate.may_send_ip("2606:4700::1111") == (False, "IPv6: the IP portal cannot look it up")
    assert gate.may_send_ip("fe80::1")[1] == "private or special address: stays on this computer"


def test_an_ipv4_address_written_in_ipv6_style_counts_as_ipv4():
    assert gate.may_send_ip("::ffff:93.184.215.14") == (True, "public address")


def test_text_that_is_not_an_address_is_never_sent():
    assert gate.may_send_ip("not-an-address") == (False, "not an IP address")


def test_dns_answers_are_read_and_aliases_skipped():
    answers = gate.answers_of("type: 5 other.example;::ffff:93.184.215.14;10.0.0.5;fe80::1;")
    assert [str(a) for a in answers] == ["93.184.215.14", "10.0.0.5", "fe80::1"]
    assert gate.answers_of("-") == [] and gate.answers_of("") == []


def test_a_single_word_stays_local():
    assert gate.may_send_name("fileserver") == (False, "a single word: a computer's local name")


def test_internal_and_reverse_lookup_endings_stay_local():
    for name in ("printer.local", "hr.corp", "nas.lan", "5.1.168.192.in-addr.arpa"):
        assert gate.may_send_name(name) == (False, "an internal or reverse-lookup ending"), name


def test_a_name_that_resolved_to_a_private_address_stays_local():
    assert gate.may_send_name("wiki.example.com", "type: 5 web.example.com;10.0.0.5;") == (
        False, "it resolved to a private address, so it is internal")


def test_an_internet_name_may_be_sent():
    assert gate.may_send_name("example.com", "93.184.215.14;") == (True, "an internet name")
    assert gate.may_send_name("example.com", "-") == (True, "an internet name")  # no answer recorded
    assert gate.may_send_name("example.com") == (True, "an internet name")
