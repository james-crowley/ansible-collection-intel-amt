# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for tests/hardware/redact-evidence.py.

Every fixture value here is deliberately, obviously fake: RFC 5737 TEST-NET-1
(``192.0.2.0/24``), RFC 3849 documentation IPv6 (``2001:db8::/32``), the RFC 7042
documentation MAC block (``00:00:5e:00:53:00``-``ff``), and ``.invalid`` domains
reserved by RFC 2606. No real lab value belongs in this file -- a fixture is
committed, and a committed lab address is the exact leak the script under test
exists to prevent.

Two properties matter equally. The script has to redact, and it has to leave the
diagnostic content alone: evidence that has been scrubbed into uselessness is
evidence nobody keeps, which is how a redaction step gets deleted a release later.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "hardware" / "redact-evidence.py"


def _load_module() -> Any:
    """Import the script by path.

    It is named with a hyphen and carries no shebang on purpose (ansible-test's
    `shebang` sanity test rejects a non-module shebang inside a collection), so it
    is not importable under its own name.
    """
    spec = importlib.util.spec_from_file_location("redact_evidence", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


redact_evidence = _load_module()


@pytest.fixture
def redactor() -> Any:
    return redact_evidence.Redactor()


# --- fixture data ----------------------------------------------------------

#: A structurally faithful stand-in for what qualify_readonly.yml writes, with
#: every redactable category present alongside the fields that must survive.
EVIDENCE: dict[str, Any] = {
    "reachable": True,
    "version": "19.0.5",
    "uuid": "4c4c4544-0037-4a10-8055-b3c04f463433",
    "uuid_compact": "4c4c454400374a108055b3c04f463433",
    "hostname": "amt-fixture-1",
    "domain_name": "mgmt.lab.example.invalid",
    "bios_version": "EXAMPLE10H.86A.0000.2026.0101.0000",
    "control_mode": "admin",
    "idle_wake_timeout": 1,
    "power_state": {"normalized": "on", "raw": 2},
    "capabilities": {"power": True, "boot_once_pxe": True, "sol": False, "storage_redirection": True},
    "network": {
        "mac_address": "00:00:5e:00:53:01",
        "mac_address_raw": "00-00-5E-00-53-01",
        "ip_address": "192.0.2.10",
        "subnet_mask": "255.255.255.0",
        "default_gateway": "192.0.2.1",
        "primary_dns": "192.0.2.2",
        "secondary_dns": "2001:db8::35",
        "dhcp_enabled": True,
        "link_is_up": True,
        "link_policy": [1, 14, 16],
        "link_policy_names": ["s0_ac", "sx_ac", "s0_dc"],
        "wake_on_lan_capable": True,
    },
    "system_state": {
        "element_name": "ManagedSystem",
        "enabled_state": 2,
        "enabled_state_text": "enabled",
        "requested_state": 12,
        "operational_status": [2],
        "operational_status_text": ["ok"],
    },
    "write_status": {"session_id": 7, "bytes_read": 4096, "bytes_written": 0, "writable": True},
    "boot_settings": {"AMT_BootSettingData": {"BIOSPause": False, "BootMediaIndex": 0, "UseSOL": False}},
    "operation": {
        "schema": "intel-amt-operation/v1",
        "action": "get_facts",
        "endpoint": "192.0.2.10:16993",
        "changed": False,
        "error_class": None,
        "tls_peer_fingerprint": ":".join(["ab"] * 32),
        "image_digest": "ab" * 32,
        "resource_uri": "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_BootSettingData",
    },
    "diagnostic": "WS-Man Get against 192.0.2.10:16993 failed; see tests/hardware/README.md for the recovery path",
    "note": "bytes_written=0 is a legitimate outcome; see this playbook header.",
}

#: Values that carry the diagnostic weight of the evidence. Redacting any of
#: these would be a regression: they say what the firmware did, not who it is.
PRESERVED_VALUES: tuple[Any, ...] = (
    "19.0.5",
    "EXAMPLE10H.86A.0000.2026.0101.0000",
    "ManagedSystem",
    "enabled",
    "intel-amt-operation/v1",
    "get_facts",
    "admin",
    "s0_ac",
    "sx_ac",
    "ok",
    "on",
)


def _all_strings(value: Any) -> list[str]:
    """Every string value anywhere in the structure. Keys are not included."""
    if isinstance(value, dict):
        return [s for v in value.values() for s in _all_strings(v)]
    if isinstance(value, list):
        return [s for item in value for s in _all_strings(item)]
    return [value] if isinstance(value, str) else []


def _shape(value: Any) -> Any:
    """The structure of ``value`` with every leaf replaced by its type name."""
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_shape(item) for item in value]
    return type(value).__name__


# --- category coverage -----------------------------------------------------


@pytest.mark.parametrize(
    ("text", "category"),
    [
        ("192.0.2.10", "ipv4"),
        ("2001:db8::35", "ipv6"),
        ("2001:0db8:0000:0000:0000:0000:0000:0035", "ipv6"),
        ("fe80::1", "ipv6"),
        ("00:00:5e:00:53:01", "mac"),
        ("00-00-5e-00-53-01", "mac"),
        ("00:00:5E:00:53:01", "mac"),
        ("00-00-5E-00-53-01", "mac"),
        ("4c4c4544-0037-4a10-8055-b3c04f463433", "uuid"),
        ("4C4C4544-0037-4A10-8055-B3C04F463433", "uuid"),
        ("4c4c454400374a108055b3c04f463433", "uuid"),
        (":".join(["ab"] * 32), "fingerprint"),
        ("ab" * 32, "digest"),
        ("mgmt.lab.example.invalid", "fqdn"),
        ("amt-fixture-1.example.invalid", "fqdn"),
    ],
)
def test_every_category_is_redacted(redactor: Any, text: str, category: str) -> None:
    result = redactor.redact_text(text)
    assert result == f"<redacted-{category}-1>", f"{text!r} was not redacted as {category}"
    assert redactor.distinct == {category: 1}


def test_amt_hostname_value_is_redacted_by_key(redactor: Any) -> None:
    """A bare AMT hostname matches no pattern, so the key is what identifies it."""
    result = redactor.redact_value({"hostname": "amt-fixture-1"})
    assert result == {"hostname": "<redacted-hostname-1>"}


def test_a_bare_label_under_a_non_identifying_key_is_left_alone(redactor: Any) -> None:
    assert redactor.redact_value({"enabled_state_text": "enabled"}) == {"enabled_state_text": "enabled"}


def test_keys_are_never_rewritten(redactor: Any) -> None:
    """Even a key that looks exactly like a redactable value stays as it is."""
    result = redactor.redact_value({"192.0.2.10": {"00:00:5e:00:53:01": 1}})
    assert list(result) == ["192.0.2.10"]
    assert list(result["192.0.2.10"]) == ["00:00:5e:00:53:01"]


# --- stable pseudonyms -----------------------------------------------------


def test_the_same_value_always_gets_the_same_token(redactor: Any) -> None:
    first = redactor.redact_text("192.0.2.10")
    second = redactor.redact_text("192.0.2.10")
    assert first == second == "<redacted-ipv4-1>"
    assert redactor.distinct["ipv4"] == 1
    assert redactor.occurrences["ipv4"] == 2


def test_different_values_get_different_tokens(redactor: Any) -> None:
    assert redactor.redact_text("192.0.2.10") == "<redacted-ipv4-1>"
    assert redactor.redact_text("192.0.2.11") == "<redacted-ipv4-2>"
    assert redactor.distinct["ipv4"] == 2


def test_tokens_are_assigned_in_first_seen_order_not_derived_from_the_value(redactor: Any) -> None:
    """Assignment order, so a token is not a reversible oracle for the value.

    A hash would be: an IPv4 on a known /24 is 254 guesses, and a MAC on a known
    OUI is not many more. Two redactors that see the same values in a different
    order must therefore disagree about which token each value got.
    """
    reversed_redactor = redact_evidence.Redactor()
    assert redactor.redact_text("192.0.2.10 then 192.0.2.11") == "<redacted-ipv4-1> then <redacted-ipv4-2>"
    assert reversed_redactor.redact_text("192.0.2.11 then 192.0.2.10") == "<redacted-ipv4-1> then <redacted-ipv4-2>"


def test_correlation_survives_across_a_whole_structure(redactor: Any) -> None:
    """One machine's address in three places is still recognisably one machine."""
    result = redactor.redact_value(
        {
            "network": {"ip_address": "192.0.2.10"},
            "operation": {"endpoint": "192.0.2.10:16993"},
            "invocation": {"module_args": {"host": "192.0.2.10"}},
        }
    )
    assert result["network"]["ip_address"] == "<redacted-ipv4-1>"
    assert result["operation"]["endpoint"] == "<redacted-ipv4-1>:16993"
    assert result["invocation"]["module_args"]["host"] == "<redacted-ipv4-1>"
    assert redactor.distinct["ipv4"] == 1


def test_the_same_value_under_two_categories_does_not_collide(redactor: Any) -> None:
    """A hostname key holding an address is still tokenised as an address."""
    result = redactor.redact_value({"host": "192.0.2.10", "hostname": "amt-fixture-1"})
    assert result == {"host": "<redacted-ipv4-1>", "hostname": "<redacted-hostname-1>"}


# --- embedded values -------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("connect to 192.0.2.10 failed", "connect to <redacted-ipv4-1> failed"),
        ("endpoint 192.0.2.10:16993 timed out", "endpoint <redacted-ipv4-1>:16993 timed out"),
        ("[192.0.2.10]", "[<redacted-ipv4-1>]"),
        ('{"peer": "192.0.2.10"}', '{"peer": "<redacted-ipv4-1>"}'),
        ("port 0 mac 00:00:5e:00:53:01 up", "port 0 mac <redacted-mac-1> up"),
        ("resolved amt.example.invalid to an address", "resolved <redacted-fqdn-1> to an address"),
    ],
)
def test_a_value_embedded_mid_string_is_caught(redactor: Any, text: str, expected: str) -> None:
    assert redactor.redact_text(text) == expected


# --- preservation ----------------------------------------------------------


@pytest.mark.parametrize("value", PRESERVED_VALUES)
def test_diagnostic_values_are_left_exactly_as_they_are(redactor: Any, value: str) -> None:
    assert redactor.redact_text(value) == value
    assert redactor.distinct == {}


@pytest.mark.parametrize(
    "value",
    [
        # Dotted, TLD-shaped, and not a name: the label before the last one has no
        # letter in it, which is what separates a version from a hostname.
        "19.0.5",
        "11.8.50",
        "2.21.0",
        "EXAMPLE10H.86A.0000.2026.0101.0000",
        "1.0.0.4096",
    ],
)
def test_dotted_version_strings_are_not_mistaken_for_dns_names(redactor: Any, value: str) -> None:
    assert redactor.redact_text(value) == value


@pytest.mark.parametrize(
    "value",
    [
        # Repository paths in the prose the playbooks write. "md" and "yml" are
        # perfectly good TLD-shaped labels, and redacting them would delete the
        # pointer a reviewer follows.
        "see tests/hardware/README.md for the recovery path",
        "rendered from tests/hardware/inventory.yml",
        "python3 tests/hardware/redact-evidence.py",
        "wired into .circleci/config.yml",
        # WS-Man resource URIs: public standards constants, not lab data.
        "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_BootSettingData",
        "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BIOSElement",
        "http://schemas.xmlsoap.org/ws/2004/08/addressing",
        "http://www.w3.org/2003/05/soap-envelope",
    ],
)
def test_filenames_and_standards_domains_are_not_redacted(redactor: Any, value: str) -> None:
    assert redactor.redact_text(value) == value


def test_numeric_and_boolean_leaves_are_returned_unchanged(redactor: Any) -> None:
    """Byte counters, power states and flags are numbers; none of them identify anything."""
    payload = {"bytes_read": 4096, "bytes_written": 0, "writable": True, "session_id": 7, "link_policy": [1, 14, 16], "error_class": None, "raw": 2.5}
    assert redactor.redact_value(payload) == payload


def test_a_full_evidence_document_keeps_every_preserved_value(redactor: Any) -> None:
    result = redactor.redact_value(EVIDENCE)
    strings = _all_strings(result)
    for value in PRESERVED_VALUES:
        assert value in strings, f"{value!r} should have survived redaction"
    assert result["write_status"] == EVIDENCE["write_status"]
    assert result["capabilities"] == EVIDENCE["capabilities"]
    assert result["boot_settings"] == EVIDENCE["boot_settings"]
    assert result["network"]["link_policy"] == [1, 14, 16]
    assert result["system_state"]["operational_status"] == [2]
    assert result["system_state"]["enabled_state"] == 2


def test_a_full_evidence_document_leaves_no_identifying_value_behind(redactor: Any) -> None:
    serialised = json.dumps(redactor.redact_value(EVIDENCE))
    for leaked in (
        "192.0.2.10",
        "192.0.2.1",
        "192.0.2.2",
        "255.255.255.0",
        "2001:db8::35",
        "00:00:5e:00:53:01",
        "00-00-5E-00-53-01",
        "4c4c4544-0037-4a10-8055-b3c04f463433",
        "4c4c454400374a108055b3c04f463433",
        "mgmt.lab.example.invalid",
        "amt-fixture-1",
        "ab" * 32,
    ):
        assert leaked not in serialised, f"{leaked!r} survived redaction"


# --- structure -------------------------------------------------------------


def test_the_json_structure_is_identical_before_and_after(redactor: Any) -> None:
    """Same keys, same nesting, same types -- only string values change."""
    result = redactor.redact_value(EVIDENCE)
    assert _shape(result) == _shape(EVIDENCE)


def test_nested_lists_of_dicts_are_walked(redactor: Any) -> None:
    result = redactor.redact_value({"targets": [{"ip": "192.0.2.10"}, {"ip": "192.0.2.11"}], "peers": [["192.0.2.10"]]})
    assert result["targets"] == [{"ip": "<redacted-ipv4-1>"}, {"ip": "<redacted-ipv4-2>"}]
    assert result["peers"] == [["<redacted-ipv4-1>"]]


# --- file handling ---------------------------------------------------------


def _write_evidence(directory: Path, name: str = "amt-fixture-1-qualify_readonly.json") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps(EVIDENCE, indent=4) + "\n", encoding="utf-8")
    return path


def test_redact_file_rewrites_in_place(tmp_path: Path, redactor: Any) -> None:
    path = _write_evidence(tmp_path / "output")
    assert redact_evidence.redact_file(path, redactor) == "json"
    rewritten = json.loads(path.read_text(encoding="utf-8"))
    assert _shape(rewritten) == _shape(EVIDENCE)
    assert rewritten["network"]["ip_address"] == "<redacted-ipv4-1>"


def test_redacting_twice_is_a_no_op(tmp_path: Path) -> None:
    """Idempotence, so a re-run (or a second wiring of the step) cannot double-redact."""
    output = tmp_path / "output"
    path = _write_evidence(output)

    assert redact_evidence.main(["redact-evidence.py", str(output)]) == 0
    after_first = path.read_text(encoding="utf-8")

    second = redact_evidence.Redactor()
    redact_evidence.redact_file(path, second)
    assert path.read_text(encoding="utf-8") == after_first
    assert second.distinct == {}


def test_main_walks_subdirectories_and_shares_tokens_across_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "output"
    first = _write_evidence(output, "amt-fixture-1-qualify_readonly.json")
    second = _write_evidence(output / "nested", "amt-fixture-1-qualify_power.json")

    assert redact_evidence.main(["redact-evidence.py", str(output)]) == 0

    first_doc = json.loads(first.read_text(encoding="utf-8"))
    second_doc = json.loads(second.read_text(encoding="utf-8"))
    # Same machine in two files must read as the same machine after redaction.
    assert first_doc["network"]["ip_address"] == second_doc["network"]["ip_address"]

    out = capsys.readouterr().out
    assert "2 JSON file(s) rewritten" in out


def test_main_prints_a_per_category_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The counts in the job log are what tell a reviewer the step actually ran."""
    output = tmp_path / "output"
    _write_evidence(output)

    assert redact_evidence.main(["redact-evidence.py", str(output)]) == 0

    out = capsys.readouterr().out
    assert "1 JSON file(s) rewritten" in out
    for category in ("ipv4", "ipv6", "mac", "uuid", "fingerprint", "digest", "fqdn", "hostname"):
        assert f"  {category}: " in out, f"summary is missing a {category} line"


def test_main_succeeds_when_there_is_no_evidence_directory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The CI step runs with `when: always`, including after a stage that wrote nothing."""
    assert redact_evidence.main(["redact-evidence.py", str(tmp_path / "absent")]) == 0
    assert "nothing to redact" in capsys.readouterr().out


def test_unparseable_json_is_redacted_as_raw_text(tmp_path: Path, redactor: Any) -> None:
    """A file truncated mid-write still has to be safe to publish."""
    output = tmp_path / "output"
    output.mkdir()
    path = output / "truncated.json"
    path.write_text('{"network": {"ip_address": "192.0.2.10", "mac_address": "00:00:5e:00:5', encoding="utf-8")

    assert redact_evidence.redact_file(path, redactor) == "text"
    content = path.read_text(encoding="utf-8")
    assert "192.0.2.10" not in content
    assert "<redacted-ipv4-1>" in content


def test_non_json_files_are_reported_rather_than_silently_skipped(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "output"
    _write_evidence(output)
    (output / "console.log").write_text("192.0.2.10\n", encoding="utf-8")

    assert redact_evidence.main(["redact-evidence.py", str(output)]) == 0

    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "console.log" in out
