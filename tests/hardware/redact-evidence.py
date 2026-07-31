# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Intentionally has no shebang and is not executable: ansible-test's `shebang`
# sanity test rejects a non-module shebang inside a collection. Invoke it as
#   python3 tests/hardware/redact-evidence.py [output-dir]

"""Redact identifying lab data from hardware qualification evidence, in place.

The hardware stage playbooks write JSON evidence into ``tests/hardware/output/``
and CI publishes that directory with ``store_artifacts``. The values in it come
from firmware, so they describe a real machine on a real network: IPv4 address,
default gateway, DNS servers, MAC address, platform GUID, management domain
name.

**Why this exists.** The AMT host, credentials, and TLS pin are held as CircleCI
context values, and CircleCI masks context values *in log output only*. Masking
does not extend to ``store_artifacts`` content. Combined with a project set to
"Free and Open Source" -- which makes artifacts world-readable -- publishing the
evidence unmodified published the lab's network topology. That visibility setting
is a checkbox someone will flip again, so the artifact has to be safe on its own
rather than safe because of how the project happens to be configured today. A
previous history rewrite deliberately removed exactly this class of data from the
repository; leaking it through CI artifacts would defeat that work.

**Why here and not in the playbooks.** Seven playbooks write evidence today. Six
of them redacting correctly and one forgetting is the same leak, and a
playbook added next year would leak by default. This runs once, at the point the
data leaves the machine, immediately before ``store_artifacts``.

**What is preserved, deliberately.** Over-redaction is its own failure: evidence
nobody can read is evidence not worth keeping, and the whole point of these
artifacts is that a reviewer can tell what the firmware actually did. Firmware
and BIOS versions, capability flags, power/enabled/operational states, byte
counters, error classes, session ids, link policies, booleans, and every
structural key survive untouched. So does the JSON shape: same keys, same
nesting, same types.

**Pseudonyms, not deletion.** Each distinct value maps to a stable token
(``<redacted-ipv4-1>``) for the whole run, so two records describing the same
machine are still recognisably the same machine. Tokens are assigned in order of
first appearance and are deliberately *not* derived from the value: a hash of an
IPv4 address on a known /24 is a reversible oracle -- 254 guesses -- and the same
is true of a MAC on a known OUI.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

#: Default evidence directory, relative to this script rather than to the caller's
#: working directory, so the CI step and a hand run agree on what gets redacted.
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "output"

#: Keys whose value identifies the machine but matches no general pattern -- an
#: AMT hostname is a bare label ("machine2"), and a lab account name is not a
#: diagnostic. Matched case-insensitively on the exact key.
_IDENTIFYING_KEYS: dict[str, str] = {
    "hostname": "hostname",
    "host_name": "hostname",
    "host": "hostname",
    "amt_host": "hostname",
    "username": "username",
    "user": "username",
    "amt_username": "username",
    # Hardware inventory, new in 0.5.0. A serial number is the single most
    # identifying value AMT reports: it is what a vendor keys a warranty and a
    # support case on, and unlike an address it never changes. An asset tag is
    # whoever owns the machine writing an internal identifier onto it, which is
    # organisational information rather than a diagnostic.
    #
    # These match no general pattern -- a serial is an arbitrary alphanumeric
    # string indistinguishable from a firmware version or a part number -- so a
    # regex cannot find them and they have to be caught by key.
    "serial_number": "serial",
    "serialnumber": "serial",
    "serial": "serial",
    "board_serial": "serial",
    "chassis_serial": "serial",
    "asset_tag": "asset_tag",
    "assettag": "asset_tag",
    "sku": "asset_tag",
    "sku_number": "asset_tag",
    # Local filesystem paths, which reach the evidence through amt_media's
    # ``devices.<slot>.path`` (the resolved backing image) and through the media
    # options echoed back in a module invocation. An absolute path on the lab
    # runner spells out the account the job runs as (``/home/<user>/...``) and the
    # workspace layout underneath it, and on a hand run it is somebody's home
    # directory outright.
    #
    # Like a serial number, a path matches no general pattern: the FQDN rule
    # deliberately refuses anything ending in a filename label (see
    # _FILENAME_LABELS), which is exactly what an image path does end in, so
    # ``/home/jane/lab/ipxe-test.iso`` passed through the previous version of this
    # script completely untouched. Caught by key for the same reason serials are.
    #
    # The whole value goes, basename included. Keeping the last component would be
    # nicer to read, but it would mean parsing a path in order to decide which part
    # of it is safe, and the stable pseudonym already preserves what a reviewer
    # actually needs from it: that the cdrom and floppy slots held *different*
    # files, and that two stages held the *same* one. Size and byte counters are
    # untouched and say more about the media than its name does.
    "path": "path",
    "iso_path": "path",
    "image_path": "path",
    "answer_image_path": "path",
    "cdrom": "path",
    "floppy": "path",
    "allowed_directory": "path",
    "runtime_dir": "path",
    "state_file": "path",
}

#: Keys whose string value must survive completely untouched -- not merely
#: exempt from the identifying-key table above, but exempt from pattern
#: matching too.
#:
#: ``amt_event_log`` renders each 21-byte record as 42 lowercase hex
#: characters in ``raw_hex`` (and the equivalent bytes as ``raw_base64``), and
#: that module's own documentation calls preserving them "not negotiable": the
#: decode is derived from third-party sources this collection has never
#: checked against firmware, so the raw bytes are the only thing that makes a
#: wrong decode diagnosable. A hex string that size has no separators for the
#: mac/uuid/fingerprint/digest patterns to anchor on in the general case, but a
#: *malformed* or truncated record decodes to something shorter -- a record
#: read as exactly 16 or 32 bytes renders as a bare 32-hex or 64-hex run with
#: clean non-hex boundaries either side, which is exactly what the compact-UUID
#: and digest patterns match. Redacting a record's raw bytes because a firmware
#: bug or a partial read happened to produce a plausible-looking length would
#: corrupt the one field the module exists to keep trustworthy -- worse than
#: leaking, since a reviewer would not know it had happened. These two keys are
#: therefore checked, and passed through, before any pattern is even tried.
_EXEMPT_KEYS: frozenset[str] = frozenset({"raw_hex", "raw_base64"})

#: Public standards domains that appear inside WS-Man resource URIs and DMTF
#: namespaces. These are protocol constants, not lab data, and redacting them
#: turns a diagnostic URI into noise.
_PRESERVED_DOMAIN_SUFFIXES: tuple[str, ...] = (
    "intel.com",
    "schemas.dmtf.org",
    "schemas.xmlsoap.org",
    "w3.org",
    "oasis-open.org",
)

#: Labels that mark a dotted string as a filename rather than a DNS name. The
#: evidence carries prose notes that reference repository paths
#: ("tests/hardware/README.md#..."), and "md"/"yml" are perfectly good TLD-shaped
#: labels. Redacting those would delete the pointer a reviewer needs.
_FILENAME_LABELS: frozenset[str] = frozenset(
    {
        "cfg",
        "conf",
        "csv",
        "html",
        "img",
        "ini",
        "iso",
        "json",
        "log",
        "md",
        "py",
        "rst",
        "sh",
        "txt",
        "xml",
        "yaml",
        "yml",
    }
)

#: Matches a token this script already produced, so a second pass is a no-op
#: rather than a rename to ``<redacted-hostname-2>``.
#:
#: The underscore in the character class is load-bearing and was missing: two
#: category names contain one (``asset_tag``, and ``partial_uuid`` added later), so
#: ``<redacted-asset_tag-1>`` did not match this pattern. Nothing else recognised it
#: either -- it holds no address, so no pattern claims it -- which meant a second
#: pass over an already-redacted file saw a bare string under an identifying key and
#: minted ``<redacted-asset_tag-2>`` for it. The documented "redacting twice is a
#: no-op" guarantee therefore held for every category except the two that needed it
#: spelled with an underscore.
_TOKEN_RE = re.compile(r"<redacted-[a-z0-9_]+-\d+>")

# Order matters. Every pattern below is anchored so it cannot match inside a
# longer hex run, and the colon-separated forms are tried longest-first: a
# SHA-256 fingerprint is 32 colon-separated hex pairs and would otherwise be
# eaten piecewise by the MAC pattern, and a MAC is six pairs and would otherwise
# be eaten by the IPv6 pattern.
_HEX = "[0-9A-Fa-f]"
_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # SHA-256 style colon-hex fingerprint: exactly 32 pairs.
    ("fingerprint", re.compile(rf"(?<!{_HEX})(?:{_HEX}{{2}}:){{31}}{_HEX}{{2}}(?!:?{_HEX})")),
    # Bare 64-hex digest.
    ("digest", re.compile(rf"(?<![0-9A-Za-z]){_HEX}{{64}}(?![0-9A-Za-z])")),
    # MAC, colon or dash separated, any case.
    ("mac", re.compile(rf"(?<![0-9A-Za-z:-])(?:{_HEX}{{2}}[:-]){{5}}{_HEX}{{2}}(?![0-9A-Za-z:-])")),
    # Dashed UUID / platform GUID.
    ("uuid", re.compile(rf"(?<![0-9A-Za-z-]){_HEX}{{8}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{12}}(?![0-9A-Za-z-])")),
    # Compact 32-hex UUID. Tried after the 64-hex digest so half a digest is
    # never mistaken for a GUID.
    ("uuid", re.compile(rf"(?<![0-9A-Za-z]){_HEX}{{32}}(?![0-9A-Za-z])")),
    # The truncated agent GUID amt_event_log renders into an event description:
    # "Agent watchdog 1a2b3c4d-5e6f-... changed to Expired". Only the first six GUID
    # bytes are in a 21-byte record, so neither source can reconstruct a full one and
    # both emit this "-..." form -- which means the dashed-UUID pattern above cannot
    # see it. It identifies a management agent registered on the machine, which is
    # organisational information rather than a firmware diagnostic.
    #
    # The lookahead keeps the "-..." marker in the output, so the redacted
    # description still reads as a truncated GUID rather than as an unexplained
    # token.
    #
    # **Be precise about what this does not do.** The same six bytes remain visible,
    # by design, in that record's raw_hex, raw_base64 and event_data -- see the
    # "deliberately preserved" note in this directory's README.md. Those are
    # amt_event_log's entire diagnostic contract (a decode this collection has never
    # checked against firmware must stay falsifiable), so they cannot be removed
    # without destroying the evidence the stage exists to produce. What this rule
    # buys is that the *rendered* identifier -- the form a scanner greps for and a
    # reader can copy -- is not published. That is a narrower claim than
    # containment, and it is the honest one.
    ("partial_uuid", re.compile(rf"(?<![0-9A-Za-z-]){_HEX}{{8}}-{_HEX}{{4}}(?=-\.\.\.)")),
    ("ipv4", re.compile(rf"(?<![0-9A-Za-z.])(?:{_OCTET}\.){{3}}{_OCTET}(?![0-9A-Za-z.])")),
    # IPv6. Only the fully-populated eight-group form and the compressed "::"
    # forms are accepted. A three-group colon run with no "::" is far more likely
    # to be a timestamp ("00:00:00") than an address, and this evidence has no
    # field that would carry a partial address.
    (
        "ipv6",
        re.compile(
            rf"(?<![0-9A-Fa-f:.])(?:"
            rf"(?:{_HEX}{{1,4}}:){{7}}{_HEX}{{1,4}}"
            rf"|(?:{_HEX}{{1,4}}:){{1,7}}:"
            rf"|(?:{_HEX}{{1,4}}:){{1,6}}:{_HEX}{{1,4}}"
            rf"|(?:{_HEX}{{1,4}}:){{1,5}}(?::{_HEX}{{1,4}}){{1,2}}"
            rf"|(?:{_HEX}{{1,4}}:){{1,4}}(?::{_HEX}{{1,4}}){{1,3}}"
            rf"|(?:{_HEX}{{1,4}}:){{1,3}}(?::{_HEX}{{1,4}}){{1,4}}"
            rf"|(?:{_HEX}{{1,4}}:){{1,2}}(?::{_HEX}{{1,4}}){{1,5}}"
            rf"|{_HEX}{{1,4}}:(?::{_HEX}{{1,4}}){{1,6}}"
            rf"|::(?:{_HEX}{{1,4}}:){{0,6}}{_HEX}{{1,4}}"
            rf")(?![0-9A-Fa-f:.])"
        ),
    ),
    # DNS name / FQDN. The label before the TLD must contain a letter, which is
    # what keeps dotted version strings out: "19.0.5" and
    # "EXAMPLE10H.86A.0000.2026.0101.0000" are firmware and BIOS versions the
    # evidence exists to record, not names. Candidates are filtered further by
    # _is_dns_name below.
    ("fqdn", re.compile(r"(?<![0-9A-Za-z.@_-])(?:[0-9A-Za-z_-]+\.)*[0-9A-Za-z_-]*[A-Za-z][0-9A-Za-z_-]*\.[A-Za-z]{2,}(?![0-9A-Za-z.-])")),
)

#: Human-readable order for the summary, so the counts always print the same way.
_CATEGORY_ORDER: tuple[str, ...] = (
    "ipv4",
    "ipv6",
    "mac",
    "uuid",
    "partial_uuid",
    "fingerprint",
    "digest",
    "fqdn",
    "hostname",
    "username",
    "serial",
    "asset_tag",
    "path",
)


def _is_dns_name(candidate: str) -> bool:
    """Whether a dotted candidate should be treated as a DNS name at all.

    Rejects the two things that legitimately look like one in this evidence:
    public standards domains inside WS-Man resource URIs, and repository paths in
    the prose ``note`` fields the playbooks write.
    """
    lowered = candidate.lower()
    if any(lowered == suffix or lowered.endswith("." + suffix) for suffix in _PRESERVED_DOMAIN_SUFFIXES):
        return False
    return not any(label in _FILENAME_LABELS for label in lowered.split("."))


class Redactor:
    """Assigns and remembers a stable pseudonym per distinct value, per run."""

    def __init__(self) -> None:
        # (category, value) -> token. Keyed by category as well as value so a
        # value that could plausibly be read as two categories still gets one
        # token per category rather than colliding.
        self._tokens: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {}
        #: Occurrences replaced, per category -- the number a reviewer reads in
        #: the job log to confirm the step did something.
        self.occurrences: dict[str, int] = {}

    def token_for(self, category: str, value: str) -> str:
        """Return the token for ``value``, minting one in first-seen order."""
        key = (category, value)
        token = self._tokens.get(key)
        if token is None:
            self._counts[category] = self._counts.get(category, 0) + 1
            token = f"<redacted-{category}-{self._counts[category]}>"
            self._tokens[key] = token
        self.occurrences[category] = self.occurrences.get(category, 0) + 1
        return token

    @property
    def distinct(self) -> dict[str, int]:
        """Distinct values redacted, per category."""
        return dict(self._counts)

    def redact_text(self, text: str) -> str:
        """Replace every identifying pattern in ``text``, leaving the rest alone.

        Applied to any string found anywhere in the structure, including strings
        that merely *contain* an address rather than being one -- an endpoint is
        written ``host:port`` and a failure message quotes it mid-sentence.
        """
        for category, pattern in _PATTERNS:

            def replace(match: re.Match[str], category: str = category) -> str:
                value = match.group(0)
                if _TOKEN_RE.fullmatch(value):
                    return value
                if category == "fqdn" and not _is_dns_name(value):
                    return value
                return self.token_for(category, value)

            text = pattern.sub(replace, text)
        return text

    def redact_value(self, value: Any, key: str | None = None) -> Any:
        """Redact ``value`` in place-of-structure: same keys, nesting, and types.

        ``key`` is the mapping key this value was found under, used only for the
        identifying keys that no pattern can catch. Keys themselves are never
        rewritten.
        """
        if isinstance(value, dict):
            return {k: self.redact_value(v, key=k if isinstance(k, str) else None) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact_value(item) for item in value]
        if isinstance(value, str):
            # Checked before any pattern is tried, not after: a malformed or
            # truncated amt_event_log record can render raw_hex/raw_base64 at a
            # length that would otherwise look exactly like a UUID or digest --
            # see _EXEMPT_KEYS.
            if key is not None and key.lower() in _EXEMPT_KEYS:
                return value
            # Patterns first, even under an identifying key. An `endpoint` and an
            # `invocation.module_args.host` hold the same IPv4 address, and they
            # have to end up as the same token or the artifact stops showing that
            # they are the same machine.
            redacted = self.redact_text(value)
            if redacted != value:
                return redacted
            if key is not None and value and not _TOKEN_RE.fullmatch(value):
                category = _IDENTIFYING_KEYS.get(key.lower())
                if category is not None:
                    return self.token_for(category, value)
            return redacted
        # bool/int/float/None are left exactly as they are: byte counters, power
        # states, enabled_state, link_policy integers and every flag in this
        # evidence are numbers, and none of them identify anything.
        return value


def redact_file(path: Path, redactor: Redactor) -> str:
    """Rewrite one evidence file in place. Returns "json", "text", or "empty"."""
    original = path.read_text(encoding="utf-8")
    if not original.strip():
        return "empty"

    try:
        parsed = json.loads(original)
    except json.JSONDecodeError as exc:
        # A truncated file -- a playbook killed mid-write -- must still be safe to
        # publish, so fall back to redacting the raw text. Not the normal path,
        # and worth saying so out loud in the log.
        print(f"  {path.name}: not valid JSON ({exc.msg}); redacted as raw text instead")
        path.write_text(redactor.redact_text(original), encoding="utf-8")
        return "text"

    redacted = redactor.redact_value(parsed)
    # indent=4 matches Ansible's to_nice_json, so the file a reviewer downloads
    # looks like the file the playbook wrote.
    path.write_text(json.dumps(redacted, indent=4, sort_keys=False) + "\n", encoding="utf-8")
    return "json"


def main(argv: list[str]) -> int:
    """Redact every JSON file under the evidence directory. Never fails the job."""
    output_dir = Path(argv[1]).resolve() if len(argv) > 1 else DEFAULT_OUTPUT_DIR

    if not output_dir.is_dir():
        # Reached whenever a stage failed before writing anything. This step runs
        # with `when: always` precisely so it covers that case, so "nothing to do"
        # is a normal outcome and must not turn a red job into a differently red
        # one.
        print(f"redact-evidence: no evidence directory at {output_dir}; nothing to redact.")
        return 0

    json_paths = sorted(p for p in output_dir.rglob("*.json") if p.is_file())
    other_paths = sorted(p for p in output_dir.rglob("*") if p.is_file() and p.suffix != ".json")

    redactor = Redactor()
    print(f"redact-evidence: scanning {output_dir}")
    for path in json_paths:
        kind = redact_file(path, redactor)
        print(f"  redacted {path.relative_to(output_dir)} ({kind})")

    total = sum(redactor.occurrences.values())
    print(f"redact-evidence: {len(json_paths)} JSON file(s) rewritten, {total} value(s) redacted")
    for category in _CATEGORY_ORDER:
        occurrences = redactor.occurrences.get(category, 0)
        if occurrences:
            print(f"  {category}: {occurrences} occurrence(s), {redactor.distinct.get(category, 0)} distinct value(s)")
    if total == 0 and json_paths:
        print("  nothing matched -- check this is really the evidence directory before publishing it")

    if other_paths:
        # Only .json is rewritten, because that is all the playbooks write. If
        # that ever stops being true, store_artifacts would publish the new file
        # unredacted, so name it here rather than pass over it silently.
        print(f"redact-evidence: WARNING -- {len(other_paths)} non-JSON file(s) present and NOT redacted:")
        for path in other_paths:
            print(f"  {path.relative_to(output_dir)}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
