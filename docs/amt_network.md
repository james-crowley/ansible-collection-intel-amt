<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# `amt_network`

Configure Intel AMT network settings — IPv4 addressing, DHCP mode, ping response,
hostname/domain, and `LinkPolicy`.

## Purpose

The write counterpart to [`amt_info`](amt_info.md), which already **reports** every
value this module can set. Two classes back it:

| Class | What this module writes | Selector on `Put` |
|---|---|---|
| `AMT_EthernetPortSettings` instance 0 | `DHCPEnabled`, `IPAddress`, `SubnetMask`, `DefaultGateway`, `PrimaryDNS`, `SecondaryDNS`, `LinkPolicy` | `InstanceID = "Intel(r) AMT Ethernet Port Settings 0"` — **required** |
| `AMT_GeneralSettings` | `PingResponseEnabled`, `RmcpPingResponseEnabled`, `HostName`, `DomainName` | **none** |

That selector asymmetry is the vendor's, not a choice here — see
[`protocol-notes.md` §2.10](protocol-notes.md) for both halves of the evidence.

Every option defaults to *"leave this alone"*, i.e. no default at all. A task states
only what it intends to converge, and a task that only sets a hostname cannot
accidentally assert an addressing mode.

## The hazard this module is shaped around

**`AMT_EthernetPortSettings` instance 0 is the wired port AMT answers WS-Man on.** So
changing its addressing is changing the path carrying the request. A `Put` that succeeds
can make its own confirmation unobtainable — the module is sawing the branch it is
sitting on.

Three consequences, and they are the design rather than caveats on it.

### 1. Addressing changes are refused unless explicitly acknowledged

A change to `dhcp_enabled`, `ip_address`, `subnet_mask` or `default_gateway` fails with
`error_class: invalid_state` unless `allow_self_disconnect: true`. This is the stance
[`amt_media`](amt_media.md) takes on `ca_path`: refuse an option that cannot be honoured
safely rather than accept it and quietly not deliver what the operator believes they
asked for.

`primary_dns` and `secondary_dns` are deliberately **not** gated. Those configure the
*endpoint's own outbound* name resolution and cannot affect how a controller reaches it,
which is whatever `host` names. A gate that fires for changes that cannot disconnect
anyone is a gate that gets set routinely, which is the same as not having one.

`subnet_mask` and `default_gateway` *are* gated even though neither moves the address: a
narrowed mask or a wrong gateway removes the endpoint from a controller's path just as
completely, for any controller not on the same link.

### 2. A write is confirmed by a re-read, or it is not reported as a success

`Put` answering HTTP 200 means firmware accepted the body, not that the property took.
The module re-reads every class it wrote and compares. Three outcomes:

| Outcome | Result | `error_class` | `indeterminate` |
|---|---|---|---|
| Re-read succeeds and agrees | success, `changed: true` | `null` | `false` |
| Re-read succeeds and reports the **old** value | **failure** | `unsupported_capability` | absent |
| Re-read cannot be obtained at all | **failure** | whatever the read failed with (`connection`, `timeout`, `tls_validation`) | `true` |

The third row is the **expected** outcome of a forced address change: the endpoint now
answers at its new address, not the one this task connected to. `indeterminate: true` has
one meaning throughout this collection — **re-probe, do not retry** — and the classified
error type is preserved rather than coerced to `timeout`, because the likely case is an
endpoint refusing connections at the old address, which is `connection`.

The second row follows the classification rule issue #69 established for `amt_media`: a
definite refusal is `unsupported_capability`, an absent verdict is `timeout`. It is
*settled*, so it is deliberately not `indeterminate` — there is nothing in flight to
re-probe.

There is no "changed, but we are not sure" result shape. A caller acting on one would be
acting on nothing.

### 3. The module does not re-probe at the new address itself

Considered and rejected. It cannot know a DHCP-assigned address, and a fresh connection
to a different address is a **new trust decision** — this collection requires a
per-machine TLS fingerprint, and opening a second connection whose pin nobody reviewed
would trade an honest `indeterminate` for a confident guess. The caller re-probes with a
second task naming the address it now expects, which is also the task that gets to pin
it. See the example below.

## `link_policy` needs its own acknowledgement

`LinkPolicy` crosses two axes — ACPI state (S0 versus any Sx) and power source (AC versus
DC). **There is no "always on" value.**

| Name | Value | Meaning |
|---|---|---|
| `s0_ac` | 1 | available on S0 AC — host powered on, mains |
| `sx_ac` | 14 | available on Sx AC — host asleep/hibernating/off, mains |
| `s0_dc` | 16 | available on S0 DC — host powered on, battery |
| `sx_dc` | 224 | available on Sx DC — host asleep/hibernating/off, battery |

A policy carrying neither Sx value keeps the link up only while the host is in S0, so the
endpoint stops answering WS-Man entirely once it sleeps or powers down — and
[`amt_power`](amt_power.md) with `state: on` can then no longer reach it to bring it back.
**That is a change an operator can make and cannot undo remotely.** Removing the last Sx
value therefore requires `allow_wake_capability_loss: true`.

That flag is kept separate from `allow_self_disconnect` on purpose: one risks losing this
connection *now*, the other risks losing every connection *from the next time the host
leaves S0*. An operator may reasonably permit one and not the other.

`link_policy` is a **replacement, not a merge**: whatever is listed becomes the policy.
The result is sorted, so the same set written in a different order is still idempotent —
firmware types the property as an unordered array, so imposing a stable order invents no
meaning, whereas leaving it caller-ordered would make `changed` depend on YAML ordering.

### The table was re-derived, and it agrees with the read table

This collection shipped a **wrong** `LinkPolicy` table in 0.2.0 and 0.3.0 — wrong in
three of five entries, which inverted `wake_on_lan_capable` so that the boolean tested
"is this endpoint reachable on battery?" and read `false` on every mains-powered desktop.
See [`capability-matrix.md`](capability-matrix.md) and
[`protocol-notes.md` §2.7](protocol-notes.md).

The write values were therefore re-derived from `go-wsman-messages` v2.48.3 rather than
reused from the corrected read table on trust, because a wrong table on the write side
does not merely misreport — it can strand a machine. The derivation is in
[§2.10](protocol-notes.md); its conclusion is that `SettingsRequest.LinkPolicy` and
`SettingsResponse.LinkPolicy` are the **same Go type** with the same `ValueMap={1, 14,
16, 224}` annotation and one set of four constants, so **the read and write tables agree
in all four entries.**

The unit test asserts the literal integers rather than the constants they are built from:
asserting the constants would pass for any table at all, including the inverted one.

## Options

| Option | Type | Default | Choices | Gated by |
|---|---|---|---|---|
| `dhcp_enabled` | `bool` | — (leave alone) | — | `allow_self_disconnect` |
| `ip_address` | `str` | — | dotted quad | `allow_self_disconnect` |
| `subnet_mask` | `str` | — | contiguous dotted-quad mask | `allow_self_disconnect` |
| `default_gateway` | `str` | — | dotted quad | `allow_self_disconnect` |
| `primary_dns` | `str` | — | dotted quad | — |
| `secondary_dns` | `str` | — | dotted quad | — |
| `link_policy` | `list` of `str` | — | `s0_ac`, `sx_ac`, `s0_dc`, `sx_dc` | `allow_wake_capability_loss` (only when the last Sx value would go) |
| `ping_response_enabled` | `bool` | — | — | — |
| `rmcp_ping_response_enabled` | `bool` | — | — | — |
| `hostname` | `str` | — | — | — |
| `domain_name` | `str` | — | — | — |
| `allow_self_disconnect` | `bool` | `false` | — | — |
| `allow_wake_capability_loss` | `bool` | `false` | — | — |
| `host` | `str` | — (required) | — | — |
| `port` | `int` | (16993 if `use_tls` else 16992) | — | — |
| `username` | `str` | `admin` | — | — |
| `password` | `str` (`no_log`) | — (required) | — | — |
| `use_tls` | `bool` | `true` | — | — |
| `allow_insecure_transport` | `bool` | `false` | — | — |
| `validate_certs` | `bool` | `true` | — | — |
| `ca_path` | `path` | — | — | — |
| `tls_fingerprint` | `str` | — | — | — |
| `timeout` | `int` | `30` | — | — |
| `connect_timeout` | `int` | `10` | — | — |

Verified against `argument_spec()` in `plugins/modules/amt_network.py` and the rendered
`ansible-doc` output.

`ca_path` is honoured here, unlike in `amt_media` — this is the WS-Man plane, which does
have a CA-chain trust path.

### Validation that happens before any `Put`

All of these are caller mistakes that would strand the endpoint if they reached firmware,
so they fail with `invalid_state` before the first write:

- **Any address option that is not a strict dotted quad.** Stricter than
  `ipaddress.IPv4Address`: leading zeros are rejected, because `192.0.2.010` is octal to
  some resolvers and decimal to others.
- **A `subnet_mask` that is not contiguous.** `255.255.0.255` parses as an address and is
  not a mask; an endpoint whose mask has a hole in it is reachable from an
  arbitrary-looking subset of the network, which is the hardest possible failure to
  diagnose remotely.
- **A static configuration with no address.** `dhcp_enabled: false` where neither the
  endpoint's current value nor a supplied `ip_address`/`subnet_mask` provides one.
- **A call with no setting at all.** It would report `changed: false` and look like
  successful convergence, which is indistinguishable from a mistyped option name.
- **An empty `link_policy` list.** It passes the `choices` validation but is unwritable:
  an array property with no values emits no element, so the body would omit `LinkPolicy`
  and firmware would be asked nothing.

One check produces a **warning** rather than a refusal: a `default_gateway` that is not
on the same subnet as the resulting address/mask. It is legal in point-to-point and
proxy-ARP setups and this collection has no evidence about how AMT firmware treats one,
so refusing it would be inventing a rule — but it is also exactly what a transposed octet
looks like.

## Return values

`amt_network` nests its `intel-amt-operation/v1` receipt under `operation`, the same shape
every module in this collection returns it under.

| Field | Type | Returned | Description |
|---|---|---|---|
| `changed` | `bool` | always | Whether any property was (or, in check mode, would be) written. |
| `changes` | `list` of dict | always | One entry per property this call moves: `resource_class`, `property`, `previous`, `desired`. Identical in check mode and a real run. |
| `written_classes` | `list` of `str` | always | Classes actually written, in the order written. Empty in check mode and when already converged. |
| `indeterminate` | `bool` | always | `true` when a `Put` was issued and no confirming read could be obtained. When `true` the task also **fails**. |
| `addressing_change` | `bool` | always | Whether the plan touches this connection's own addressing. |
| `wake_capability_loss` | `bool` | always | Whether the plan leaves `LinkPolicy` with no Sx value. |
| `connected_through_managed_address` | `bool` or `null` | always | Whether `host` equals the `IPAddress` firmware reports. `null` for a hostname — see below. |
| `network` | `dict` | always | `AMT_EthernetPortSettings` instance 0 decoded, in exactly the field shape `amt_info` returns under `amt.network`. |
| `general` | `dict` | always | The writable `AMT_GeneralSettings` fields plus read-only `network_interface_enabled`. |
| `operation.schema` | `str` | always | Always `intel-amt-operation/v1`. |
| `operation.action` | `str` | always | Always `amt_network`. |
| `operation.endpoint` | `str` | always | `host:port` this operation was performed against. |
| `operation.changed` | `bool` | always | Mirrors the top-level `changed`. |
| `operation.previous` | `dict` | always | Both instances as read before any mutation, keyed by class name. |
| `operation.desired` | `dict` | always | The **exact** `Put` bodies, keyed by class name; `null` for a class with nothing to write. |
| `operation.observed` | `dict` | always | The instances re-read after the write, keyed by class name. `null` per class where no confirming read was obtained, and in check mode. |
| `operation.tls_peer_fingerprint` | `str` or `null` | always | SHA-256 of the TLS leaf certificate observed, or `null` over plaintext. |
| `operation.error_class` | `str` or `null` | always | `null` on success. |

`operation.desired` carries the finished bodies rather than a summary, which is what makes
check mode worth reading: it shows the read-only properties that were stripped and the
static addressing dropped for a DHCP switch.

### `connected_through_managed_address` has three states, not two

`true` / `false` / `null`, and `null` is not a synonym for `false`. When `host` is a
hostname rather than an IPv4 literal the module genuinely does not know: it does **not**
resolve names, because doing so would introduce a second opinion about where the
connection actually went, which could differ from what `requests` did.

It is reported as **evidence and does not gate anything**. The `allow_self_disconnect`
refusal fires regardless, including when `host` is demonstrably a different address:
instance 0 is the port AMT answers on, so the module has no basis for believing a second
path exists.

## Examples

Nothing here is gated — none of these three properties can affect how the task reaches
the endpoint:

```yaml
- name: Ensure the endpoint answers neither ICMP nor RMCP ping, and knows its own name
  james_crowley.intel_amt.amt_network:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    ping_response_enabled: false
    rmcp_ping_response_enabled: false
    hostname: amt-lab-01
    domain_name: lab.example.invalid
  delegate_to: localhost
  no_log: true
```

An addressing change is a one-machine-at-a-time operation, and `serial` is a **play**
keyword — a task carrying it fails with "conflicting action statements". `delegate_to:
localhost` moves execution to the controller and does nothing about inventory fan-out:

```yaml
- name: Pin one endpoint to a static management address
  hosts: "{{ target }}"
  serial: 1                     # play-level; never fan out an addressing write
  gather_facts: false
  tasks:
    - name: Write the new addressing, expecting to lose this connection
      james_crowley.intel_amt.amt_network:
        host: "{{ amt_host }}"
        username: "{{ amt_username }}"
        password: "{{ amt_password }}"
        tls_fingerprint: "{{ amt_tls_fingerprint }}"
        dhcp_enabled: false
        ip_address: 192.0.2.10
        subnet_mask: 255.255.255.0
        default_gateway: 192.0.2.1
        allow_self_disconnect: true
      delegate_to: localhost
      no_log: true
      register: moved
      # An indeterminate failure is the expected shape of a SUCCESSFUL address
      # change: the endpoint stopped answering at the old address. Tolerate
      # exactly that, and nothing else.
      failed_when:
        - moved.failed | default(false)
        - not (moved.indeterminate | default(false))

    - name: Re-probe at the address we now expect, rather than retrying the write
      james_crowley.intel_amt.amt_info:
        host: 192.0.2.10
        username: "{{ amt_username }}"
        password: "{{ amt_password }}"
        tls_fingerprint: "{{ amt_tls_fingerprint }}"
      delegate_to: localhost
      no_log: true
      register: reprobe
      until: reprobe is succeeded
      retries: 10
      delay: 6
```

The TLS fingerprint is unchanged by an address move — it pins the endpoint's leaf
certificate, not its address — so the re-probe can reuse it. What the operator must
supply is the address, which is exactly what the module refuses to guess.

Preview without touching anything. Note that check mode still applies both refusals, so
this is also how you find out an option is gated before a maintenance window:

```yaml
- name: Preview the addressing change
  james_crowley.intel_amt.amt_network:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    dhcp_enabled: false
    ip_address: 192.0.2.10
    subnet_mask: 255.255.255.0
    allow_self_disconnect: true
  delegate_to: localhost
  no_log: true
  check_mode: true
  register: plan

- name: Show the exact Put body that would be sent
  ansible.builtin.debug:
    var: plan.operation.desired.AMT_EthernetPortSettings
```

Keep the link up while the host is off, on mains **and** on battery:

```yaml
- name: Widen the link policy
  james_crowley.intel_amt.amt_network:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    link_policy: [s0_ac, sx_ac, sx_dc]
  delegate_to: localhost
  no_log: true
```

## Idempotence and check mode

| Change | Idempotent? | `changed` |
|---|---|---|
| any option already at the requested value | yes | `false`, and no `Put` is issued |
| `link_policy` written as the same set in a different order | yes | `false` |
| anything else | yes (convergent) | `true` only when a property actually moves |

The comparison is made on the **wire representation**. Firmware returns element text, so
a bool arrives as the string `"false"`; comparing that against the Python `False` naively
is the classic always-changed bug, and it is why the idempotence test feeds string values
rather than bools.

`check_mode` support is **full**: both classes are read, the plan is computed, **every
refusal is applied**, and the exact `Put` bodies a real run would send are returned — but
no `Put` is issued. A dry run that skipped the safety refusals would be worse than no dry
run, because it would report a dangerous write as fine.

`diff_mode` support is **full** via `changes` and `operation.previous`/`operation.desired`.

## Ordering within one call

`AMT_GeneralSettings` is written **first**, `AMT_EthernetPortSettings` second. The
ethernet `Put` is the one that can end the connection, so running it last means every
non-addressing change requested in the same task has already been written and confirmed
before the risky one is issued. The reverse order would make a self-disconnecting address
change also lose the hostname change in the same task, with no way to tell which of the
two happened.

## Errors this module can raise

| `error_class` | Meaning here |
|---|---|
| `invalid_state` | An unacknowledged hazard (`allow_self_disconnect`, `allow_wake_capability_loss`), or a caller mistake caught before any `Put` — malformed address, non-contiguous mask, static with no address, nothing to apply, empty `link_policy`. |
| `unsupported_capability` | Either class did not answer a `Get`, **or** a `Put` was accepted with HTTP 200 and the confirming read reported the old value. |
| `connection` | TCP/DNS failure. Carries `indeterminate: true` when it happened during the confirming read — the ordinary shape of a completed address change. |
| `timeout` | Ditto, when the confirming read timed out instead. Also raised by the transport for a `Put` that timed out after transmission, already `indeterminate`. |
| `tls_validation` | Certificate/fingerprint problem, or plaintext without `allow_insecure_transport`. |
| `authentication` | Digest credentials rejected. Raised on the first `Get`, so nothing is written. |
| `protocol` | Malformed SOAP, unexpected HTTP status, or a SOAP fault — which is how a firmware-rejected `Put` body surfaces (WS-Management binds faults to HTTP 500; the fault reason arrives in `diagnostic`). |

Unlike facts gathering, a class that cannot be **read** here is fatal rather than
degraded: the `Put` body *is* the read instance with edits applied, so an unreadable class
means there is nothing to edit. And a call naming options on both classes will not
partially apply — if `AMT_GeneralSettings` is absent, nothing is written to
`AMT_EthernetPortSettings` either, because an endpoint left in a state the caller did not
describe is worse than a refusal.

## Testing, and what is deliberately absent

**Mock coverage only. There is no hardware qualification stage for this module, on
purpose.**

A bad network write can leave a machine needing a physical MEBx visit, which is a
different class of risk from every existing stage — even the wake-from-off stage (stage
12) can be recovered with a power button. `tests/hardware/PREFLIGHT.md` carries a
pre-flight brief so a human can decide later; nothing in `.circleci/config.yml` wires a
stage up, and the module's own documentation says so.

What *is* covered:

- Unit tests for the planner, both gates (each with a negative control), the address
  validators, the `Put` body construction, and the confirm/indeterminate/unapplied
  outcomes.
- The `LinkPolicy` write table asserted against the **literal vendor integers**.
- An integration target driving the real module against **two** mock WS-Man servers: a
  permissive one, and a strict one that faults a `Put` carrying a read-only property or
  combining `DHCPEnabled=true` with static addressing, and that silently discards a
  general-settings `Put`. The strict server is what proves the body this module builds is
  one real firmware could accept, and that the confirming re-read is load-bearing rather
  than decorative.
- Every one of those, plus the integration target itself, verified to actually **fail**
  when the corresponding behaviour is broken.

So everything in this document is **Tier 2** in [`capability-matrix.md`](capability-matrix.md)'s
terms — unit and mock tested, against a vendor-cited protocol reference. Nothing here has
been exercised against real firmware, and this document makes no claim that it has.

## Limitations

- **IPv4 only.** `IPS_IPv6PortSettings` is the IPv6 class and this collection has never
  read it, let alone written it.
- **Instance 0 only.** Multi-NIC parts expose higher `AMT_EthernetPortSettings` indices.
  There is no option to select one, and an absent instance 0 fails with
  `unsupported_capability` rather than falling back to another index — writing addressing
  to a different port than the caller believes they are configuring is worse than
  refusing.
- **No `LinkPreference` / `SetLinkPreference`.** Real and documented, but the method's
  `Timeout` has undocumented units and expiry semantics, and handing the link to the host
  OS is a plausible way to lose the management plane.
- **No `AMTNetworkEnabled`.** The class definition states outright that disabling it
  leaves *"no option to enable it back remotely"*. No acknowledgement flag makes that
  reasonable to offer.
- **No `WsmanOnlyMode`.** Required for the `Put` and therefore passed through unchanged;
  never set. Blocking every non-WS-Man interface has no way back if the WS-Man path is
  then lost.
- **No `IpSyncEnabled`.** Writable, and deliberately unexposed: `parmstro`'s collection
  writes it from an option named `ping_response_enabled`, and offering an option for it
  would invite that confusion back. Still reported by `amt_info`.
- **The off-link-gateway check is a warning, not a guarantee.** It catches a transposed
  octet in the common case and says nothing about routability in general.
- **`connected_through_managed_address` is `null` for any hostname.** The module does not
  resolve names. This costs nothing operationally — the gate does not depend on it — but
  it does mean the field is not a reachability check.
- **Nothing here is hardware-verified.** See the section above.

## See also

- [`amt_info`](amt_info.md) — reports every value this module writes, and is the
  re-probe tool after a forced address change.
- [`amt_power`](amt_power.md) — what stops working if `LinkPolicy` loses its last Sx
  value.
- [`protocol-notes.md` §2.10](protocol-notes.md) — the write path with full citations,
  including the `LinkPolicy` re-derivation and the list of properties deliberately not
  written.
- [`capability-matrix.md`](capability-matrix.md) — the `LinkPolicy` correction this
  module's table was re-derived to avoid repeating.
