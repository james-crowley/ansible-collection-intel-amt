# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report privately via GitHub's
[private vulnerability reporting](https://github.com/james-crowley/ansible-collection-intel-amt/security/advisories/new)
(Security → Report a vulnerability). If that is unavailable to you, open a
minimal public issue saying only *"security report, requesting a private
channel"* with no technical detail, and a maintainer will follow up.

Expect an acknowledgement within a week. There is no bug bounty.

## Why this collection warrants unusual care

Intel AMT is a management engine that runs **beneath the operating system**. It
is powered whenever the machine has power, it is reachable when the OS is off,
and it cannot be observed or restricted by anything the OS runs. Practically:

**AMT admin credentials are equivalent to physical access to the machine.** Someone
holding them can power it on or off, watch and control the console, and boot it
from media of their choosing — regardless of what the installed operating system
wants. Treat a leaked AMT password as you would treat handing over the machine.

Two capabilities in this collection deserve specific attention.

### Writable virtual media hands a remote BIOS raw block access to a local file

`amt_media` with `floppy_writable: true` presents a file on the *controller* as a
writable block device to the *remote* machine's firmware. The remote side issues
SCSI writes; we execute them against that file.

Mitigations in place:

- Writability is opt-in per image; the default is read-only.
- The CD/DVD slot is read-only by design and cannot be made writable.
- Writes are bounded twice: against the length the WRITE CDB declares, and again
  in the primitive that touches the filesystem, which refuses any write that
  would extend the backing file. Both layers exist because a single upstream
  guard was found insufficient — see the history of `plugins/module_utils/ider.py`.
- A writable image that is a symlink, or that resolves outside a caller-supplied
  allowed directory, is refused.

If you find a way to write outside the attached image, or to make the read-only
CD slot accept writes, that is a vulnerability — please report it.

### Transport can be unauthenticated if explicitly configured

TLS is the default. Certificate trust requires an explicit decision: a CA path,
or a reviewed SHA-256 leaf fingerprint. `amt_media` accepts **only** fingerprint
pinning, because the redirection plane is a raw TLS socket with no CA-chain path,
and it refuses TLS without a pin rather than running encrypted-but-unauthenticated.

Plaintext HTTP is reachable, but only when the caller sets **both**
`use_tls: false` and `allow_insecure_transport: true`. This exists because AMT
provisioned in Small Business Mode never opens port 16993 at all, so a TLS-only
collection would be unusable on that hardware. It is never selected implicitly,
and the collection will not probe for TLS and silently fall back.

If you find a path that downgrades transport or skips a configured trust check
without that explicit acknowledgement, that is a vulnerability.

## Credential handling

Report anything that contradicts the following, as each is intended behaviour:

- `password` is `no_log` in every module argument spec.
- Every user-visible message and diagnostic passes through the redaction layer in
  `plugins/module_utils/errors.py`, which strips passwords, `Authorization`
  headers, digest responses and cookies, and bounds excerpt length.
- Credentials are never written to operation receipts, facts, or state files.
- `amt_media` spawns a background session **without** `subprocess`/`exec`, so
  credentials cross into it as in-memory values and never appear in `argv` or the
  process environment where other local users could read them.
- Session state files are created mode `0600`.

## Scope

In scope: the collection's Python code, the role, and the CI configuration in
this repository.

Out of scope: vulnerabilities in Intel AMT firmware itself (report those to
[Intel](https://www.intel.com/content/www/us/en/security-center/default.html)),
in `ansible-core`, or in `requests`.

### One out-of-scope advisory worth stating plainly

`meta/runtime.yml` declares `requires_ansible: '>=2.17.0'`. That is a **minimum**,
not a recommendation, and the oldest versions satisfying it are not patched.

`GHSA-w8p5-mx5w-cpqj` (HIGH) — argument injection in `ansible-galaxy role install`
leading to arbitrary code execution — affects ansible-core `>= 2.17.0b1, < 2.18.18rc1`
and is **first fixed in 2.18.18**. There is no fix in the 2.17 line; that branch
is end-of-life and will not receive one.

So satisfying this collection's floor with ansible-core 2.17.x means running an
ansible-core that will never be patched for that advisory. The floor stays at
2.17 because the collection genuinely works there and raising it would drop
Python 3.10 support without protecting anyone already on a patched release — but
if you are choosing a controller version now, **choose 2.18.18 or newer.**

This is a vulnerability in `ansible-core`, not in this collection, and nothing in
this collection invokes `ansible-galaxy role install`. Report it to the
[Ansible project](https://github.com/ansible/ansible/security), not here.

## Supported versions

Pre-1.0. Only the latest commit on `main` receives fixes; there are no
maintained release branches yet.
