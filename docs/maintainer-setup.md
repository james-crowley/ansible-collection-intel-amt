<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Maintainer runbook: accounts, secrets, and one-time steps

This is the maintainer-side setup for the repository: the accounts, CircleCI
contexts, and secrets that CI itself cannot create. It is excluded from the
published collection artifact (`build_ignore` in `galaxy.yml`), because none of it
is actionable by a consumer.

Each section states the current state first, then whatever action remains.

---

## 1. Galaxy namespace

**Decided: `james_crowley`.** `galaxy.yml` declares
`namespace: james_crowley`, `name: intel_amt`, so the fully-qualified collection
name is `james_crowley.intel_amt` and every FQCN in `plugins/`, `roles/`,
`tests/`, the hardware playbooks, the docs, and `scripts/setup-collection-tree.sh`
uses it. Changing it after publication would be a breaking change for every
consumer, so treat it as fixed.

Two facts worth recording, because they are easy to get wrong:

- **`james_crowley` needs no claiming.** Galaxy auto-creates a namespace matching
  the owner's GitHub login the first time they sign in with GitHub, mapping
  hyphens to underscores (`james-crowley` → `james_crowley`). An empty Galaxy
  search result for a name does not mean it is available to others; it means
  nobody has signed in to create it yet.
- **Any *other* name is a forum request, not self-service.** There is no "create
  namespace" button for a name that does not match a GitHub login. Requests go to
  the Galaxy namespace request thread on the Ansible forum:
  <https://forum.ansible.com/t/ansible-galaxy-how-to-request-a-custom-namespace/45689>
  A request needs the desired namespace, a one-line description (shown on
  Galaxy), a link to the GitHub org if there is one, and the Galaxy usernames to
  make namespace admins — each of whom must have signed in to Galaxy at least
  once first.

**Remaining action:** sign in at <https://galaxy.ansible.com/> with GitHub, if
that has not been done, so the namespace exists before the first publish.

---

## 2. The `galaxy-publish` CircleCI context

**Exists.** The context is named exactly `galaxy-publish`, it holds the Galaxy API
key as **`GALAXY_API_KEY`**, and it is restricted to this project only, so no other
project in the org can publish with the key.

`GALAXY_API_KEY` is the name that matters: it is what the `publish` job in
`.circleci/config.yml` reads, and the job fails fast with
"`GALAXY_API_KEY` is not set; is the `galaxy-publish` context attached?" if the
context is missing or renamed. Do not store it under any other name.

To rotate the key, get a new one from <https://galaxy.ansible.com/ui/token/> →
**Load token** (shown once), then store it under the same name — the same command
form `.circleci/config.yml` documents for the lab context, which prompts for the
value rather than taking it on the command line:

```bash
circleci context store-secret galaxy-publish --org gh/james-crowley GALAXY_API_KEY
```

If the context ever has to be recreated from scratch, restrict it to this project
only, the same way `amt-lab-runner` is restricted. Context restrictions are managed
in **Organization Settings → Contexts** in the CircleCI UI, or via the contexts
API; the project ID they need is not reproduced here, because it is a stable
identifier better looked up than copied:

```bash
circleci api "/api/v2/project/gh/james-crowley/ansible-collection-intel-amt"
```

### How a release actually publishes

Publishing is triggered by pushing a `v*` tag, and is gated twice:

1. `publish-approval`, a manual approval that only exists on tag pushes.
2. The `publish` job asserts that the tag matches `galaxy.yml`'s `version` before
   uploading anything, and uploads one exact filename rather than a
   `./dist/*.tar.gz` glob.

That check exists because **a Galaxy version is immutable once published**: it
cannot be replaced, only superseded by a higher version. Tagging `v0.2.0` while
`galaxy.yml` still says `0.1.0` would be irrecoverable.

---

## 3. Renovate

**Installed and running.** The GitHub App is active on this repository, and
Renovate has onboarded: it opened its "Dependency Dashboard" issue and is
evaluating the surfaces `renovate.json` configures.

**What Renovate manages here:**

- **Does:** `requirements.txt`, `tests/unit/requirements.txt`,
  `tests/integration/requirements.txt`, the `cimg/python` images in CI, and the
  `ansible-core~=2.18.18` pin the hardware job uses.
- **Does not:** the sanity/unit *matrices*, because those are comma-separated
  lists of supported versions rather than single pins — there is no "current
  version" to bump. Widening or narrowing the support matrix is a policy decision.
  The Dependency Dashboard still surfaces new `ansible-core` releases to act on
  manually.

**Remaining actions**, both visible on the Dependency Dashboard issue:

- Renovate reports a **config migration** available for `renovate.json`. Ticking
  the box on the dashboard makes it open the migration PR.
- At least one update has **errored** and is being retried. The dashboard links
  the Mend logs; resolve it there rather than assuming a green dashboard.

---

## 4. Repository visibility and branch protection

**Both done.** The repository is **public**, and branch protection is **active on
`main`** with required status checks — 12 of them, all CircleCI contexts — plus
"require branches to be up to date before merging". CI is therefore enforced, not
advisory: a red required check blocks the merge.

List the current set rather than trusting a copy of it:

```bash
gh api repos/james-crowley/ansible-collection-intel-amt/branches/main/protection \
  --jq '.required_status_checks.contexts'
```

Keep that list in step with `.circleci/config.yml`. A job renamed in CI but not in
the protection rule silently stops being required; a required check that no longer
exists blocks every merge instead.

Because the repository is public, the lab's AMT topology must stay out of it.
Endpoint addresses, credentials, platform GUIDs, and TLS fingerprints live in the
`amt-lab-runner` context and the gitignored `tests/hardware/inventory.yml`, never
in the repository — see `tests/hardware/render-inventory.sh`, which emits
credentials as `lookup('ansible.builtin.env', ...)` expressions so nothing secret
reaches disk. Private vulnerability reporting (referenced by `SECURITY.md`) also
depends on the repository being public.

---

## 5. The second lab machine

**Done.** Two machines are provisioned in the `amt-lab-runner` context, and
`tests/hardware/render-inventory.sh` renders both as `amt-lab-01` and
`amt-lab-02`. Per-machine credentials are already supported: machine 1 uses the
unsuffixed variables (`AMT_HOST`, `AMT_PASSWORD`, `AMT_TLS_FINGERPRINT`, …) and
each additional machine appends `_N` (`AMT_HOST_2`, `AMT_PASSWORD_2`,
`AMT_TLS_FINGERPRINT_2`, …). Each machine needs **its own** reviewed fingerprint,
because each AMT endpoint presents its own self-signed certificate; the render
script refuses to emit a machine that has no pin. `AMT_HOSTS` (comma-separated)
also still works, for machines that share one credential set.

Adding a further machine therefore needs no code change:

```bash
circleci context store-secret amt-lab-runner --org gh/james-crowley AMT_HOST_3
circleci context store-secret amt-lab-runner --org gh/james-crowley AMT_TLS_FINGERPRINT_3
# plus AMT_PASSWORD_3 / AMT_USERNAME_3 if they differ from machine 1's
```

Read the new machine's fingerprint from the `hardware-observe` job, which sends no
credentials and mutates nothing, and review it before storing it.

**Machine 2 completed all eight stages on 2026-07-29**, its four mutating
approvals included, so power, media, writable-image and PXE are no longer a
single-machine result. That run was triggered with `hardware-limit=amt-lab-02`, so
machine 1 was untouched.

**Remaining action: re-run machine 1.** Its recorded evidence is from 2026-07-28
and predates v0.2.0's network and system-state facts, which have therefore only
ever been read on 19.0.5. A machine-1 run (`hardware-limit=amt-lab-01`) is what
closes that gap. See [`capability-matrix.md`](capability-matrix.md) Tier 4.

---

## 6. Cross-check a machine's UUID (optional)

This closes the loop on the stage-2 identity guard, which is what stops a reset
landing on the wrong machine. It is **optional**: where `amt_expected_uuid` is
unset, `tests/hardware/qualify_readonly.yml` proceeds and simply reports that
there is nothing to cross-check. Both lab machines now have a value recorded in the
context, and machine 2's comparison ran and matched on 2026-07-29 — but note what a
recorded value buys. It was recorded from a UUID this collection itself reported, so
the automatic check detects **drift** in the inventory-to-endpoint binding; the
`dmidecode` step below is what makes the recorded value an *independently* confirmed
identity rather than a self-consistent one. Note also that the guard exists **only
in `tests/hardware/`** — it is not a module feature, and nothing in `plugins/` or
`roles/` compares a UUID unless a caller passes one.

1. Run the `hardware-observe` job (or stage 1) and read the `uuid` that `amt_info`
   reports for the machine. The values are not reproduced in this repository,
   because a platform GUID identifies a physical machine and this repository is
   public.
2. Boot the machine and read the same value from the OS's view of SMBIOS:

   ```bash
   sudo dmidecode -s system-uuid
   # or, without root:
   cat /sys/class/dmi/id/product_uuid
   ```

3. Compare the two strings. They must match exactly.
4. Record the confirmed value as `amt_expected_uuid` for that host in the lab
   inventory. Every later run of stage 1 then cross-checks it automatically and
   fails on a drifted binding.

The comparison is worth doing for a reason beyond bookkeeping: `amt_info` derives
this value from `CIM_ComputerSystemPackage.PlatformGUID` and has to reverse the
first three fields, because an SMBIOS Type 1 UUID stores them little-endian (see
`_canonical_uuid()` in `plugins/module_utils/client.py`). Matching the OS-reported
UUID confirms that reasoning, not just a string. Both lab machines already render
with UUID version nibble `1` after the reversal, which is corroborating but weaker
than a direct comparison.

Do **not** substitute a certificate fingerprint for this check.
`openssl x509 -fingerprint -sha256` returns the TLS leaf certificate's
fingerprint, which is a different property of a different object and cannot
confirm a platform UUID. It is the right tool for reviewing the TLS pin — which is
what the `hardware-observe` job prints — and the wrong tool for identity.

---

## Already in place (no action needed)

- **Weekly drift-detection schedule** — `weekly-drift-detection`, Mondays 11:00
  UTC, running the `test` workflow against `main`. It exists because some breakage
  arrives without anyone pushing: a new `ansible-core` point release, a PyPI
  dependency change, or a rebuilt `cimg/python` image. Safe by construction, since
  `run-hardware-tests` defaults to `false`, so a scheduled pipeline can never reach
  lab hardware. Scheduled triggers live in project settings, not
  `.circleci/config.yml`; inspect them with:

  ```bash
  circleci api "/api/v2/project/gh/james-crowley/ansible-collection-intel-amt/schedule"
  ```

- **The `amt-lab-runner` context**, restricted to this project, holding the lab
  addresses, credentials and reviewed TLS pins.

## Summary: what is left

| Item | Status | Remaining |
|---|---|---|
| Galaxy namespace | Decided: `james_crowley` | Sign in to Galaxy once, if not already |
| `galaxy-publish` context | Exists, holds `GALAXY_API_KEY`, project-restricted | Nothing |
| Renovate | Installed, dashboard open | Config migration PR; one errored update |
| Public repo + branch protection | Public, 12 required checks, enforced | Keep the check list in step with CI |
| Second lab machine | Provisioned; all eight stages done | Nothing; re-run machine 1 for the v0.2.0 facts |
| UUID identity guard | Live for machine 2, matched on 2026-07-29 | One `dmidecode` comparison per machine, for independent identity |
