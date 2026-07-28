<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Maintainer setup: accounts, secrets, and one-time steps

Everything here needs a human. Each item says what to do, where, and what it
unblocks. Nothing in this list can be done from CI.

---

## 1. Decide the Galaxy namespace — **blocking, and time-sensitive**

The collection is currently `james_crowley.intel_amt`. Nothing is published yet,
so this is free to change now and a breaking change later.

**Namespace rules.** A Galaxy namespace must be lowercase alphanumeric with
underscores, cannot start with an underscore or a digit, and cannot contain
consecutive underscores. It does **not** have to match a GitHub username — you can
request an arbitrary name, and you can also have a namespace that maps to a GitHub
org rather than a personal account.

Plausible alternatives, all valid:

| Namespace | FQCN becomes | Notes |
|---|---|---|
| `james_crowley` | `james_crowley.intel_amt` | current; ties the collection to you personally |
| `crowley` | `crowley.intel_amt` | matches the CircleCI runner namespace already in use |
| `crowleylab` / `crowley_lab` | `crowleylab.intel_amt` | reads as a project rather than a person |
| something org-shaped | e.g. `<org>.intel_amt` | best if this may gain co-maintainers |

**Cost of changing it:** 242 occurrences across 63 files. It is a mechanical
rename (namespace directory, `galaxy.yml`, every FQCN in modules, role, tests,
integration targets, hardware playbooks, docs, README, CI paths, and
`scripts/setup-collection-tree.sh`), done in one PR and verified by the full test
suite. Tell me the name and I will do it.

**How claiming actually works** — this is not what I first told you, and the
correction matters:

- **`james_crowley` needs no claiming.** Galaxy auto-creates a namespace matching
  your GitHub login the first time you sign in with GitHub, mapping hyphens to
  underscores (`james-crowley` → `james_crowley`). So it is effectively reserved
  for you already. My earlier "0 results means someone could take it" was wrong:
  an empty query just means you have not signed in to Galaxy yet, not that the
  name is up for grabs.
- **Any other name is a forum request, not self-service.** There is no "create
  namespace" button for a name that does not match a GitHub login. You post to the
  Galaxy namespace request thread on the Ansible forum:
  <https://forum.ansible.com/t/ansible-galaxy-how-to-request-a-custom-namespace/45689>

  The request needs: the desired namespace, a one-line description (it is shown on
  Galaxy), a link to the GitHub org if there is one, and the Galaxy usernames to
  make namespace admins — **each of whom must have signed in to Galaxy at least
  once first**, so do that before requesting.

**So:**

1. Sign in at <https://galaxy.ansible.com/> with GitHub. This alone secures
   `james_crowley`.
2. If you want a different name, open the forum request above. Expect it to take
   days rather than minutes, so start it early if you want it.
3. Tell me the final name and I will do the rename in one PR.

---

## 2. Create the `galaxy-publish` CircleCI context — **blocks publishing**

The publish job exists and is wired, but the context it needs **does not exist**,
so its first run would fail. This is the single largest untested path in the repo.

Get an API key: <https://galaxy.ansible.com/ui/token/> → **Load token** (it is
shown once).

```bash
circleci context create galaxy-publish --org gh/james-crowley

circleci context secret set galaxy-publish --org gh/james-crowley \
  --name ANSIBLE_GALAXY_API_KEY --value '<paste token>'

# Restrict it to this project only, exactly as amt-lab-runner is restricted,
# so no other project in the org can publish using your token.
circleci context restriction create galaxy-publish \
  --type project --value 833e6f14-146b-4cc1-9313-18576537356c \
  --org gh/james-crowley
```

Publishing then happens on a `v*` tag, behind a manual approval.

---

## 3. Install Renovate — **replaces Dependabot**

`renovate.json` is committed and configured for our actual dependency surfaces
(pip requirements, `cimg/python` images, and the single `ansible-core` pin the
hardware job uses). It needs the GitHub App installed to do anything.

1. <https://github.com/apps/renovate> → **Install**.
2. Grant it access to **this repository only** (not all repos).
3. It opens an onboarding PR plus a "Dependency Dashboard" issue. Merge the
   onboarding PR to activate.

Note it works on private repos on the free tier. No secrets or env vars required.

**What Renovate will and will not manage here:**

- **Will:** `requirements.txt`, `tests/unit/requirements.txt`,
  `tests/integration/requirements.txt`, `cimg/python` images in CI, and the
  `ansible-core~=2.17.0` pin in the hardware job.
- **Will not:** the sanity/unit *matrices*, because those are comma-separated lists
  of supported versions rather than single pins — there is no "current version" to
  bump. Widening or narrowing the support matrix is a policy decision, and the
  Dependency Dashboard will still surface new `ansible-core` releases for you to
  act on. I removed a regex manager that appeared to handle this; it would only
  have produced noise.

---

## 4. Decide: make the repository public?

This is a genuine trade-off, not a formality.

**Gained:**

- **Branch protection.** Currently unavailable ("Upgrade to GitHub Pro or make this
  repository public"). Right now CI is *advisory* — every merge so far was green
  because I verified it manually, not because anything would have stopped a red
  merge. Public unlocks required status checks.
- Required for Galaxy to be genuinely useful to anyone else.
- Private vulnerability reporting (referenced by `SECURITY.md`) works properly.

**Cost:** the lab's AMT topology becomes public in git history and CI logs. I have
kept endpoint addresses out of the repository, and CircleCI masks context values in
job output, but **before flipping this I should sweep git history** for anything
that leaked — commit messages, changelog fragments, and the evidence artifacts in
particular. Ask me to do that sweep first.

If it stays private, consider GitHub Pro purely to get branch protection, because
unenforced CI on a repo that power-cycles hardware is a real gap.

---

## 5. Give me Theta — **blocks the repeatability claim**

Everything is qualified against **one** machine and **one** firmware version
(AMT 16.1.30). The design intent was always that a second machine proves
repeatability, and until it runs, "repeatable" is an assumption.

What I need, added to the existing `amt-lab-runner` context:

```bash
circleci context secret set amt-lab-runner --org gh/james-crowley \
  --name AMT_HOSTS --value '<LAB_HOST_1-ip>,<theta-amt-ip>'
```

`AMT_HOSTS` (plural) is already supported and takes precedence over `AMT_HOST`.
**Two caveats:**

- Theta's TLS fingerprint differs from Lambda's, and there is currently only one
  `AMT_TLS_FINGERPRINT` variable. Supporting per-host pins needs a small change to
  `render-inventory.sh` — tell me when you add Theta and I will do it.
- If Theta's AMT password differs from Lambda's, the same applies to
  `AMT_PASSWORD`.

Theta's reviewed fingerprint is held in the `amt-lab-runner` context, not
recorded here — this repository is public.

---

## 6. Confirm Lambda's UUID against MEBx — **one minute, unblocks the identity guard**

Run the `hardware-observe` job (or stage 1) and read the `uuid` that `amt_info`
reports for Lambda. The value is not reproduced here, because a platform GUID
identifies a physical machine and this repository is public.

Open MEBx (or BIOS system information) on Lambda and confirm it matches. This
matters because the stage-2 identity cross-check compares the firmware-reported
UUID against a reviewed value, and that check is what stops a reset landing on the
wrong machine. It is currently *plausible* but unconfirmed — and the value needed a
non-obvious SMBIOS little-endian field reversal to derive, so confirming it is
confirming that reasoning, not just a string.

Cross-check from a trusted host if you prefer:

```bash
openssl s_client -connect <LAB_HOST_1-ip>:16993 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

Once confirmed, record it as `amt_expected_uuid` in the lab inventory and the
guard becomes live.

---

## Already done for you (no action needed)

- **Weekly drift-detection schedule** — created via the CircleCI API as
  `weekly-drift-detection`, Mondays 11:00 UTC, running the `test` workflow against
  `main`. This closes a real gap found while auditing against community practice:
  Geerling runs a weekly cron on every one of his ~100 repos precisely to catch
  breakage that arrives without a push. Safe by construction, since
  `run-hardware-tests` defaults to `false`.

## Summary: what blocks what

| Item | Blocks | Needs |
|---|---|---|
| Galaxy namespace decision | any publish; gets harder later | your choice of name |
| `galaxy-publish` context | publishing at all | Galaxy API token |
| Renovate install | dependency updates | 2 clicks |
| Public vs private | **enforced CI**, Galaxy usefulness | a decision + a history sweep |
| Theta access | the repeatability claim | one context variable |
| MEBx UUID check | the identity guard | one minute at the machine |
