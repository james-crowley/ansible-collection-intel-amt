#!/usr/bin/env bash
#
# Render a hardware-test inventory on stdout from environment variables supplied
# by the restricted `amt-lab-runner` CircleCI context.
#
# Why this exists: real AMT endpoint addresses, credentials and reviewed TLS
# fingerprints must never live in the repository. tests/hardware/inventory.yml is
# gitignored; only inventory.yml.example is committed. On the lab runner this
# script materialises the real thing from the context, and the calling job
# removes it again afterwards.
#
# Usage:
#   ./tests/hardware/render-inventory.sh > tests/hardware/inventory.yml
#
# Never echo the output to a log: it contains the AMT password.

set -euo pipefail

: "${AMT_HOSTS:?AMT_HOSTS is required (comma-separated AMT endpoint addresses)}"
: "${AMT_USERNAME:?AMT_USERNAME is required}"
: "${AMT_PASSWORD:?AMT_PASSWORD is required}"

AMT_TLS_FINGERPRINT="${AMT_TLS_FINGERPRINT:-}"
AMT_ALLOW_INSECURE="${AMT_ALLOW_INSECURE:-false}"

# Transport policy, mirroring the collection's own rule that a trust decision is
# always explicit. Refuse to render an inventory that would ask a module to do
# something it will reject anyway, so the failure is here with a clear cause
# rather than midway through a playbook.
if [ -z "${AMT_TLS_FINGERPRINT}" ] && [ "${AMT_ALLOW_INSECURE}" != "true" ]; then
    echo "Refusing to render: no AMT_TLS_FINGERPRINT and AMT_ALLOW_INSECURE is not 'true'." >&2
    echo "Either supply the reviewed SHA-256 leaf fingerprint, or set" >&2
    echo "AMT_ALLOW_INSECURE=true for an endpoint whose firmware has no TLS at all" >&2
    echo "(AMT in Small Business Mode never opens port 16993)." >&2
    exit 1
fi

if [ -n "${AMT_TLS_FINGERPRINT}" ]; then
    use_tls=true
    allow_insecure=false
else
    use_tls=false
    allow_insecure=true
fi

emit_scalar() {
    # Single-quote and escape for YAML, so a password containing ':', '#', '{'
    # or a leading '!' cannot break the document or be reinterpreted.
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

printf 'all:\n'
printf '  vars:\n'
printf '    amt_username: %s\n' "$(emit_scalar "${AMT_USERNAME}")"
printf '    amt_password: %s\n' "$(emit_scalar "${AMT_PASSWORD}")"
printf '    amt_use_tls: %s\n' "${use_tls}"
printf '    amt_allow_insecure_transport: %s\n' "${allow_insecure}"
if [ -n "${AMT_TLS_FINGERPRINT}" ]; then
    printf '    amt_tls_fingerprint: %s\n' "$(emit_scalar "${AMT_TLS_FINGERPRINT}")"
fi
printf '  children:\n'
printf '    amt_lab:\n'
printf '      hosts:\n'

index=0
# shellcheck disable=SC2001
for host in $(printf '%s' "${AMT_HOSTS}" | tr ',' ' '); do
    [ -n "${host}" ] || continue
    index=$((index + 1))
    printf '        amt-lab-%02d:\n' "${index}"
    printf '          amt_host: %s\n' "$(emit_scalar "${host}")"
done

if [ "${index}" -eq 0 ]; then
    echo "AMT_HOSTS produced no usable entries." >&2
    exit 1
fi
