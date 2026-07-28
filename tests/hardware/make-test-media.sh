#!/usr/bin/env bash
#
# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Provision the two small local media files hardware qualification stages 5 and 6
# need, entirely inside the workspace. Neither is ever committed -- .gitignore
# already blocks *.iso/*.img -- so every environment that runs those stages
# (the lab runner, or a developer's own machine) must materialise them itself.
#
#   1. A small BOOTABLE ISO for stage 5 (qualify_media_attach.yml). We fetch
#      iPXE's own ipxe.iso (a few MB): it is genuinely bootable (it is a real
#      network bootloader, not a blank filler), small, and -- per
#      docs/protocol-notes.md's own sources -- exactly the kind of media
#      MeshCmd's IDE-R workflow is built to serve. A machine that boots this
#      ISO over IDE-R and shows the iPXE banner on console is proof the
#      attach-and-boot-handoff path genuinely works, not just that a file of
#      the right size was accepted.
#   2. A small WRITABLE raw image for stage 6 (qualify_writable_image.yml):
#      zero-filled, sized like a classic 1.44 MB floppy (2880 * 512 bytes),
#      which is both a clean multiple of 512 (amt_media's MediaImage rejects
#      anything else -- docs/protocol-notes.md s4.4) and a size a floppy/USB-R
#      guest driver will not be surprised by.
#
# Idempotent and safe to re-run: an existing file is kept if it already has a
# valid size; only a missing or invalid file is (re)created. Pass --force to
# always regenerate both regardless.
#
# Usage:
#   ./tests/hardware/make-test-media.sh [--force]
#
# Respects AMT_TEST_ISO_PATH / AMT_TEST_IMAGE_PATH if already exported (as the
# hardware-media / hardware-writable CircleCI jobs do), so the CI step and this
# script always agree on where the files live. Falls back to
# tests/hardware/media/ next to this script otherwise.

set -euo pipefail

FORCE=false
if [ "${1:-}" = "--force" ]; then
    FORCE=true
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MEDIA_DIR="${SCRIPT_DIR}/media"
mkdir -p "${MEDIA_DIR}"

ISO_PATH="${AMT_TEST_ISO_PATH:-${MEDIA_DIR}/ipxe-test.iso}"
IMAGE_PATH="${AMT_TEST_IMAGE_PATH:-${MEDIA_DIR}/writable-test.img}"

# iPXE publishes stable, versioned build artifacts at boot.ipxe.org. https first;
# http as a fallback for lab networks that only proxy plain HTTP outbound.
IPXE_ISO_URLS=(
    "https://boot.ipxe.org/ipxe.iso"
    "http://boot.ipxe.org/ipxe.iso"
)

# ---------------------------------------------------------------------------
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        # macOS and other BSD-userland dev machines: shasum is the equivalent.
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

is_multiple_of_512() {
    local size="$1"
    [ "$((size % 512))" -eq 0 ]
}

file_size() {
    wc -c <"$1" | tr -d ' '
}

report() {
    local label="$1" path="$2"
    local size
    size="$(file_size "${path}")"
    echo "  ${label}: ${path}"
    echo "    size:   ${size} bytes ($((size / 512)) x 512-byte sectors)"
    echo "    sha256: $(sha256_of "${path}")"
}

# ---------------------------------------------------------------------------
# 1. Bootable ISO (stage 5)
# ---------------------------------------------------------------------------
need_iso=true
if [ "${FORCE}" = false ] && [ -s "${ISO_PATH}" ]; then
    existing_size="$(file_size "${ISO_PATH}")"
    if is_multiple_of_512 "${existing_size}"; then
        echo "Reusing existing bootable ISO at ${ISO_PATH} (${existing_size} bytes, already a multiple of 512)."
        need_iso=false
    else
        echo "Existing ${ISO_PATH} is ${existing_size} bytes, not a multiple of 512 -- refetching." >&2
    fi
fi

if [ "${need_iso}" = true ]; then
    tmp_iso="$(mktemp "${MEDIA_DIR}/.ipxe-download.XXXXXX")"
    fetched=false
    for url in "${IPXE_ISO_URLS[@]}"; do
        echo "Fetching bootable test ISO from ${url} ..."
        if curl -fsSL --retry 3 --retry-connrefused --connect-timeout 10 -o "${tmp_iso}" "${url}"; then
            fetched=true
            break
        fi
        echo "  ... failed, trying next URL if any remain." >&2
    done

    if [ "${fetched}" = false ]; then
        rm -f "${tmp_iso}"
        echo "ERROR: could not fetch a bootable test ISO from any of: ${IPXE_ISO_URLS[*]}" >&2
        echo "Refusing to produce a placeholder file -- stage 5 needs media that genuinely" >&2
        echo "boots, and a silent empty/junk ISO would make a green run meaningless." >&2
        exit 1
    fi

    downloaded_size="$(file_size "${tmp_iso}")"
    if [ "${downloaded_size}" -eq 0 ]; then
        rm -f "${tmp_iso}"
        echo "ERROR: downloaded ISO is empty (0 bytes). Refusing to use it." >&2
        exit 1
    fi
    if ! is_multiple_of_512 "${downloaded_size}"; then
        rm -f "${tmp_iso}"
        echo "ERROR: downloaded ISO is ${downloaded_size} bytes, not a multiple of 512." >&2
        echo "amt_media's MediaImage rejects sizes that are not a multiple of 512" >&2
        echo "(docs/protocol-notes.md s4.4) -- refusing to hand qualification a file" >&2
        echo "that would fail for a reason unrelated to what this stage is testing." >&2
        exit 1
    fi

    mv "${tmp_iso}" "${ISO_PATH}"
    echo "Fetched bootable test ISO: ${downloaded_size} bytes."
fi

# ---------------------------------------------------------------------------
# 2. Writable raw image (stage 6)
# ---------------------------------------------------------------------------
# 2880 x 512-byte sectors = 1,474,560 bytes = the classic 1.44 MB floppy size --
# a clean multiple of 512 and a size no floppy/USB-R guest driver will balk at.
IMAGE_SECTORS=2880
IMAGE_SIZE_BYTES=$((IMAGE_SECTORS * 512))

need_image=true
if [ "${FORCE}" = false ] && [ -s "${IMAGE_PATH}" ]; then
    existing_size="$(file_size "${IMAGE_PATH}")"
    if [ "${existing_size}" -eq "${IMAGE_SIZE_BYTES}" ]; then
        echo "Reusing existing writable image at ${IMAGE_PATH} (${existing_size} bytes)."
        need_image=false
    else
        echo "Existing ${IMAGE_PATH} is ${existing_size} bytes, expected ${IMAGE_SIZE_BYTES} -- recreating." >&2
    fi
fi

if [ "${need_image}" = true ]; then
    echo "Creating zero-filled writable test image (${IMAGE_SIZE_BYTES} bytes) at ${IMAGE_PATH} ..."
    dd if=/dev/zero of="${IMAGE_PATH}" bs=512 count="${IMAGE_SECTORS}" status=none
fi

created_size="$(file_size "${IMAGE_PATH}")"
if [ "${created_size}" -eq 0 ]; then
    echo "ERROR: writable test image is empty (0 bytes) after creation." >&2
    exit 1
fi
if ! is_multiple_of_512 "${created_size}"; then
    echo "ERROR: writable test image is ${created_size} bytes, not a multiple of 512." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
echo
echo "Test media ready:"
report "bootable ISO (stage 5, read-only cdrom slot)" "${ISO_PATH}"
report "writable image (stage 6, floppy/USB-R slot)" "${IMAGE_PATH}"
echo
echo "AMT_TEST_ISO_PATH=${ISO_PATH}"
echo "AMT_TEST_IMAGE_PATH=${IMAGE_PATH}"
