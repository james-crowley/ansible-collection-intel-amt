# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os
import struct
import time

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import ider
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import ProtocolError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.ider import DEVICE_CDROM, DEVICE_FLOPPY, IderEngine, MediaImage

# ---------------------------------------------------------------------------
# Frame builders (mirroring docs/protocol-notes.md sections 4.1-4.3, 5.2)
# ---------------------------------------------------------------------------


def _header(cmdid: int, seq: int, attributes: int = 0) -> bytes:
    return bytes([cmdid, 0x00, 0x00, attributes]) + struct.pack("<I", seq)


def open_session_reply(*, seq: int = 0, proto: int = 0, readbfr: int = 512, writebfr: int = 512, oem: bytes = b"") -> bytes:
    body = bytearray(22)  # absolute offsets 8..29
    body[0:4] = bytes([1, 0, 1, 0])  # major, minor, fw major, fw minor
    struct.pack_into("<H", body, 8, readbfr)  # abs 16..17
    struct.pack_into("<H", body, 10, writebfr)  # abs 18..19
    body[13] = proto  # abs 21
    struct.pack_into("<I", body, 17, 0x123456)  # abs 25..28 (iana)
    body[21] = len(oem)  # abs 29
    return _header(0x41, seq) + bytes(body) + oem


def keepalive_ping(seq: int = 0) -> bytes:
    return _header(0x44, seq)


def keepalive_pong(seq: int = 0) -> bytes:
    return _header(0x45, seq)


def heartbeat(seq: int = 0) -> bytes:
    return _header(0x4B, seq)


def close_frame(seq: int = 0) -> bytes:
    return _header(0x43, seq)


def status_data(status_type: int, value: int, *, seq: int = 0) -> bytes:
    """``0x49`` STATUS_DATA: 13 bytes total -- 8-byte header, type at abs 8,
    LE uint32 value at abs 9..12 (docs/protocol-notes.md section 4.2)."""
    return _header(0x49, seq) + bytes([status_type]) + struct.pack("<I", value)


def reset_occurred(seq: int = 0, mask: int = 0) -> bytes:
    return _header(0x46, seq) + bytes([mask])


def command_written(device_flags: int, cdb: bytes, *, feature_register: int = 0, seq: int = 0) -> bytes:
    assert len(cdb) == 12
    body = bytearray(20)  # absolute offsets 8..27
    body[1] = feature_register  # abs 9
    body[6] = device_flags  # abs 14
    body[8:20] = cdb  # abs 16..27
    return _header(0x50, seq) + bytes(body)


def data_from_host(data: bytes, *, seq: int = 0) -> bytes:
    body = bytearray(6)
    struct.pack_into("<H", body, 1, len(data))  # length at abs 9..10
    return _header(0x53, seq) + bytes(body) + data


READ_6 = 0x08
WRITE_6 = 0x0A
MODE_SENSE_6 = 0x1A
START_STOP = 0x1B
ALLOW_MEDIUM_REMOVAL = 0x1E
READ_FORMAT_CAPACITIES = 0x23
READ_CAPACITY = 0x25
READ_10 = 0x28
WRITE_10 = 0x2A
WRITE_AND_VERIFY = 0x2E
READ_TOC = 0x43
GET_CONFIGURATION = 0x46
GET_EVENT_STATUS = 0x4A
READ_DISC_INFO = 0x51
MODE_SELECT_10 = 0x55
MODE_SENSE_10 = 0x5A
GET_PERFORMANCE = 0xAC
TEST_UNIT_READY = 0x00


def cdb6(op: int, lba: int, length: int) -> bytes:
    return bytes([op, (lba >> 16) & 0x1F, (lba >> 8) & 0xFF, lba & 0xFF, length & 0xFF, 0x00]) + bytes(6)


def cdb10(op: int, lba: int, length: int) -> bytes:
    # The real SCSI CDB for READ_10/WRITE_10/WRITE_AND_VERIFY is 10 bytes;
    # the COMMAND_WRITTEN CDB slot is a fixed 12 bytes, so it is padded.
    return bytes([op, 0x00]) + struct.pack(">I", lba) + bytes([0x00]) + struct.pack(">H", length) + bytes(3)


def mode_sense_10(page: int, *, buflen: int = 0x40) -> bytes:
    """A MODE_SENSE(10) CDB for ``page``, padded to the 12-byte COMMAND_WRITTEN slot.

    Page code is the low 6 bits of ``cdb[2]``; allocation length is a BE uint16 at
    ``cdb[7]`` (docs/protocol-notes.md section 4.5).
    """
    return bytes([MODE_SENSE_10, 0x00, page, 0x00, 0x00, 0x00, 0x00]) + struct.pack(">H", buflen) + bytes(3)


def unpack_frame(frame: bytes) -> tuple[int, int, bytes]:
    cmdid = frame[0]
    seq = struct.unpack_from("<I", frame, 4)[0]
    return cmdid, seq, frame[8:]


@pytest.fixture
def sent() -> list[bytes]:
    return []


@pytest.fixture
def engine(sent) -> IderEngine:
    return IderEngine(send=sent.append)


def open_and_toggle(engine: IderEngine, sent: list[bytes], *, readbfr: int = 512, writebfr: int = 512) -> None:
    """Drive the OPEN_SESSION / OPEN_SESSION_REPLY / feature-toggle exchange,
    then reset both sequence counters to 0.

    Sequence continuity across the handshake is exercised directly and
    thoroughly in ``TestFraming``; resetting here lets every SCSI-focused
    test below start its own COMMAND_WRITTEN frames at ``seq=0`` (the
    ``command_written()``/``data_from_host()`` builders' default) instead of
    every call site having to track how many inbound messages setup already
    consumed.
    """
    engine.start()
    assert unpack_frame(sent[0])[0] == ider.CMD_OPEN_SESSION
    sent.clear()
    engine.feed(open_session_reply(readbfr=readbfr, writebfr=writebfr))
    # DISABLE_ENABLE_FEATURES was sent in response.
    assert unpack_frame(sent[-1])[0] == ider.CMD_DISABLE_ENABLE_FEATURES
    sent.clear()
    engine._in_seq = 0
    engine._out_seq = 0


def make_image(tmp_path, name: str, size: int, *, device_code: int = DEVICE_FLOPPY, writable: bool = False, fill: bytes = b"\x00") -> MediaImage:
    path = tmp_path / name
    path.write_bytes((fill * (size // len(fill) + 1))[:size])
    return MediaImage(path, device_code=device_code, writable=writable)


# ---------------------------------------------------------------------------
# Framing / sequencing
# ---------------------------------------------------------------------------


class TestFraming:
    def test_open_session_sends_expected_payload(self, sent):
        engine = IderEngine(send=sent.append, start_mode=ider.START_MODE_GRACEFUL, rx_timeout=1000, tx_timeout=2, heartbeat=3000)
        engine.start()
        cmdid, seq, body = unpack_frame(sent[0])
        assert cmdid == ider.CMD_OPEN_SESSION
        assert seq == 0
        assert struct.unpack("<HHHI", body) == (1000, 2, 3000, 1)

    def test_keepalive_ping_gets_pong(self, sent, engine):
        open_and_toggle(engine, sent)
        engine.feed(keepalive_ping(seq=0))
        assert len(sent) == 1
        cmdid, _unused, body = unpack_frame(sent[0])
        assert cmdid == ider.CMD_KEEPALIVE_PONG
        assert body == b""

    def test_in_sequence_counter_increments_independently_of_out(self, sent, engine):
        open_and_toggle(engine, sent)
        for i in range(3):
            engine.feed(keepalive_ping(seq=i))
        assert engine._in_seq == 3
        # Each PONG was sent with its own independently-incrementing out sequence.
        seqs = [unpack_frame(f)[1] for f in sent]
        assert seqs == sorted(seqs)
        assert len(set(seqs)) == 3

    def test_out_of_sequence_inbound_tears_down_session(self, sent, engine):
        open_and_toggle(engine, sent)
        with pytest.raises(ProtocolError):
            engine.feed(keepalive_ping(seq=5))
        assert engine.stopped

    def test_feed_after_teardown_raises(self, sent, engine):
        open_and_toggle(engine, sent)
        with pytest.raises(ProtocolError):
            engine.feed(keepalive_ping(seq=99))
        with pytest.raises(ProtocolError):
            engine.feed(keepalive_ping(seq=0))

    def test_unknown_inbound_command_tears_down(self, sent, engine):
        open_and_toggle(engine, sent)
        with pytest.raises(ProtocolError):
            engine.feed(_header(0xFE, 0))
        assert engine.stopped

    def test_error_occurred_is_logged_not_fatal(self, sent, engine):
        open_and_toggle(engine, sent)
        engine.feed(_header(0x4A, 0) + bytes([0x07, 0x00, 0x00]))
        assert engine.errors_seen == [0x07]
        assert not engine.stopped
        # Session keeps working afterwards.
        engine.feed(keepalive_ping(seq=1))
        assert unpack_frame(sent[-1])[0] == ider.CMD_KEEPALIVE_PONG

    def test_partial_frame_bytes_are_buffered_until_complete(self, sent, engine):
        open_and_toggle(engine, sent)
        whole = keepalive_ping(seq=0)
        engine.feed(whole[:3])
        assert sent == []
        engine.feed(whole[3:])
        assert len(sent) == 1


class TestOpenSessionValidation:
    def test_valid_reply_stores_buffers_and_sends_feature_toggle(self, sent, engine):
        engine.start()
        sent.clear()
        engine.feed(open_session_reply(readbfr=4096, writebfr=2048))
        assert engine.session_open is True
        assert engine.session_info.readbfr == 4096
        assert engine.session_info.writebfr == 2048
        cmdid, _unused, body = unpack_frame(sent[0])
        assert cmdid == ider.CMD_DISABLE_ENABLE_FEATURES
        assert body[0] == 3  # REGS_TOGGLE
        assert struct.unpack_from("<I", body, 1)[0] == ider.START_MODE_ON_REBOOT

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"proto": 1},
            {"readbfr": 8193},
            {"writebfr": 8193},
        ],
    )
    def test_invalid_reply_is_rejected(self, sent, engine, kwargs):
        engine.start()
        with pytest.raises(ProtocolError):
            engine.feed(open_session_reply(**kwargs))
        assert engine.stopped

    def test_boundary_buffer_size_is_accepted(self, sent, engine):
        engine.start()
        engine.feed(open_session_reply(readbfr=8192, writebfr=8192))
        assert engine.session_open is True


class TestScsiReplyShapes:
    def test_test_unit_ready_no_medium(self, sent, engine):
        open_and_toggle(engine, sent)
        engine.feed(command_written(0x00, cdb6(TEST_UNIT_READY, 0, 0)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body == bytes(12) + bytes([0xC5, 0x00, 0x03, 0x00, 0x00, 0x00, DEVICE_FLOPPY, 0x50, 0x00, 0x00, 0x00])

    def test_test_unit_ready_reports_media_change_once_then_ready(self, sent, engine, tmp_path):
        # NB: amt-ider-module.js calls SendCommandEndResponse(error=True, ...)
        # for *both* the media-change-unit-attention reply and the
        # subsequent ready reply, and error=True always emits the fixed
        # no-sense form (see IderEngine._send_command_end_response's
        # docstring) -- so these two SCSI conditions are, quirkily,
        # byte-for-byte identical on the wire. Only the internal
        # media_change_reported flag actually distinguishes them.
        image = make_image(tmp_path, "f.img", 512)
        open_and_toggle(engine, sent)
        engine.attach_device(image)
        engine.feed(command_written(0x00, cdb6(TEST_UNIT_READY, 0, 0)))
        assert image.media_change_reported is True
        _unused, _unused, body1 = unpack_frame(sent[-1])
        expected_error_form = bytes(12) + bytes([0xC5, 0x00, 0x03, 0x00, 0x00, 0x00, DEVICE_FLOPPY, 0x50, 0x00, 0x00, 0x00])
        assert body1 == expected_error_form
        sent.clear()
        engine.feed(command_written(0x00, cdb6(TEST_UNIT_READY, 0, 0), seq=1))
        _cmdid, _unused, body2 = unpack_frame(sent[-1])
        assert body2 == expected_error_form

    def test_read_capacity(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512 * 10))
        cdb = bytes([READ_CAPACITY]) + bytes(11)
        engine.feed(command_written(0x00, cdb))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_DATA_TO_HOST
        payload = body[26:34]
        assert struct.unpack(">I", payload[0:4])[0] == 9  # 10 blocks - 1
        assert payload[6] == 0x02  # floppy blocksize hi byte

    def test_mode_sense_6_write_protected_when_read_only(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512, writable=False))
        engine.feed(command_written(0x00, bytes([MODE_SENSE_6, 0x00, 0x3F, 0x00]) + bytes(8)))
        _unused, _unused, body = unpack_frame(sent[-1])
        data = body[26:]
        assert data == bytes([0, 0x00, 0x80, 0])

    def test_mode_sense_6_writable_clears_bit(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512, writable=True))
        engine.feed(command_written(0x00, bytes([MODE_SENSE_6, 0x00, 0x3F, 0x00]) + bytes(8)))
        _unused, _unused, body = unpack_frame(sent[-1])
        data = body[26:]
        assert data == bytes([0, 0x00, 0x00, 0])

    def test_unknown_scsi_command_gets_generic_sense(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512))
        engine.feed(command_written(0x00, bytes([0xEE]) + bytes(11)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body == bytes(12) + bytes([0x87, 0x50, 0x03, 0x00, 0x00, 0x00, DEVICE_FLOPPY, 0x51, 0x05, 0x20, 0x00])

    def test_get_event_status_notification(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512))
        cdb = bytes([GET_EVENT_STATUS, 0x01, 0x00, 0x00, 0x10]) + bytes(7)
        engine.feed(command_written(0x00, cdb))
        _unused, _unused, body = unpack_frame(sent[-1])
        assert body[26:] == bytes([0x00, 0x02, 0x80, 0x00])

    def test_get_configuration_buflen_zero(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM))
        cdb = bytes([GET_CONFIGURATION, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + bytes(3)
        engine.feed(command_written(0x10, cdb))
        _unused, _unused, body = unpack_frame(sent[-1])
        assert struct.unpack(">II", body[26:34]) == (0x003C, 0x0008)

    def test_get_configuration_current_profile_list(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM))
        # RT=2 (current), starting feature 0 -> only the profile list matches.
        cdb = bytes([GET_CONFIGURATION, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20]) + bytes(3)
        engine.feed(command_written(0x10, cdb))
        _unused, _unused, body = unpack_frame(sent[-1])
        payload = body[26:]
        length = struct.unpack(">I", payload[4:8])[0]
        assert length == len(ider._CD_CONFIG_PROFILE_LIST) + 4
        assert payload[8:] == ider._CD_CONFIG_PROFILE_LIST


class TestChunkedReads:
    def test_large_read_splits_across_frames_honouring_readbfr(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent, readbfr=512)
        data = bytes(range(256)) * 8  # 2048 bytes = 4 floppy sectors
        image = make_image(tmp_path, "f.img", len(data))
        image.path.write_bytes(data)
        engine.attach_device(image)

        engine.feed(command_written(0x00, cdb10(READ_10, 0, 4)))

        frames = [unpack_frame(f) for f in sent]
        assert all(cmdid == ider.CMD_DATA_TO_HOST for cmdid, _unused, _unused in frames)
        assert len(frames) == 4  # 2048 bytes / 512-byte readbfr
        reassembled = b""
        for i, (_unused, _unused, body) in enumerate(frames):
            chunk_len = struct.unpack_from("<H", body, 1)[0]
            payload = body[26:]
            assert len(payload) == chunk_len == 512
            reassembled += payload
            completed_flag = body[12] == 0x85
            assert completed_flag == (i == len(frames) - 1)
        assert reassembled == data

    def test_single_frame_read_is_marked_completed(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent, readbfr=512)
        image = make_image(tmp_path, "f.img", 512, fill=b"\xab")
        engine.attach_device(image)
        engine.feed(command_written(0x00, cdb10(READ_10, 0, 1)))
        assert len(sent) == 1
        _unused, _unused, body = unpack_frame(sent[0])
        assert body[12] == 0x85
        assert body[26:] == b"\xab" * 512

    def test_read_out_of_bounds_rejected(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "f.img", 512)
        engine.attach_device(image)
        engine.feed(command_written(0x00, cdb10(READ_10, 0, 2)))  # only 1 block exists
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[12] == 0xC5  # error-form: bounds failure sense is not transmitted, matching the read path


class TestWritePath:
    def test_multi_frame_write_lands_correct_bytes_at_correct_offset(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "f.img", 512 * 4, writable=True)
        engine.attach_device(image)

        engine.feed(command_written(0x00, cdb10(WRITE_10, 1, 2)))  # write 2 sectors starting at LBA 1
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_GET_DATA_FROM_HOST
        chunk = struct.unpack_from("<H", body, 1)[0]
        assert chunk == 1024
        sent.clear()

        payload = (b"A" * 512) + (b"B" * 512)
        # Firmware splits the logical write across two 0x53 frames.
        engine.feed(data_from_host(payload[:300], seq=1))
        assert sent == []  # not complete yet, no ack
        engine.feed(data_from_host(payload[300:], seq=2))
        cmdid, _unused, ack_body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert ack_body == bytes(12) + bytes([0x87, 0x00, 0x03, 0x00, 0x00, 0x00, DEVICE_FLOPPY, 0x51, 0x00, 0x00, 0x00])

        on_disk = image.path.read_bytes()
        assert on_disk[512:1536] == payload
        assert on_disk[:512] == b"\x00" * 512  # untouched sector before the write
        assert image.bytes_written == 1024

    def test_write_rejected_when_read_only(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "f.img", 512, writable=False)
        original = image.path.read_bytes()
        engine.attach_device(image)
        engine.feed(command_written(0x00, cdb10(WRITE_10, 0, 1)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body == bytes(12) + bytes([0x87, 0x70, 0x03, 0x00, 0x00, 0x00, DEVICE_FLOPPY, 0x51, 0x07, 0x27, 0x00])
        assert image.path.read_bytes() == original

    def test_write_out_of_bounds_rejected_and_file_unchanged(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "f.img", 512, writable=True)
        original = image.path.read_bytes()
        engine.attach_device(image)
        engine.feed(command_written(0x00, cdb10(WRITE_10, 0, 2)))  # 2 sectors, only 1 exists
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[12] == 0xC5  # error-form
        assert image.path.read_bytes() == original
        assert image.path.stat().st_size == len(original)

    def test_cdrom_device_never_accepts_writes_even_if_backing_flag_were_writable(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM)
        engine.attach_device(image)
        engine.feed(command_written(0x10, cdb10(WRITE_10, 0, 1)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[18] == DEVICE_CDROM
        assert body[12] == 0xC5  # no-medium/unsupported error form, not a write-protect sense

    def test_cdrom_media_image_rejects_writable_flag_at_construction(self, tmp_path):
        path = tmp_path / "c.iso"
        path.write_bytes(b"\x00" * 2048)
        with pytest.raises(ValueError, match="read-only by design"):
            MediaImage(path, device_code=DEVICE_CDROM, writable=True)

    def test_non_multiple_of_512_rejected(self, tmp_path):
        path = tmp_path / "bad.img"
        path.write_bytes(b"\x00" * 500)
        with pytest.raises(ValueError, match="not a multiple of 512"):
            MediaImage(path, device_code=DEVICE_FLOPPY)

    def test_symlink_refused(self, tmp_path):
        real = tmp_path / "real.img"
        real.write_bytes(b"\x00" * 512)
        link = tmp_path / "link.img"
        link.symlink_to(real)
        with pytest.raises(ValueError, match="symlink"):
            MediaImage(link, device_code=DEVICE_FLOPPY)

    def test_outside_allowed_directory_refused(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        image_path = outside / "f.img"
        image_path.write_bytes(b"\x00" * 512)
        with pytest.raises(ValueError, match="outside allowed directory"):
            MediaImage(image_path, device_code=DEVICE_FLOPPY, allowed_directory=allowed)

    def test_inside_allowed_directory_succeeds(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        image_path = allowed / "f.img"
        image_path.write_bytes(b"\x00" * 512)
        image = MediaImage(image_path, device_code=DEVICE_FLOPPY, allowed_directory=allowed)
        assert image.blocks == 1


class TestResetDuringRead:
    def test_reset_mid_read_finishes_current_chunk_then_acks_and_drops_queue(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent, readbfr=512)
        data = bytes(range(256)) * 8  # 4 sectors
        image = make_image(tmp_path, "f.img", len(data))
        image.path.write_bytes(data)
        engine.attach_device(image)

        # Simulate a second READ_10 being queued and then RESET_OCCURRED
        # being processed, both concurrently with the second sector's disk
        # read -- the real-world analogue of the JS reference's async
        # fs.read callback racing inbound messages while the file read is
        # outstanding. A synchronous local file read has no natural yield
        # point of its own, so the race is reproduced explicitly here via
        # the image's read() call, exactly at the point _pump_read() would
        # otherwise be blocked on disk I/O in an async implementation.
        original_read = image.read
        call_count = 0

        def read_with_side_effects_on_second_chunk(offset: int, length: int) -> bytes:
            nonlocal call_count
            call_count += 1
            result = original_read(offset, length)
            if call_count == 2:
                # A second READ_10 arrives and, since a read is already in
                # flight, gets queued rather than served immediately.
                engine._scsi_read(DEVICE_FLOPPY, image, 0, 1, False)
                # Then RESET_OCCURRED arrives while that first read is still
                # mid-flight, so it must be deferred rather than acked now.
                engine._on_reset_occurred()
            return result

        image.read = read_with_side_effects_on_second_chunk

        engine.feed(command_written(0x00, cdb10(READ_10, 0, 4)))

        frames = [unpack_frame(f) for f in sent]
        data_frames = [f for f in frames if f[0] == ider.CMD_DATA_TO_HOST]
        reset_acks = [f for f in frames if f[0] == ider.CMD_RESET_OCCURRED_RESPONSE]

        assert len(data_frames) == 2  # chunks 1 and 2 were sent; 3 and 4 were abandoned
        assert len(reset_acks) == 1
        assert frames[-1][0] == ider.CMD_RESET_OCCURRED_RESPONSE
        # The second chunk (where the reset landed) was still fully sent,
        # i.e. "finish the current chunk" before tearing down the read.
        assert len(data_frames[1][2][26:]) == 512
        assert engine._read_queue == []
        assert engine._read_state is None


class TestMutableConstantTrap:
    def test_writable_then_read_only_image_in_same_process_both_report_correctly(self, sent, tmp_path):
        writable_engine = IderEngine(send=[].append)
        writable_engine.start()
        writable_engine.feed(open_session_reply())
        writable_image = make_image(tmp_path, "writable.img", 512, writable=True)
        writable_engine.attach_device(writable_image)
        writable_sent: list[bytes] = []
        writable_engine._send_bytes = writable_sent.append
        writable_engine.feed(command_written(0x00, bytes([MODE_SENSE_10, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40]) + bytes(3), seq=1))
        _unused, _unused, writable_body = unpack_frame(writable_sent[-1])
        assert writable_body[26 + 3] & 0x80 == 0x00  # writable: bit cleared

        read_only_engine = IderEngine(send=[].append)
        read_only_engine.start()
        read_only_engine.feed(open_session_reply())
        read_only_image = make_image(tmp_path, "readonly.img", 512, writable=False)
        read_only_engine.attach_device(read_only_image)
        read_only_sent: list[bytes] = []
        read_only_engine._send_bytes = read_only_sent.append
        read_only_engine.feed(command_written(0x00, bytes([MODE_SENSE_10, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40]) + bytes(3), seq=1))
        _unused, _unused, read_only_body = unpack_frame(read_only_sent[-1])
        # If the writable session had mutated the shared constant in place,
        # this would incorrectly read back as writable (0x00) too.
        assert read_only_body[26 + 3] & 0x80 == 0x80

    def test_source_constant_is_never_mutated(self, tmp_path):
        pristine = bytes(ider._MS_FLOPPY_DISK_PAGE)
        ider._mode_sense_10_page(ider._MS_FLOPPY_DISK_PAGE, writable=True)
        assert ider._MS_FLOPPY_DISK_PAGE == pristine


class TestWriteOverrunCannotExtendTheBackingFile:
    """Regression tests for a genuine out-of-bounds write found in review.

    _scsi_write_request validates the *declared* transfer length against the
    image size, but the payload arrives separately in arbitrarily many 0x53
    frames. Before the fix, each frame was written at an advancing offset with
    no check against the declared length, so a host could declare a one-sector
    write (passing the bounds check) and then stream frames indefinitely,
    walking past the end of the image and growing the local file.

    This is remote-driven: the peer is firmware we authenticated to, but the
    transport may be plaintext (Small Business Mode has no TLS), so a
    well-behaved peer cannot be assumed.
    """

    def test_frames_exceeding_declared_length_are_refused(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "f.img", 512 * 2, writable=True)
        size_before = image.path.stat().st_size
        engine.attach_device(image)

        # Declare a single-sector write at LBA 0 -- entirely in bounds.
        engine.feed(command_written(0x00, cdb10(WRITE_10, 0, 1)))
        sent.clear()

        # Send a partial first frame, so the write is still pending, then a
        # second frame far larger than the 212 bytes still outstanding. A first
        # frame of the full 512 would legitimately complete the write and clear
        # the pending state, so the overrun has to arrive mid-transfer.
        engine.feed(data_from_host(b"A" * 300, seq=1))
        assert sent == [], "a partial frame must not be acknowledged"
        engine.feed(data_from_host(b"B" * 4096, seq=2))

        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        # Illegal LBA / out-of-range sense, not a success ack.
        assert body[-2] == 0x21

        assert image.path.stat().st_size == size_before, "backing file was extended by an over-long write"

    def test_pending_write_is_abandoned_after_an_overrun(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "f.img", 512 * 2, writable=True)
        engine.attach_device(image)
        engine.feed(command_written(0x00, cdb10(WRITE_10, 0, 1)))
        engine.feed(data_from_host(b"A" * 9999, seq=1))
        sent.clear()
        # A further unsolicited frame must be treated as unexpected, proving the
        # pending write was cleared rather than left half-applied.
        engine.feed(data_from_host(b"C" * 16, seq=2))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[-2] == 0x20  # invalid command / unsolicited payload

    def test_media_image_write_primitive_refuses_to_grow_the_file(self, tmp_path):
        # Defence in depth: the primitive that touches the filesystem enforces
        # the invariant independently of the SCSI layer above it.
        image = make_image(tmp_path, "f.img", 512, writable=True)
        size_before = image.path.stat().st_size
        with pytest.raises(ProtocolError, match="out-of-bounds"):
            image.write(0, b"X" * 1024)
        with pytest.raises(ProtocolError, match="out-of-bounds"):
            image.write(512, b"X")
        with pytest.raises(ProtocolError, match="out-of-bounds"):
            image.write(-1, b"X")
        assert image.path.stat().st_size == size_before


class TestWriteOverrunBoundary:
    """The exact boundary of the declared-transfer-length check in _on_data_from_host.

    The tests above prove the *consequence* the guard exists to prevent -- the backing
    file must not grow -- using overruns of 4096 and 9999 bytes. That is a real
    property, but it does not pin the boundary: loosening the bound from
    ``len(data) > remaining`` to ``> remaining + 512`` leaves every one of them passing,
    because MediaImage.write independently refuses to grow the file and catches the
    overrun a sector later. So the in-window bound was unverified, and a host could
    corrupt up to one sector *inside* the image outside its declared window -- an
    answer file silently gaining 512 bytes of the previous write's tail is not a
    failure anyone would notice from a task result.
    """

    #: Four sectors, so that a one-sector declared write leaves plenty of image
    #: *behind* the window. That is the point: MediaImage.write must not be the thing
    #: that rejects these, or the test would be probing the wrong guard.
    IMAGE_SECTORS = 4

    def _declare_one_sector_write(self, engine, sent, tmp_path, *, name="f.img"):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, name, 512 * self.IMAGE_SECTORS, writable=True)
        engine.attach_device(image)
        engine.feed(command_written(0x00, cdb10(WRITE_10, 0, 1)))  # declare exactly 512 bytes
        sent.clear()
        return image

    def test_exactly_remaining_is_accepted_and_completes(self, sent, engine, tmp_path):
        image = self._declare_one_sector_write(engine, sent, tmp_path)
        engine.feed(data_from_host(b"A" * 512, seq=1))  # len(data) == remaining
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[-3:] == bytes([0x00, 0x00, 0x00]), "an exactly-sized write must be acked as success"
        assert image.bytes_written == 512
        assert image.path.read_bytes()[:512] == b"A" * 512

    def test_exactly_remaining_plus_one_is_refused(self, sent, engine, tmp_path):
        image = self._declare_one_sector_write(engine, sent, tmp_path)
        engine.feed(data_from_host(b"A" * 513, seq=1))  # len(data) == remaining + 1
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[-2] == 0x21, "a one-byte overrun of the declared length must be refused (illegal LBA)"
        assert image.bytes_written == 0, "not one byte of an over-long frame may be written"
        assert image.path.read_bytes() == b"\x00" * (512 * self.IMAGE_SECTORS)

    def test_mid_transfer_boundary_is_measured_against_what_remains(self, sent, engine, tmp_path):
        # The bound is against *remaining*, not against the declared total, so it has to
        # hold after a partial frame too. 300 arrive, 212 remain; 212 is legal, 213 is not.
        image = self._declare_one_sector_write(engine, sent, tmp_path)
        engine.feed(data_from_host(b"A" * 300, seq=1))
        assert sent == [], "a partial frame must not be acknowledged"
        engine.feed(data_from_host(b"B" * 213, seq=2))  # remaining + 1
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[-2] == 0x21
        assert image.bytes_written == 300, "the refused frame must not have been applied"
        # The 300 legitimate bytes stand; the 213 must not have landed behind them.
        on_disk = image.path.read_bytes()
        assert on_disk[:300] == b"A" * 300
        assert on_disk[300:512] == b"\x00" * 212

    def test_mid_transfer_exactly_remaining_completes(self, sent, engine, tmp_path):
        image = self._declare_one_sector_write(engine, sent, tmp_path)
        engine.feed(data_from_host(b"A" * 300, seq=1))
        engine.feed(data_from_host(b"B" * 212, seq=2))  # exactly remaining
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[-3:] == bytes([0x00, 0x00, 0x00])
        assert image.bytes_written == 512
        assert image.path.read_bytes()[:512] == b"A" * 300 + b"B" * 212


class TestTruncatedImageMidSession:
    """A backing image truncated underneath a live session must terminate the transfer.

    ``image.blocks`` is computed once, at open, and the daemon
    (media_session._run_daemon) holds the image for as long as the redirected boot takes
    -- up to an hour for an OS install. So the bounds check in ``_scsi_read`` is a check
    against a *stale* block count, and a read that passed it can still hit EOF.

    Without the short-read guard in ``_pump_read`` that is not a wrong answer, it is an
    unbounded spin: ``read()`` returns b"", ``remaining`` never decreases, and the loop
    emits empty DATA_TO_HOST frames until the process is OOM killed. Dropping the
    ``_scsi_read`` bounds check during mutation testing made the unit suite hang at
    2.5 GB RSS for exactly this reason -- the mutation was not the bug, it only removed
    the thing that was hiding it.
    """

    @staticmethod
    def _bounded_send(sent: list[bytes], *, max_frames: int = 64, seconds: float = 10.0):
        """A ``send`` callable that fails fast instead of letting a spin hang CI.

        Belt and braces, because the two failure modes differ: a frame budget catches the
        spin deterministically and immediately (the fixed sequence below sends four frames,
        so 64 is not a close-run thing), while the wall-clock bound catches any future
        variant that spins without sending. Either way a regression fails this test in
        under a second rather than filling memory for as long as CI tolerates it.
        """
        deadline = time.monotonic() + seconds

        def _send(frame: bytes) -> None:
            if len(sent) >= max_frames:
                raise AssertionError(f"_pump_read emitted more than {max_frames} frames: it is not making progress")
            if time.monotonic() > deadline:
                raise AssertionError(f"_pump_read did not terminate within {seconds}s: it is not making progress")
            sent.append(frame)

        return _send

    def test_read_of_a_truncated_image_ends_with_a_medium_error_and_stops(self, tmp_path):
        sent: list[bytes] = []
        engine = IderEngine(send=self._bounded_send(sent))
        open_and_toggle(engine, sent, readbfr=512)

        image = make_image(tmp_path, "f.img", 512 * 4, fill=b"\xcd")
        engine.attach_device(image)
        assert image.blocks == 4

        # The image loses three of its four sectors while the session holds it open --
        # a partially written or externally rotated file, or a truncate by another
        # process. image.blocks is now stale, so the read below still passes bounds.
        os.truncate(image.path, 512)

        engine.feed(command_written(0x00, cdb10(READ_10, 0, 4)))

        frames = [unpack_frame(f) for f in sent]
        data_frames = [f for f in frames if f[0] == ider.CMD_DATA_TO_HOST]
        end_responses = [f for f in frames if f[0] == ider.CMD_COMMAND_END_RESPONSE]

        # Exactly the one sector that still exists was served, then the transfer ended.
        assert len(data_frames) == 1
        assert data_frames[0][2][26:] == b"\xcd" * 512
        assert data_frames[0][2][12] != 0x85, "a truncated read must not be reported as a completed transfer"

        # MEDIUM ERROR / UNRECOVERED READ ERROR, in the sense-bearing form so the host
        # can actually see why -- not a success ack, and not silence.
        assert len(end_responses) == 1
        body = end_responses[-1][2]
        assert body[12] == 0x87, "must use the sense-bearing form, which is the only one that transmits sense/asc/asq"
        assert body[-3:] == bytes([0x03, 0x11, 0x00])

        # And the engine is back to idle rather than mid-read, so the session survives.
        assert engine._read_state is None
        assert not engine.stopped

    def test_a_queued_read_behind_the_truncation_is_still_answered(self, tmp_path):
        # Terminating the failed transfer must not orphan the reads queued behind it:
        # firmware is waiting on a response for each CDB it sent, and an unanswered CDB
        # wedges the session just as thoroughly as a spin does.
        sent: list[bytes] = []
        engine = IderEngine(send=self._bounded_send(sent))
        open_and_toggle(engine, sent, readbfr=512)
        image = make_image(tmp_path, "f.img", 512 * 4)
        engine.attach_device(image)
        # Truncate before any read, not part-way through: MediaImage holds a buffered
        # file object, so a read that has already pulled the whole image into its 8 KiB
        # buffer keeps serving those bytes and would never observe the truncation at all.
        # That is worth knowing (it narrows, but does not close, the window in
        # production) and it would make this test prove nothing about the guard.
        os.truncate(image.path, 512)

        original_read = image.read
        calls = 0

        def read_then_queue_another(offset: int, length: int) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 1:
                # A second READ_10 arrives while the first is still in flight, so it is
                # queued -- and it asks for sectors that no longer exist either.
                engine._scsi_read(DEVICE_FLOPPY, image, 2, 1, False)
            return original_read(offset, length)

        image.read = read_then_queue_another
        engine.feed(command_written(0x00, cdb10(READ_10, 0, 2)))

        end_responses = [unpack_frame(f) for f in sent if unpack_frame(f)[0] == ider.CMD_COMMAND_END_RESPONSE]
        # One per abandoned transfer: the in-flight read and the queued one both hit EOF.
        assert len(end_responses) == 2
        assert all(f[2][-3:] == bytes([0x03, 0x11, 0x00]) for f in end_responses)
        assert engine._read_state is None
        assert engine._read_queue == []


class TestStatusData:
    """STATUS_DATA (0x49) driven through ``feed()``, i.e. the way firmware sends it.

    This frame is not incidental: type 3 REGS_TOGGLE is how firmware says whether it
    actually engaged IDE-R, and ``media_session._run_daemon`` gates ``session_state:
    attached`` on it. Before this class existed, ``_on_status_data`` had no test at all,
    so neither ``enabled`` nor ``feature_toggle_ok`` was ever set by anything --
    which is how the engine came to expose a toggle result that no consumer read.
    """

    def test_toggle_success_sets_feature_toggle_ok(self, sent, engine):
        open_and_toggle(engine, sent)
        assert engine.feature_toggle_ok is None, "unknown until firmware reports it, not assumed true"
        engine.feed(status_data(3, 1))
        assert engine.feature_toggle_ok is True
        assert sent == [], "a toggle verdict is a report, not a request; nothing to answer"

    @pytest.mark.parametrize("value", [0, 2, 0xFFFFFFFF])
    def test_toggle_failure_sets_feature_toggle_false(self, sent, engine, value):
        # docs/protocol-notes.md section 4.2: "value != 1 means the toggle failed" --
        # any value other than exactly 1, not just zero.
        open_and_toggle(engine, sent)
        engine.feed(status_data(3, value))
        assert engine.feature_toggle_ok is False

    def test_regs_status_sets_enabled_from_bit_1(self, sent, engine):
        open_and_toggle(engine, sent)
        engine.feed(status_data(2, 0x02))
        assert engine.enabled is True
        engine.feed(status_data(2, 0x01, seq=1))  # bit 0 set, bit 1 clear
        assert engine.enabled is False

    def test_regs_avail_with_bit_0_resends_the_feature_toggle(self, sent, engine):
        open_and_toggle(engine, sent)
        engine.feed(status_data(1, 0x01))
        assert len(sent) == 1
        cmdid, _unused, body = unpack_frame(sent[0])
        assert cmdid == ider.CMD_DISABLE_ENABLE_FEATURES
        assert body[0] == 3  # REGS_TOGGLE
        assert struct.unpack_from("<I", body, 1)[0] == ider.START_MODE_ON_REBOOT

    def test_regs_avail_without_bit_0_sends_nothing(self, sent, engine):
        open_and_toggle(engine, sent)
        engine.feed(status_data(1, 0x02))
        assert sent == []

    def test_unknown_status_type_is_ignored_without_tearing_down(self, sent, engine):
        open_and_toggle(engine, sent)
        engine.feed(status_data(9, 1))
        assert not engine.stopped
        assert engine.feature_toggle_ok is None
        assert engine.enabled is False


class TestInboundControlFramesThroughFeed:
    """The remaining inbound control frames, driven through ``feed()``.

    Reaching ``_dispatch`` through ``feed()`` rather than by calling the handler directly
    is the point: it also proves ``_peek_length`` agrees with each frame's real length.
    A length mismatch there does not fail cleanly -- it silently desynchronises the byte
    stream and surfaces as a sequence-mismatch teardown on some later, unrelated frame.
    """

    def test_close_stops_the_session(self, sent, engine):
        open_and_toggle(engine, sent)
        engine.feed(close_frame(seq=0))
        assert engine.stopped is True
        assert sent == [], "CLOSE is not acknowledged; the session is simply over"
        with pytest.raises(ProtocolError):
            engine.feed(keepalive_ping(seq=1))

    def test_close_mid_stream_leaves_trailing_bytes_unprocessed(self, sent, engine):
        # feed() must stop dispatching the moment the session goes down, rather than
        # continuing through whatever else happened to arrive in the same TCP segment.
        open_and_toggle(engine, sent)
        engine.feed(close_frame(seq=0) + keepalive_ping(seq=1))
        assert engine.stopped is True
        assert sent == []

    def test_keepalive_pong_is_a_silent_no_op(self, sent, engine):
        open_and_toggle(engine, sent)
        engine.feed(keepalive_pong(seq=0))
        assert sent == []
        assert not engine.stopped
        engine.feed(keepalive_ping(seq=1))  # sequence continued correctly across it
        assert unpack_frame(sent[-1])[0] == ider.CMD_KEEPALIVE_PONG

    def test_heartbeat_is_a_silent_no_op(self, sent, engine):
        open_and_toggle(engine, sent)
        engine.feed(heartbeat(seq=0))
        assert sent == []
        assert not engine.stopped
        engine.feed(keepalive_ping(seq=1))
        assert unpack_frame(sent[-1])[0] == ider.CMD_KEEPALIVE_PONG

    def test_reset_occurred_while_idle_is_acked_immediately(self, sent, engine):
        # The deferred case (a read in flight) is covered by TestResetDuringRead; this
        # is the idle path, and the only one that goes through feed()'s 9-byte length.
        open_and_toggle(engine, sent)
        engine.feed(reset_occurred(seq=0, mask=0x01))
        assert len(sent) == 1
        assert unpack_frame(sent[0])[0] == ider.CMD_RESET_OCCURRED_RESPONSE
        engine.feed(keepalive_ping(seq=1))  # 9-byte frame consumed exactly
        assert unpack_frame(sent[-1])[0] == ider.CMD_KEEPALIVE_PONG


class TestModeSense10Pages:
    """MODE_SENSE(10) across the page codes real firmware asks for.

    Page ``0x3F`` ("return all pages") matters most: it is what a BIOS typically asks
    for, and it was the one page code with no test. The write-protect bit that hardware
    qualification stage 6 checks lives at index 3 of every one of these canned arrays,
    so testing it on a single page proved it for a sixth of the surface.
    """

    def test_page_3f_floppy_reports_writable_when_the_image_is_writable(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512, writable=True))
        engine.feed(command_written(0x00, mode_sense_10(0x3F, buflen=0x100)))
        _unused, _unused, body = unpack_frame(sent[-1])
        page = body[26:]
        assert page[0:2] == ider._MS_3F_FLOPPY[0:2], "must be the all-pages array, not the 0x05 disk page"
        assert page[3] & 0x80 == 0x00
        assert page[4:] == ider._MS_3F_FLOPPY[4:], "only the write-protect byte may differ from the canned array"

    def test_page_3f_floppy_reports_write_protected_when_read_only(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512, writable=False))
        engine.feed(command_written(0x00, mode_sense_10(0x3F, buflen=0x100)))
        _unused, _unused, body = unpack_frame(sent[-1])
        assert body[26:] == ider._MS_3F_FLOPPY, "read-only: the canned array already carries 0x80, byte-for-byte"

    def test_page_3f_selects_the_ls120_array_above_the_geometry_threshold(self, sent, engine, tmp_path):
        # Floppy vs LS-120 page selection is by sector count <= 0xB40 (2880 sectors,
        # i.e. a 1.44 MB floppy). 0xB41 sectors is the first size that is not one.
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "big.img", 512 * 0xB41))
        engine.feed(command_written(0x00, mode_sense_10(0x3F, buflen=0x100)))
        _unused, _unused, body = unpack_frame(sent[-1])
        assert body[26:] == ider._MS_3F_LS120

    def test_page_3f_cdrom_returns_the_cd_array(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM))
        engine.feed(command_written(0x10, mode_sense_10(0x3F, buflen=0x100)))
        _unused, _unused, body = unpack_frame(sent[-1])
        assert body[26:] == ider._MS_3F_CD
        assert body[26 + 3] & 0x80 == 0x80, "the CD slot is read-only by design and must always say so"

    def test_page_01_error_recovery_per_device_and_geometry(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512))
        engine.attach_device(make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM))
        engine.feed(command_written(0x00, mode_sense_10(0x01)))
        assert unpack_frame(sent[-1])[2][26:] == ider._MS_FLOPPY_ERROR_RECOVERY
        engine.feed(command_written(0x10, mode_sense_10(0x01), seq=1))
        assert unpack_frame(sent[-1])[2][26:] == ider._MS_CD_ERROR_RECOVERY

    @pytest.mark.parametrize(
        ("page", "expected"),
        [
            (0x1A, "_MS_CD_1A"),
            (0x1D, "_MS_CD_1D"),
            (0x2A, "_MS_CD_2A"),
        ],
    )
    def test_cdrom_only_pages(self, sent, engine, tmp_path, page, expected):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM))
        engine.feed(command_written(0x10, mode_sense_10(page)))
        assert unpack_frame(sent[-1])[2][26:] == getattr(ider, expected)

    @pytest.mark.parametrize("page", [0x1A, 0x1D, 0x2A])
    def test_cdrom_only_pages_are_refused_on_the_floppy_slot(self, sent, engine, tmp_path, page):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512))
        engine.feed(command_written(0x00, mode_sense_10(page)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[-3:] == bytes([0x05, 0x20, 0x00])  # illegal request / invalid command

    def test_page_05_is_floppy_only(self, sent, engine, tmp_path):
        # There is no canned 0x05 array for the CD slot, so the CD case must fall through
        # to a sense rather than answering with a floppy geometry page.
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM))
        engine.feed(command_written(0x10, mode_sense_10(0x05)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[-3:] == bytes([0x05, 0x20, 0x00])

    def test_zero_allocation_length_returns_the_short_canned_header(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512))
        engine.feed(command_written(0x00, mode_sense_10(0x3F, buflen=0)))
        _unused, _unused, body = unpack_frame(sent[-1])
        assert struct.unpack(">II", body[26:34]) == (0x003C, 0x0008)


class TestRemainingScsiDispatchArms:
    """The dispatch arms with no other coverage.

    Kept deliberately terse. These are the arms a real BIOS touches on the way to a
    boot, and the risk being managed is that one of them is simply not wired up (a
    typo'd opcode, an arm answering on the wrong device) -- which a single frame per arm
    catches. Anything with real logic of its own has its own class above; padding these
    out further would add suite time without adding evidence.
    """

    def test_read_6_serves_data_like_read_10(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent, readbfr=512)
        image = make_image(tmp_path, "f.img", 512 * 2)
        image.path.write_bytes(b"\x11" * 512 + b"\x22" * 512)
        engine.attach_device(image)
        engine.feed(command_written(0x00, cdb6(READ_6, 1, 1)))  # second sector
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_DATA_TO_HOST
        assert body[26:] == b"\x22" * 512

    def test_read_6_length_zero_means_256_sectors(self, sent, engine, tmp_path):
        # cdb[4] == 0 is 256 sectors, not a zero-length read -- so against a 4-sector
        # image this is an out-of-bounds request, which is what proves the decode.
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512 * 4))
        engine.feed(command_written(0x00, cdb6(READ_6, 0, 0)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[12] == 0xC5  # error form, as the READ_10 bounds path also uses

    def test_write_6_takes_the_same_write_path_as_write_10(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "f.img", 512 * 2, writable=True)
        engine.attach_device(image)
        engine.feed(command_written(0x00, cdb6(WRITE_6, 1, 1)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_GET_DATA_FROM_HOST
        assert struct.unpack_from("<H", body, 1)[0] == 512
        engine.feed(data_from_host(b"W" * 512, seq=1))
        assert image.path.read_bytes() == b"\x00" * 512 + b"W" * 512

    def test_write_6_is_refused_on_a_read_only_image(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512, writable=False))
        engine.feed(command_written(0x00, cdb6(WRITE_6, 0, 1)))
        _unused, _unused, body = unpack_frame(sent[-1])
        assert body[-3:] == bytes([0x07, 0x27, 0x00]), "write protected, not 'no medium'"

    def test_start_stop_is_acked(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512))
        engine.feed(command_written(0x00, bytes([START_STOP, 0x00, 0x00, 0x00, 0x01]) + bytes(7)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[12] == 0xC5  # plain ack (the error form carries no sense)

    def test_allow_medium_removal_acks_with_medium_and_senses_without(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        cdb = bytes([ALLOW_MEDIUM_REMOVAL, 0x00, 0x00, 0x00, 0x00]) + bytes(7)
        engine.feed(command_written(0x00, cdb))  # nothing attached yet
        assert unpack_frame(sent[-1])[2][18] == DEVICE_FLOPPY
        no_medium = unpack_frame(sent[-1])[2]
        engine.attach_device(make_image(tmp_path, "f.img", 512))
        engine.feed(command_written(0x00, cdb, seq=1))
        with_medium = unpack_frame(sent[-1])[2]
        # Both use the error wire form, so they are byte-identical -- see
        # _send_command_end_response's docstring. What is being proven here is that the
        # arm answers at all, on the right device, in both states.
        assert no_medium == with_medium
        assert not engine.stopped

    def test_read_format_capacities(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512 * 4))
        engine.feed(command_written(0x00, bytes([READ_FORMAT_CAPACITIES]) + bytes(11)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_DATA_TO_HOST
        assert body[26:] == struct.pack(">I", 8) + bytes([0x00, 0x00, 0x0B, 0x40, 0x02, 0x00, 0x02, 0x00])

    def test_read_format_capacities_without_medium_senses(self, sent, engine):
        open_and_toggle(engine, sent)
        engine.feed(command_written(0x00, bytes([READ_FORMAT_CAPACITIES]) + bytes(11)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[-3:] == bytes([0x05, 0x24, 0x00])

    def test_read_toc_format_0_msf_and_lba_variants(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM))
        engine.feed(command_written(0x10, bytes([READ_TOC, 0x00, 0x00]) + bytes(9)))
        lba_form = unpack_frame(sent[-1])[2][26:]
        engine.feed(command_written(0x10, bytes([READ_TOC, 0x02, 0x00]) + bytes(9), seq=1))
        msf_form = unpack_frame(sent[-1])[2][26:]
        assert len(lba_form) == len(msf_form) == 20
        # Two different canned TOCs, not one array sent twice: the msf flag selects
        # MSF-encoded track and lead-out addresses, which is the whole point of it.
        assert lba_form != msf_form
        assert lba_form[:10] == msf_form[:10]  # descriptor header is common to both
        assert lba_form.endswith(bytes([0x00, 0x00, 0x00, 0x00]))
        assert msf_form.endswith(bytes([0x00, 0x00, 0x34, 0x13]))

    def test_read_toc_is_refused_on_the_floppy_slot(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512))
        engine.feed(command_written(0x00, bytes([READ_TOC, 0x00, 0x00]) + bytes(9)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[18] == DEVICE_FLOPPY

    def test_read_disc_info_reports_not_implemented(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM))
        engine.feed(command_written(0x10, bytes([READ_DISC_INFO]) + bytes(11)))
        _unused, _unused, body = unpack_frame(sent[-1])
        assert body[-3:] == bytes([0x05, 0x20, 0x00])  # BIOSes accept this

    def test_mode_select_10_is_refused(self, sent, engine, tmp_path):
        # This is the arm that keeps a host from *changing* mode parameters -- notably
        # the write-protect bit it was told about in MODE_SENSE.
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512, writable=True))
        engine.feed(command_written(0x00, bytes([MODE_SELECT_10, 0x10]) + bytes(10)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[12] == 0xC5
        assert engine._pending_write is None, "MODE_SELECT must not open a data-in phase"

    def test_get_performance_returns_the_canned_reply(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM))
        engine.feed(command_written(0x10, bytes([GET_PERFORMANCE]) + bytes(11)))
        cmdid, _unused, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_DATA_TO_HOST
        assert body[26:] == ider._GET_PERFORMANCE_REPLY
