# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import struct

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
GET_CONFIGURATION = 0x46
GET_EVENT_STATUS = 0x4A
MODE_SENSE_10 = 0x5A
TEST_UNIT_READY = 0x00


def cdb6(op: int, lba: int, length: int) -> bytes:
    return bytes([op, (lba >> 16) & 0x1F, (lba >> 8) & 0xFF, lba & 0xFF, length & 0xFF, 0x00]) + bytes(6)


def cdb10(op: int, lba: int, length: int) -> bytes:
    # The real SCSI CDB for READ_10/WRITE_10/WRITE_AND_VERIFY is 10 bytes;
    # the COMMAND_WRITTEN CDB slot is a fixed 12 bytes, so it is padded.
    return bytes([op, 0x00]) + struct.pack(">I", lba) + bytes([0x00]) + struct.pack(">H", length) + bytes(3)


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
        cmdid, _, body = unpack_frame(sent[0])
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
        cmdid, _, body = unpack_frame(sent[0])
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
        cmdid, _, body = unpack_frame(sent[-1])
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
        _, _, body1 = unpack_frame(sent[-1])
        expected_error_form = bytes(12) + bytes([0xC5, 0x00, 0x03, 0x00, 0x00, 0x00, DEVICE_FLOPPY, 0x50, 0x00, 0x00, 0x00])
        assert body1 == expected_error_form
        sent.clear()
        engine.feed(command_written(0x00, cdb6(TEST_UNIT_READY, 0, 0), seq=1))
        _cmdid, _, body2 = unpack_frame(sent[-1])
        assert body2 == expected_error_form

    def test_read_capacity(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512 * 10))
        cdb = bytes([READ_CAPACITY]) + bytes(11)
        engine.feed(command_written(0x00, cdb))
        cmdid, _, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_DATA_TO_HOST
        payload = body[26:34]
        assert struct.unpack(">I", payload[0:4])[0] == 9  # 10 blocks - 1
        assert payload[6] == 0x02  # floppy blocksize hi byte

    def test_mode_sense_6_write_protected_when_read_only(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512, writable=False))
        engine.feed(command_written(0x00, bytes([MODE_SENSE_6, 0x00, 0x3F, 0x00]) + bytes(8)))
        _, _, body = unpack_frame(sent[-1])
        data = body[26:]
        assert data == bytes([0, 0x00, 0x80, 0])

    def test_mode_sense_6_writable_clears_bit(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512, writable=True))
        engine.feed(command_written(0x00, bytes([MODE_SENSE_6, 0x00, 0x3F, 0x00]) + bytes(8)))
        _, _, body = unpack_frame(sent[-1])
        data = body[26:]
        assert data == bytes([0, 0x00, 0x00, 0])

    def test_unknown_scsi_command_gets_generic_sense(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512))
        engine.feed(command_written(0x00, bytes([0xEE]) + bytes(11)))
        cmdid, _, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body == bytes(12) + bytes([0x87, 0x50, 0x03, 0x00, 0x00, 0x00, DEVICE_FLOPPY, 0x51, 0x05, 0x20, 0x00])

    def test_get_event_status_notification(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "f.img", 512))
        cdb = bytes([GET_EVENT_STATUS, 0x01, 0x00, 0x00, 0x10]) + bytes(7)
        engine.feed(command_written(0x00, cdb))
        _, _, body = unpack_frame(sent[-1])
        assert body[26:] == bytes([0x00, 0x02, 0x80, 0x00])

    def test_get_configuration_buflen_zero(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM))
        cdb = bytes([GET_CONFIGURATION, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + bytes(3)
        engine.feed(command_written(0x10, cdb))
        _, _, body = unpack_frame(sent[-1])
        assert struct.unpack(">II", body[26:34]) == (0x003C, 0x0008)

    def test_get_configuration_current_profile_list(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        engine.attach_device(make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM))
        # RT=2 (current), starting feature 0 -> only the profile list matches.
        cdb = bytes([GET_CONFIGURATION, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20]) + bytes(3)
        engine.feed(command_written(0x10, cdb))
        _, _, body = unpack_frame(sent[-1])
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
        assert all(cmdid == ider.CMD_DATA_TO_HOST for cmdid, _, _ in frames)
        assert len(frames) == 4  # 2048 bytes / 512-byte readbfr
        reassembled = b""
        for i, (_, _, body) in enumerate(frames):
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
        _, _, body = unpack_frame(sent[0])
        assert body[12] == 0x85
        assert body[26:] == b"\xab" * 512

    def test_read_out_of_bounds_rejected(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "f.img", 512)
        engine.attach_device(image)
        engine.feed(command_written(0x00, cdb10(READ_10, 0, 2)))  # only 1 block exists
        cmdid, _, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[12] == 0xC5  # error-form: bounds failure sense is not transmitted, matching the read path


class TestWritePath:
    def test_multi_frame_write_lands_correct_bytes_at_correct_offset(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "f.img", 512 * 4, writable=True)
        engine.attach_device(image)

        engine.feed(command_written(0x00, cdb10(WRITE_10, 1, 2)))  # write 2 sectors starting at LBA 1
        cmdid, _, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_GET_DATA_FROM_HOST
        chunk = struct.unpack_from("<H", body, 1)[0]
        assert chunk == 1024
        sent.clear()

        payload = (b"A" * 512) + (b"B" * 512)
        # Firmware splits the logical write across two 0x53 frames.
        engine.feed(data_from_host(payload[:300], seq=1))
        assert sent == []  # not complete yet, no ack
        engine.feed(data_from_host(payload[300:], seq=2))
        cmdid, _, ack_body = unpack_frame(sent[-1])
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
        cmdid, _, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body == bytes(12) + bytes([0x87, 0x70, 0x03, 0x00, 0x00, 0x00, DEVICE_FLOPPY, 0x51, 0x07, 0x27, 0x00])
        assert image.path.read_bytes() == original

    def test_write_out_of_bounds_rejected_and_file_unchanged(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "f.img", 512, writable=True)
        original = image.path.read_bytes()
        engine.attach_device(image)
        engine.feed(command_written(0x00, cdb10(WRITE_10, 0, 2)))  # 2 sectors, only 1 exists
        cmdid, _, body = unpack_frame(sent[-1])
        assert cmdid == ider.CMD_COMMAND_END_RESPONSE
        assert body[12] == 0xC5  # error-form
        assert image.path.read_bytes() == original
        assert image.path.stat().st_size == len(original)

    def test_cdrom_device_never_accepts_writes_even_if_backing_flag_were_writable(self, sent, engine, tmp_path):
        open_and_toggle(engine, sent)
        image = make_image(tmp_path, "c.iso", 2048, device_code=DEVICE_CDROM)
        engine.attach_device(image)
        engine.feed(command_written(0x10, cdb10(WRITE_10, 0, 1)))
        cmdid, _, body = unpack_frame(sent[-1])
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
        _, _, writable_body = unpack_frame(writable_sent[-1])
        assert writable_body[26 + 3] & 0x80 == 0x00  # writable: bit cleared

        read_only_engine = IderEngine(send=[].append)
        read_only_engine.start()
        read_only_engine.feed(open_session_reply())
        read_only_image = make_image(tmp_path, "readonly.img", 512, writable=False)
        read_only_engine.attach_device(read_only_image)
        read_only_sent: list[bytes] = []
        read_only_engine._send_bytes = read_only_sent.append
        read_only_engine.feed(command_written(0x00, bytes([MODE_SENSE_10, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40]) + bytes(3), seq=1))
        _, _, read_only_body = unpack_frame(read_only_sent[-1])
        # If the writable session had mutated the shared constant in place,
        # this would incorrectly read back as writable (0x00) too.
        assert read_only_body[26 + 3] & 0x80 == 0x80

    def test_source_constant_is_never_mutated(self, tmp_path):
        pristine = bytes(ider._MS_FLOPPY_DISK_PAGE)
        ider._mode_sense_10_page(ider._MS_FLOPPY_DISK_PAGE, writable=True)
        assert ider._MS_FLOPPY_DISK_PAGE == pristine
