import pytest

pytest.importorskip("Crypto.Cipher.AES")

from moyu_v10_rescue.cube_protocol import (
    A1Info,
    packet,
    bit_groups_msb,
    parse_a5_move,
    parse_a3_facelets,
)

# Decrypted A1 responses captured from both cubes.
A1_1322 = bytes.fromhex("a1 e5 a7 01 8b 01 00 00 00 02 01 02 0b 60 59 40 00 00 00 00")
A1_8DD8 = bytes.fromhex("a1 22 f9 81 60 bb e0 96 53 02 01 02 0b 63 e2 80 00 00 00 00")


class TestA1Info:
    def test_reads_the_model_and_versions(self):
        info = A1Info.from_decrypted(b"", A1_1322)
        assert info.model_bytes == bytes.fromhex("e5 a7 01 8b 01 00 00 00")
        assert info.hw_version == (2, 1)
        assert info.sw_version == (2, 11)
        assert info.version_text == "hw 2.1, sw 2.11"

    def test_both_cubes_run_the_same_firmware(self):
        # WRITE_DATA is only known to time out on one firmware. These two cubes
        # report the same one, so the 8DD8 timeout is evidence about 1322.
        a, b = A1Info.from_decrypted(b"", A1_1322), A1Info.from_decrypted(b"", A1_8DD8)
        assert (a.hw_version, a.sw_version) == (b.hw_version, b.sw_version)

    def test_tolerates_a_short_response(self):
        info = A1Info.from_decrypted(b"", bytes.fromhex("a1 57 43 55"))
        assert info.hw_version is None
        assert info.version_text == "hw unknown, sw unknown"


def test_packet_builds_20_byte_zero_padded_message():
    p = packet(0xAC, b"\x00\x01")
    assert len(p) == 20
    assert p[:3] == bytes.fromhex("ac 00 01")
    assert p[3:] == b"\x00" * 17


def test_packet_rejects_payloads_over_19_bytes():
    with pytest.raises(ValueError, match="payload too long"):
        packet(0xA1, b"x" * 20)


def test_bit_groups_msb_decodes_known_5_bit_move_codes():
    # From the real A5 packet: bytes 12..16 = 01 42 50 40 00.
    # Interpreted as five 5-bit values MSB-first, that yields [0, 5, 1, 5, 0].
    assert bit_groups_msb(bytes.fromhex("01 42 50 40 00"), width=5, count=5) == [0, 5, 1, 5, 0]


def test_parse_a5_move_uses_real_log_fixture_first_event():
    dec = bytes.fromhex(
        "a5 01 29 00 8e 00 8c 00 64 00 62 00 01 42 50 40 00 00 00 00"
    )
    move = parse_a5_move(dec)
    assert move.serial == 0
    assert move.move_codes == [0, 5, 1, 5, 0]
    assert move.guessed_moves == ["F", "U'", "F'", "U'", "F"]
    assert move.times_be == [297, 142, 140, 100, 98]
    assert move.times_le == [10497, 36352, 35840, 25600, 25088]


@pytest.mark.parametrize(
    ("packet_hex", "serial", "codes"),
    [
        ("a5 00 84 01 29 00 8e 00 8c 00 64 01 20 0a 12 90 00 00 00 00", 1, [4, 0, 5, 1, 5]),
        ("a5 00 53 00 84 01 29 00 8e 00 8c 02 09 00 50 c0 00 00 00 00", 2, [1, 4, 0, 5, 1]),
        ("a5 00 70 00 53 00 84 01 29 00 8e 03 48 48 02 84 00 00 00 00", 3, [9, 1, 4, 0, 5]),
    ],
)
def test_parse_a5_move_additional_real_events(packet_hex, serial, codes):
    move = parse_a5_move(bytes.fromhex(packet_hex))
    assert move.serial == serial
    assert move.move_codes == codes


def test_parse_a3_facelets_returns_six_faces_and_serial():
    # Synthetic zero color state: 48 packed 3-bit zeros plus serial 7.
    pkt = bytes([0xA3]) + b"\x00" * 18 + bytes([7])
    faces, serial = parse_a3_facelets(pkt)
    assert serial == 7
    assert list(faces) == ["F", "B", "U", "D", "L", "R"]
    for raw_values, guess in faces.values():
        assert raw_values == [0] * 8
        assert guess == "G" * 8
