import pytest

pytest.importorskip("Crypto.Cipher.AES")

from moyu_v10_rescue.crypto import CubeCrypto, salted, salt_candidates, ROOT_KEY, ROOT_IV
from moyu_v10_rescue.config import parse_mac


MAC = "CF:30:16:01:8D:D8"
SALT_REVERSED = bytes.fromhex("d8 8d 01 16 30 cf")
SALT_SAME = bytes.fromhex("cf 30 16 01 8d d8")

A1_RAW = bytes.fromhex("4d ab 5c 00 67 62 2b 14 11 f9 03 5f 3f fe ee 5c 6c 17 ce 52")
A1_DEC = bytes.fromhex("a1 22 f9 81 60 bb e0 96 53 02 01 02 0b 63 e2 80 00 00 00 00")
BATTERY_RAW = bytes.fromhex("da 2d ee b8 08 f2 a2 91 4f 6a 9e 8f bd d7 2e 79 d7 f5 5f 37")
BATTERY_DEC = bytes.fromhex("a4 44 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
MOVE_RAW = bytes.fromhex("0a cc dc 54 79 f7 01 b0 54 60 94 b6 97 6a de 00 71 c8 73 19")
MOVE_DEC = bytes.fromhex("a5 01 29 00 8e 00 8c 00 64 00 62 00 01 42 50 40 00 00 00 00")


def test_salted_root_values_use_reversed_mac_salt():
    key = salted(ROOT_KEY, SALT_REVERSED)
    iv = salted(ROOT_IV, SALT_REVERSED)
    assert key[:6].hex(" ") == "ed 05 3b 72 97 dd"
    assert iv[:6].hex(" ") == "e9 b0 27 3b b6 f9"


@pytest.mark.parametrize(
    ("raw", "decrypted"),
    [
        (A1_RAW, A1_DEC),
        (BATTERY_RAW, BATTERY_DEC),
        (MOVE_RAW, MOVE_DEC),
    ],
)
def test_crypto_decrypts_real_log_vectors(raw, decrypted):
    crypto = CubeCrypto.from_salt("fixture", SALT_REVERSED)
    assert crypto.decrypt(raw) == decrypted


@pytest.mark.parametrize(
    ("raw", "decrypted"),
    [
        (A1_RAW, A1_DEC),
        (BATTERY_RAW, BATTERY_DEC),
        (MOVE_RAW, MOVE_DEC),
    ],
)
def test_crypto_encrypt_round_trips_real_log_vectors(raw, decrypted):
    crypto = CubeCrypto.from_salt("fixture", SALT_REVERSED)
    assert crypto.encrypt(decrypted) == raw


def test_same_direction_mac_salt_does_not_decrypt_a1_fixture():
    crypto = CubeCrypto.from_salt("wrong", SALT_SAME)
    assert crypto.decrypt(A1_RAW) != A1_DEC


def test_encrypt_rejects_too_short_packets():
    crypto = CubeCrypto.from_salt("fixture", SALT_REVERSED)
    with pytest.raises(ValueError, match="at least 16"):
        crypto.encrypt(b"short")


class FakeAdv:
    manufacturer_data = {0x0000: bytes.fromhex("00 00 30 d8 8d 01 16 30 cf")}


def test_salt_candidates_include_manual_and_manufacturer_windows_without_duplicates():
    candidates = salt_candidates(MAC, FakeAdv())
    salts = [c.salt for c in candidates]
    assert SALT_REVERSED in salts
    assert SALT_SAME in salts
    assert len(salts) == len(set(salts))
    assert all(len(s) == 6 for s in salts)
    assert parse_mac(MAC)[::-1] in salts
