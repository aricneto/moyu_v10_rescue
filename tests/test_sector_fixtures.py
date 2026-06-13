from pathlib import Path

SECTOR_DIR = Path(__file__).parent / "fixtures" / "sectors"
BAK = SECTOR_DIR / "v10_sector_0x0007b000.bak.bin"
PATCHED = SECTOR_DIR / "v10_sector_0x0007b000_patched.bin"

CORRUPT_MODEL = bytes.fromhex("22 f9 81 60 bb e0 96 53")
GOOD_MODEL = b"WCU_MY32"
SUFFIX = b"_8DD8"
MAC_BYTES_IN_RECORD = bytes.fromhex("d8 8d 01 16 30 cf")


def test_sector_fixture_files_exist_and_are_4k():
    assert BAK.exists()
    assert PATCHED.exists()
    assert BAK.stat().st_size == 0x1000
    assert PATCHED.stat().st_size == 0x1000


def test_backup_sector_contains_real_corrupt_identity_record():
    data = BAK.read_bytes()
    assert data[0x006:0x00E] == CORRUPT_MODEL
    assert data[0x00E:0x013] == SUFFIX
    assert data[0x01A:0x020] == MAC_BYTES_IN_RECORD
    assert data[0x000:0x006] == bytes.fromhex("25 12 23 cb 0e 09")


def test_patched_sector_preserves_everything_except_model_bytes():
    original = BAK.read_bytes()
    patched = PATCHED.read_bytes()

    assert patched[0x006:0x00E] == GOOD_MODEL
    assert patched[0x00E:0x013] == SUFFIX
    assert patched[0x01A:0x020] == MAC_BYTES_IN_RECORD

    diffs = [i for i, (a, b) in enumerate(zip(original, patched)) if a != b]
    assert diffs == list(range(0x006, 0x00E))


def test_blank_sector_detection_fixture_shape():
    blank = b"\xFF" * 0x1000
    assert all(b == 0xFF for b in blank)
    assert CORRUPT_MODEL not in blank
    assert GOOD_MODEL not in blank
