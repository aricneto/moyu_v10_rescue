"""Locating and rebuilding the advertising identity record.

Fixtures are real sector bytes from two cubes with the same failure mode but
different corruption lengths:

  8DD8 (tests/fixtures/logs/flash_scan_before_erase.log)
      the 8-byte model was overwritten with 8 junk bytes, so the record kept
      its original length and the A1 model bytes appeared verbatim in flash.

  1322 (HWTrainer session, 2026-08-04)
      the 8-byte model was replaced by 5 junk bytes and the AD length byte was
      rewritten to match, so the record is 3 bytes shorter and the A1 field --
      always 8 bytes wide -- comes back zero-padded.
"""

from moyu_v10_rescue.config import ToolConfig
from moyu_v10_rescue.identity import (
    SECTOR_SIZE,
    build_repaired_sector,
    flash_model_pattern,
    parse_identity_record,
    sector_from_backup_name,
)


def sector_from(head: bytes) -> bytes:
    return bytes(head) + b"\xFF" * (SECTOR_SIZE - len(head))


# Sector 0x0007b000, cube CF:30:16:02:13:22. Model field is 5 junk bytes.
SECTOR_1322 = sector_from(bytes.fromhex(
    "25 12 23 cb"                          # record header (unidentified)
    "0b 09"                                # AD: length 11, type 0x09 complete local name
    "e5 a7 01 8b 01 5f 31 33 32 32"        # corrupt model + "_1322"
    "0c ff 00 00 00 00 30 22 13 02 16 30 cf"  # AD: manufacturer data, reversed MAC
    "00 00 00 19 02 24 bc 3a 00 ff ff 13 06 25 ac d2 0f"
))

# Sector 0x0007b000, cube CF:30:16:01:8D:D8. Model field is 8 junk bytes.
SECTOR_8DD8 = sector_from(bytes.fromhex(
    "00 00 00 00"
    "0e 09"                                # AD: length 14 -- original length preserved
    "22 f9 81 60 bb e0 96 53 5f 38 44 44 38"  # corrupt model + "_8DD8"
    "0c ff 00 00 00 00 30 d8 8d 01 16 30 cf"
))

A1_MODEL_1322 = bytes.fromhex("e5 a7 01 8b 01 00 00 00")  # 5 real bytes + A1 padding
A1_MODEL_8DD8 = bytes.fromhex("22 f9 81 60 bb e0 96 53")  # all 8 bytes real


def cfg_1322() -> ToolConfig:
    return ToolConfig(target_name_suffix="1322", color=False)


def cfg_8DD8() -> ToolConfig:
    return ToolConfig(target_name_suffix="8DD8", color=False)


class TestFlashModelPattern:
    def test_strips_the_a1_zero_padding(self):
        # Flash stores only the real bytes; searching for the padded field finds
        # nothing, which is what made the 1322 cube unrepairable.
        assert flash_model_pattern(A1_MODEL_1322) == bytes.fromhex("e5 a7 01 8b 01")

    def test_is_a_no_op_when_all_eight_bytes_are_real(self):
        assert flash_model_pattern(A1_MODEL_8DD8) == A1_MODEL_8DD8

    def test_handles_missing_model(self):
        assert flash_model_pattern(None) == b""
        assert flash_model_pattern(b"\x00" * 8) == b""


class TestParseIdentityRecord:
    def test_locates_a_shortened_record(self):
        record = parse_identity_record(SECTOR_1322, A1_MODEL_1322, cfg_1322())
        assert record is not None
        assert record.header_offset == 0x004
        assert record.name_offset == 0x006
        assert record.name == bytes.fromhex("e5 a7 01 8b 01") + b"_1322"
        assert record.tail_offset == 0x010

    def test_locates_a_full_length_record(self):
        record = parse_identity_record(SECTOR_8DD8, A1_MODEL_8DD8, cfg_8DD8())
        assert record is not None
        assert record.header_offset == 0x004
        assert record.name_offset == 0x006
        assert record.name.endswith(b"_8DD8")
        assert record.tail_offset == 0x013

    def test_returns_none_when_the_model_is_absent(self):
        assert parse_identity_record(SECTOR_1322, b"\xAA" * 8, cfg_1322()) is None

    def test_returns_none_when_the_ad_type_is_not_a_local_name(self):
        # Junk bytes could match anywhere; without the 0x09 type byte in front,
        # this is not an advertising name record and must not be rewritten.
        broken = bytearray(SECTOR_1322)
        broken[0x005] = 0x08  # shortened local name
        assert parse_identity_record(bytes(broken), A1_MODEL_1322, cfg_1322()) is None

    def test_returns_none_when_the_name_does_not_carry_the_expected_suffix(self):
        record = parse_identity_record(SECTOR_1322, A1_MODEL_1322, cfg_8DD8())
        assert record is None


class TestBuildRepairedSector:
    def test_restores_the_model_and_fixes_the_length_byte(self):
        cfg = cfg_1322()
        record = parse_identity_record(SECTOR_1322, A1_MODEL_1322, cfg)

        repaired = build_repaired_sector(SECTOR_1322, record, cfg.clean_name_bytes)

        assert repaired[0x004] == 0x0E  # 1 type byte + 13 name bytes
        assert repaired[0x005] == 0x09
        assert repaired[0x006:0x013] == b"WCU_MY32_1322"

    def test_preserves_the_bytes_before_the_record(self):
        cfg = cfg_1322()
        record = parse_identity_record(SECTOR_1322, A1_MODEL_1322, cfg)
        repaired = build_repaired_sector(SECTOR_1322, record, cfg.clean_name_bytes)
        assert repaired[:0x004] == SECTOR_1322[:0x004]

    def test_shifts_the_manufacturer_record_intact(self):
        # The repaired name is 3 bytes longer, so everything after it moves. The
        # manufacturer block carries the MAC that seeds the AES salt, so losing
        # or truncating it would be worse than the corruption being repaired.
        cfg = cfg_1322()
        record = parse_identity_record(SECTOR_1322, A1_MODEL_1322, cfg)
        repaired = build_repaired_sector(SECTOR_1322, record, cfg.clean_name_bytes)

        mfg = bytes.fromhex("0c ff 00 00 00 00 30 22 13 02 16 30 cf")
        assert repaired[0x013:0x013 + len(mfg)] == mfg
        assert SECTOR_1322[record.tail_offset:].rstrip(b"\xFF") in repaired

    def test_keeps_the_sector_exactly_one_page(self):
        cfg = cfg_1322()
        record = parse_identity_record(SECTOR_1322, A1_MODEL_1322, cfg)
        repaired = build_repaired_sector(SECTOR_1322, record, cfg.clean_name_bytes)
        assert len(repaired) == SECTOR_SIZE
        assert repaired[-1] == 0xFF

    def test_repaired_sector_reparses_as_the_clean_name(self):
        cfg = cfg_1322()
        record = parse_identity_record(SECTOR_1322, A1_MODEL_1322, cfg)
        repaired = build_repaired_sector(SECTOR_1322, record, cfg.clean_name_bytes)

        reparsed = parse_identity_record(repaired, cfg.good_model, cfg)
        assert reparsed is not None
        assert reparsed.name == b"WCU_MY32_1322"

    def test_is_idempotent_on_an_already_clean_record(self):
        cfg = cfg_1322()
        record = parse_identity_record(SECTOR_1322, A1_MODEL_1322, cfg)
        once = build_repaired_sector(SECTOR_1322, record, cfg.clean_name_bytes)
        again = build_repaired_sector(
            once, parse_identity_record(once, cfg.good_model, cfg), cfg.clean_name_bytes
        )
        assert once == again


class TestSectorFromBackupName:
    def test_reads_the_address_backup_sector_wrote(self):
        # Restoring to a wrong address would corrupt an unrelated sector, so the
        # target comes from the file being restored, not from current config.
        assert sector_from_backup_name(
            "pre_write_identity_sector_0x0007b000_20260804_134513.bin"
        ) == 0x0007B000

    def test_returns_none_for_an_unrecognised_filename(self):
        assert sector_from_backup_name("some_random_dump.bin") is None
