"""Locating and rebuilding the advertising identity record.

Sector bytes for both cubes live in tests/cube_fixtures.py.
"""

import pytest

from moyu_v10_rescue.config import ToolConfig
from moyu_v10_rescue.identity import (
    SECTOR_SIZE,
    build_repaired_sector,
    flash_model_pattern,
    parse_identity_record,
    sector_from_backup_name,
)

from .cube_fixtures import (
    A1_MODEL_1322,
    A1_MODEL_8DD8,
    MFG_RECORD_1322,
    SECTOR_1322,
    SECTOR_8DD8,
)


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
        # The repaired name is 3 bytes longer, so the manufacturer block moves up
        # to keep the AD chain contiguous. It carries the MAC that seeds the AES
        # salt, so losing or truncating it would be worse than the corruption.
        cfg = cfg_1322()
        record = parse_identity_record(SECTOR_1322, A1_MODEL_1322, cfg)
        repaired = build_repaired_sector(SECTOR_1322, record, cfg.clean_name_bytes)

        assert repaired[0x013:0x013 + len(MFG_RECORD_1322)] == MFG_RECORD_1322
        # ...landing exactly where the 8DD8 cube, whose record was never shortened,
        # has its own.
        assert SECTOR_8DD8[0x013:0x015] == MFG_RECORD_1322[:2]

    def test_keeps_the_trailing_structure_at_its_absolute_offset(self):
        # Both cubes carry an unidentified structure at sector+0x020, and on the
        # 1322 cube the 3 bytes in front of it are zero padding created when the
        # name record was shortened. Nothing after that padding may move: the AD
        # chain terminates before it, so firmware cannot be reaching it by walking
        # records — it must be using the offset.
        cfg = cfg_1322()
        record = parse_identity_record(SECTOR_1322, A1_MODEL_1322, cfg)
        repaired = build_repaired_sector(SECTOR_1322, record, cfg.clean_name_bytes)

        assert SECTOR_1322[0x01D:0x020] == b"\x00\x00\x00"
        assert repaired[0x020:0x02E] == SECTOR_1322[0x020:0x02E]
        assert repaired[0x020] == 0x19

    def test_absorbs_the_growth_from_the_padding_not_the_end_of_the_sector(self):
        cfg = cfg_1322()
        record = parse_identity_record(SECTOR_1322, A1_MODEL_1322, cfg)
        repaired = build_repaired_sector(SECTOR_1322, record, cfg.clean_name_bytes)

        # The AD chain now runs right up to the structure, with no padding left.
        assert repaired[0x01F] != 0x00
        assert repaired[0x2E:] == SECTOR_1322[0x2E:]

    def test_refuses_when_the_padding_cannot_absorb_the_growth(self):
        cfg = cfg_1322()
        cramped = bytearray(SECTOR_1322)
        cramped[0x01E] = 0x77  # one padding byte short of the 3 the repair needs
        record = parse_identity_record(bytes(cramped), A1_MODEL_1322, cfg)

        with pytest.raises(ValueError, match="only 1 padding byte"):
            build_repaired_sector(bytes(cramped), record, cfg.clean_name_bytes)

    def test_refuses_when_the_advertising_chain_has_no_terminator(self):
        cfg = cfg_1322()
        endless = bytearray(SECTOR_1322)
        endless[0x010] = 0x20  # manufacturer record overruns its terminator
        record = parse_identity_record(bytes(endless), A1_MODEL_1322, cfg)

        with pytest.raises(ValueError, match="terminator"):
            build_repaired_sector(bytes(endless), record, cfg.clean_name_bytes)

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
