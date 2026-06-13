import asyncio
from pathlib import Path

from moyu_v10_rescue.config import ToolConfig
from moyu_v10_rescue.identity import (
    Finding,
    IdentityScanResult,
    SECTOR_SIZE,
    backup_sector,
    choose_repair_sector,
    infer_user_start,
    scan_for_patterns,
    scan_range_from_storage,
    summarize_sector,
)


def run(coro):
    return asyncio.run(coro)


class FakeOTA:
    def __init__(self, flash: bytes, base: int = 0):
        self.flash = flash
        self.base = base
        self.reads = []

    async def read_flash(self, addr: int, length: int, chunk=None) -> bytes:
        self.reads.append((addr, length, chunk))
        rel = addr - self.base
        if rel < 0:
            raise ValueError("address before fake flash base")
        return self.flash[rel:rel + length]


def test_infer_user_start_from_storage_base():
    cfg = ToolConfig(flash_max=0x100000)
    assert infer_user_start(0x2C000, cfg) == 0x58000
    assert infer_user_start(None, cfg) is None
    assert infer_user_start(0, cfg) is None


def test_scan_range_matches_recovery_logs():
    cfg = ToolConfig(flash_max=0x100000, user_region_margin_before=0x8000, user_region_scan_after=0x30000)
    assert scan_range_from_storage(0x2C000, cfg) == (0x50000, 0x88000, 0x58000)


def test_scan_for_patterns_finds_data_across_chunk_boundary():
    cfg = ToolConfig(read_chunk=4, color=False)
    flash = b"xxAB" + b"CDEF" + b"yy_SUFFIX_8DD8zz"
    ota = FakeOTA(flash, base=0x1000)

    findings = run(scan_for_patterns(
        ota,
        {"split_pattern": b"ABCDEF", "suffix": b"_8DD8"},
        0x1000,
        0x1000 + len(flash),
        cfg,
        print_context=False,
    ))

    by_label = {(f.label, f.address) for f in findings}
    assert ("split_pattern", 0x1002) in by_label
    assert ("suffix", 0x1000 + flash.index(b"_8DD8")) in by_label


def test_choose_repair_sector_prefers_a1_model_in_user_region():
    cfg = ToolConfig(default_identity_sector=0x7B000)
    corrupt = bytes.fromhex("22 f9 81 60 bb e0 96 53")
    scan = IdentityScanResult(
        storage_base=0x2C000,
        user_start=0x58000,
        scan_start=0x50000,
        scan_end=0x88000,
        findings=[
            Finding("good_model", 0x513A5, b"WCU_MY32"),
            Finding("a1_model_bytes", 0x7B006, corrupt),
            Finding("name_suffix", 0x7B00E, b"_8DD8"),
        ],
    )
    assert choose_repair_sector(scan, corrupt, cfg) == 0x7B000


def test_choose_repair_sector_refuses_a1_match_before_user_region():
    cfg = ToolConfig(default_identity_sector=0x7B000)
    corrupt = b"BADMODEL"
    scan = IdentityScanResult(
        storage_base=0x2C000,
        user_start=0x58000,
        scan_start=0x50000,
        scan_end=0x88000,
        findings=[Finding("a1_model_bytes", 0x513A5, corrupt)],
    )
    assert choose_repair_sector(scan, corrupt, cfg) is None


def test_summarize_sector_reports_blank_and_patterns(capsys):
    cfg = ToolConfig(target_name_suffix="8DD8", color=False)
    sector = bytearray([0xFF] * SECTOR_SIZE)
    sector[0x006:0x00E] = b"WCU_MY32"
    sector[0x00E:0x013] = b"_8DD8"

    summarize_sector(bytes(sector), 0x7B000, cfg, a1_model=b"WCU_MY32")
    out = capsys.readouterr().out
    assert "all blank/erased: False" in out
    assert "good_model" in out and "flash 0x0007b006" in out
    assert "clean_name" in out and "flash 0x0007b006" in out


def test_backup_sector_writes_4k_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = b"\xFF" * SECTOR_SIZE
    ota = FakeOTA(data, base=0x7B000)
    cfg = ToolConfig(color=False)

    path = run(backup_sector(ota, 0x7B000, cfg, label="unit"))
    assert path.parent == Path("backups")
    assert path.name.startswith("unit_sector_0x0007b000_")
    assert (tmp_path / path).read_bytes() == data
