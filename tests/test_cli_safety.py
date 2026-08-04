import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("bleak")
pytest.importorskip("Crypto.Cipher.AES")

from moyu_v10_rescue import cli
from moyu_v10_rescue.config import ToolConfig
from moyu_v10_rescue.cube_protocol import A1Info
from moyu_v10_rescue.identity import Finding, IdentityScanResult, SECTOR_SIZE


def run(coro):
    return asyncio.run(coro)


class FakeClient:
    def __init__(self):
        self.disconnected = False

    async def disconnect(self):
        self.disconnected = True


class FakeOTA:
    def __init__(self, sector: bytes):
        self.sector = sector
        self.erased = False
        self.stopped = False
        self.reads = []

    async def stop(self):
        self.stopped = True

    async def read_flash(self, addr, length):
        self.reads.append((addr, length))
        if self.erased:
            return b"\xFF" * length
        return self.sector[:length]

    async def page_erase(self, sector):
        self.erased = True
        self.erased_sector = sector


def fake_scan(user_start=0x58000, finding_addr=0x7B006, model=b"BADMODEL"):
    return IdentityScanResult(
        storage_base=0x2C000,
        user_start=user_start,
        scan_start=0x50000,
        scan_end=0x88000,
        findings=[Finding("a1_model_bytes", finding_addr, model)],
    )


def install_common_apply_mocks(monkeypatch, a1_model, ota, scan=None, sector_choice=0x7B000, prompt=True):
    fd = SimpleNamespace(adv=SimpleNamespace(manufacturer_data={}))
    client = FakeClient()

    async def connect_target(cfg):
        return fd, client

    async def get_a1_and_ota(cfg, client_arg, adv):
        assert client_arg is client
        return A1Info(raw=b"", decrypted=b"", model_bytes=a1_model), ota

    async def identity_scan(cfg_ota, cfg, model):
        return scan or fake_scan(model=model)

    async def backup_sector(ota_arg, sector, cfg, label="identity"):
        return Path("backups/pre_erase_identity.bin")

    monkeypatch.setattr(cli, "connect_target", connect_target)
    monkeypatch.setattr(cli, "_get_a1_and_ota", get_a1_and_ota)
    monkeypatch.setattr(cli, "identity_scan", identity_scan)
    monkeypatch.setattr(cli, "backup_sector", backup_sector)
    monkeypatch.setattr(cli, "choose_repair_sector", lambda scan, model, cfg: sector_choice)
    monkeypatch.setattr(cli, "prompt_exact", lambda prompt_text, expected: prompt)

    return client


def test_action_apply_does_nothing_when_a1_is_already_clean(monkeypatch):
    cfg = ToolConfig(color=False)
    ota = FakeOTA(b"not used")
    client = install_common_apply_mocks(monkeypatch, cfg.good_model, ota)

    run(cli.action_apply(cfg))

    assert not ota.erased
    assert ota.stopped
    assert client.disconnected


def test_action_apply_refuses_when_sector_choice_is_unknown_and_default_is_not_blank(monkeypatch):
    cfg = ToolConfig(color=False)
    dirty_model = b"BADMODEL"
    sector = bytearray([0x00] * SECTOR_SIZE)
    ota = FakeOTA(bytes(sector))
    client = install_common_apply_mocks(monkeypatch, dirty_model, ota, sector_choice=None)

    run(cli.action_apply(cfg))

    assert not ota.erased
    assert ota.reads[-1] == (cfg.default_identity_sector, SECTOR_SIZE)
    assert client.disconnected


def test_action_apply_when_default_sector_already_blank_says_to_reboot_without_erasing(monkeypatch):
    cfg = ToolConfig(color=False)
    dirty_model = b"BADMODEL"
    ota = FakeOTA(b"\xFF" * SECTOR_SIZE)
    install_common_apply_mocks(monkeypatch, dirty_model, ota, sector_choice=None)

    run(cli.action_apply(cfg))

    assert not ota.erased


def test_action_apply_aborts_if_confirmation_phrase_is_wrong(monkeypatch):
    cfg = ToolConfig(color=False)
    dirty_model = bytes.fromhex("22 f9 81 60 bb e0 96 53")
    sector = bytearray([0xFF] * SECTOR_SIZE)
    sector[0x006:0x00E] = dirty_model
    ota = FakeOTA(bytes(sector))
    install_common_apply_mocks(monkeypatch, dirty_model, ota, sector_choice=0x7B000, prompt=False)

    run(cli.action_apply(cfg))

    assert not ota.erased


def test_action_apply_erases_only_when_dirty_model_is_present_and_confirmed(monkeypatch):
    cfg = ToolConfig(color=False)
    dirty_model = bytes.fromhex("22 f9 81 60 bb e0 96 53")
    sector = bytearray([0xFF] * SECTOR_SIZE)
    sector[0x006:0x00E] = dirty_model
    ota = FakeOTA(bytes(sector))
    install_common_apply_mocks(monkeypatch, dirty_model, ota, sector_choice=0x7B000, prompt=True)

    run(cli.action_apply(cfg))

    assert ota.erased
    assert ota.erased_sector == 0x7B000
    assert ota.stopped


class RWFakeOTA:
    """Stateful sector fake: erase blanks it, writes land in it, reads see both."""

    def __init__(self, sector_bytes: bytes, base: int = 0x7B000, write_ok: bool = True):
        self.mem = bytearray(sector_bytes)
        self.base = base
        self.write_ok = write_ok
        self.erased = False
        self.stopped = False
        self.writes = []

    async def stop(self):
        self.stopped = True

    async def read_flash(self, addr, length):
        off = addr - self.base
        return bytes(self.mem[off:off + length])

    async def page_erase(self, sector):
        self.erased = True
        self.erased_sector = sector
        self.mem = bytearray(b"\xFF" * len(self.mem))

    async def write_flash(self, addr, data, chunk=None):
        if not self.write_ok:
            raise TimeoutError("No OTA notification for opcode 0x05")
        self.writes.append((addr, bytes(data)))
        off = addr - self.base
        self.mem[off:off + len(data)] = data

    async def write_data(self, addr, data, timeout=6.0):
        await self.write_flash(addr, data)
        return b""


# Real bytes from cube CF:30:16:02:13:22 — model corrupted to 5 bytes, AD length 0x0b.
CORRUPT_1322_HEAD = bytes.fromhex(
    "25 12 23 cb 0b 09 e5 a7 01 8b 01 5f 31 33 32 32"
    "0c ff 00 00 00 00 30 22 13 02 16 30 cf"
)
A1_1322 = bytes.fromhex("e5 a7 01 8b 01 00 00 00")


def sector_1322() -> bytes:
    return CORRUPT_1322_HEAD + b"\xFF" * (SECTOR_SIZE - len(CORRUPT_1322_HEAD))


def test_action_repair_write_rewrites_the_record_and_verifies(monkeypatch):
    cfg = ToolConfig(color=False, target_name_suffix="1322")
    ota = RWFakeOTA(sector_1322())
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=0x7B000, prompt=True)

    run(cli.action_repair_write(cfg))

    assert ota.erased and ota.erased_sector == 0x7B000
    assert b"WCU_MY32_1322" in bytes(ota.mem)
    assert ota.mem[0x004] == 0x0E  # AD length corrected for the longer name
    # The manufacturer record carries the MAC the AES salt comes from; losing it
    # would be worse than the corruption being repaired.
    assert bytes.fromhex("0c ff 00 00 00 00 30 22 13 02 16 30 cf") in bytes(ota.mem)


def test_action_repair_write_refuses_when_the_record_structure_is_unknown(monkeypatch):
    # Model bytes present, but not behind an AD complete-local-name header.
    cfg = ToolConfig(color=False, target_name_suffix="1322")
    stray = bytearray(b"\xFF" * SECTOR_SIZE)
    stray[0x100:0x105] = bytes.fromhex("e5 a7 01 8b 01")
    ota = RWFakeOTA(bytes(stray))
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=0x7B000, prompt=True)

    run(cli.action_repair_write(cfg))

    assert not ota.erased
    assert ota.writes == []


def test_action_repair_write_refuses_when_the_sector_cannot_be_located(monkeypatch):
    cfg = ToolConfig(color=False, target_name_suffix="1322")
    ota = RWFakeOTA(sector_1322())
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=None, prompt=True)

    run(cli.action_repair_write(cfg))

    assert not ota.erased


def test_action_repair_write_aborts_on_a_wrong_confirmation_phrase(monkeypatch):
    cfg = ToolConfig(color=False, target_name_suffix="1322")
    ota = RWFakeOTA(sector_1322())
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=0x7B000, prompt=False)

    run(cli.action_repair_write(cfg))

    assert not ota.erased
    assert ota.writes == []


def test_action_repair_write_leaves_the_sector_erased_when_the_write_fails(monkeypatch):
    # The degraded outcome must be exactly the erase-only state, which the saved
    # backup can be restored over — not a half-written record.
    cfg = ToolConfig(color=False, target_name_suffix="1322")
    ota = RWFakeOTA(sector_1322(), write_ok=False)
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=0x7B000, prompt=True)

    with pytest.raises(TimeoutError):
        run(cli.action_repair_write(cfg))

    assert ota.erased
    assert all(b == 0xFF for b in ota.mem)


def test_action_write_test_refuses_when_the_probe_area_is_not_blank(monkeypatch):
    cfg = ToolConfig(color=False, target_name_suffix="1322")
    dirty = bytearray(b"\xFF" * SECTOR_SIZE)
    dirty[-16:] = bytes(range(16))
    ota = RWFakeOTA(bytes(dirty))
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=0x7B000, prompt=True)

    run(cli.action_write_test(cfg))

    assert ota.writes == []


def test_action_apply_refuses_if_chosen_sector_no_longer_contains_a1_model(monkeypatch):
    cfg = ToolConfig(color=False)
    dirty_model = b"BADMODEL"
    sector = bytearray([0xFF] * SECTOR_SIZE)
    sector[0x006:0x00E] = b"OTHERBAD"
    ota = FakeOTA(bytes(sector))
    install_common_apply_mocks(monkeypatch, dirty_model, ota, sector_choice=0x7B000, prompt=True)

    run(cli.action_apply(cfg))

    assert not ota.erased
