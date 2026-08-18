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

from .cube_fixtures import A1_MODEL_1322 as A1_1322, MFG_RECORD_1322, SECTOR_1322


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


def sector_1322() -> bytes:
    return SECTOR_1322


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
    assert bytes(ota.mem[0x013:0x020]) == MFG_RECORD_1322
    # ...and the unidentified structure after the advertising area does not move.
    assert bytes(ota.mem[0x020:0x02E]) == SECTOR_1322[0x020:0x02E]


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
    # backup can be restored over - not a half-written record.
    cfg = ToolConfig(color=False, target_name_suffix="1322")
    ota = RWFakeOTA(sector_1322(), write_ok=False)
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=0x7B000, prompt=True)

    with pytest.raises(TimeoutError):
        run(cli.action_repair_write(cfg))

    assert ota.erased
    assert all(b == 0xFF for b in ota.mem)


class NoOpWriteOTA(RWFakeOTA):
    """Accepts WRITE_DATA and changes nothing - the silent-failure case."""

    async def write_data(self, addr, data, timeout=6.0):
        self.writes.append((addr, bytes(data)))
        return b""


class TruncatingOTA(RWFakeOTA):
    """Drops everything past `limit` bytes of a WRITE_DATA payload, as a too-small MTU would."""

    def __init__(self, sector_bytes, limit, **kwargs):
        super().__init__(sector_bytes, **kwargs)
        self.limit = limit

    async def write_data(self, addr, data, timeout=6.0):
        await self.write_flash(addr, data[:self.limit])
        return b""


def probe_offsets(cfg: ToolConfig) -> tuple[int, int]:
    """Sector-relative offsets of the small and full-size write probes."""
    chunk = SECTOR_SIZE - cfg.write_chunk
    return chunk - 8, chunk


def test_action_write_test_refuses_when_the_probe_area_is_not_blank(monkeypatch):
    cfg = ToolConfig(color=False, target_name_suffix="1322")
    small_off, _ = probe_offsets(cfg)
    dirty = bytearray(b"\xFF" * SECTOR_SIZE)
    dirty[small_off:small_off + 16] = bytes(range(16))
    ota = RWFakeOTA(bytes(dirty))
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=0x7B000, prompt=True)

    run(cli.action_write_test(cfg))

    assert ota.writes == []


def test_action_write_test_probes_both_a_small_and_a_full_chunk_write(monkeypatch):
    # A 4-byte write proves the opcode; only a write_chunk-sized one proves the
    # size the repair actually uses after it has erased the sector.
    cfg = ToolConfig(color=False, target_name_suffix="1322", assume_yes=True)
    small_off, chunk_off = probe_offsets(cfg)
    ota = RWFakeOTA(b"\xFF" * SECTOR_SIZE)
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=0x7B000, prompt=True)

    run(cli.action_write_test(cfg))

    assert [(addr - 0x7B000, len(data)) for addr, data in ota.writes] == [
        (small_off, 4),
        (chunk_off, cfg.write_chunk),
    ]
    assert bytes(ota.mem[small_off:small_off + 4]) == bytes.fromhex("a5 5a a5 5a")
    assert not ota.erased


def test_action_write_test_stops_when_the_small_probe_does_not_read_back(monkeypatch):
    cfg = ToolConfig(color=False, target_name_suffix="1322", assume_yes=True)
    ota = NoOpWriteOTA(b"\xFF" * SECTOR_SIZE)
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=0x7B000, prompt=True)

    run(cli.action_write_test(cfg))

    assert len(ota.writes) == 1


def test_action_write_test_catches_a_full_size_write_that_is_truncated(monkeypatch):
    # The small probe passes and the big one is silently cut short - the exact
    # failure that would otherwise surface after the repair had erased the sector.
    cfg = ToolConfig(color=False, target_name_suffix="1322", assume_yes=True)
    _, chunk_off = probe_offsets(cfg)
    ota = TruncatingOTA(b"\xFF" * SECTOR_SIZE, limit=20)
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=0x7B000, prompt=True)

    run(cli.action_write_test(cfg))

    assert len(ota.writes) == 2
    assert bytes(ota.mem[chunk_off + 20:chunk_off + cfg.write_chunk]) == b"\xFF" * (cfg.write_chunk - 20)


def test_write_test_probes_leave_the_repair_able_to_run(monkeypatch):
    # The probes land in blank padding far past the record, so running option 9
    # first cannot block option 10.
    cfg = ToolConfig(color=False, target_name_suffix="1322", assume_yes=True)
    ota = RWFakeOTA(sector_1322())
    install_common_apply_mocks(monkeypatch, A1_1322, ota, sector_choice=0x7B000, prompt=True)

    run(cli.action_write_test(cfg))
    run(cli.action_repair_write(cfg))

    assert ota.erased
    assert b"WCU_MY32_1322" in bytes(ota.mem)
    assert ota.mem[0x004] == 0x0E


async def _fake_connect_target(cfg):
    return SimpleNamespace(adv=SimpleNamespace(manufacturer_data={})), FakeClient()


def _with_start(ota):
    async def start():
        return None

    ota.start = start
    return ota


def test_action_restore_does_not_write_when_the_erase_did_not_take(monkeypatch, tmp_path):
    class DeadEraseOTA(RWFakeOTA):
        async def page_erase(self, sector):
            self.erased = True  # reports success, sector unchanged

    cfg = ToolConfig(color=False, target_name_suffix="1322")
    backup = tmp_path / "identity_sector_0x0007b000_20260101_120000.bin"
    backup.write_bytes(sector_1322())
    ota = DeadEraseOTA(bytearray(b"\x00" * SECTOR_SIZE))

    monkeypatch.setattr("builtins.input", lambda *_: str(backup))
    monkeypatch.setattr(cli, "connect_target", _fake_connect_target)
    monkeypatch.setattr(cli, "FreqchipOTA", lambda client, cfg: _with_start(ota))
    monkeypatch.setattr(cli, "prompt_exact", lambda prompt_text, expected: True)

    run(cli.action_restore(cfg))

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
