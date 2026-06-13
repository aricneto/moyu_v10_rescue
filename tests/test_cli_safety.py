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


def test_action_apply_refuses_if_chosen_sector_no_longer_contains_a1_model(monkeypatch):
    cfg = ToolConfig(color=False)
    dirty_model = b"BADMODEL"
    sector = bytearray([0xFF] * SECTOR_SIZE)
    sector[0x006:0x00E] = b"OTHERBAD"
    ota = FakeOTA(bytes(sector))
    install_common_apply_mocks(monkeypatch, dirty_model, ota, sector_choice=0x7B000, prompt=True)

    run(cli.action_apply(cfg))

    assert not ota.erased
