import asyncio
import struct

import pytest

from moyu_v10_rescue.config import ToolConfig
from moyu_v10_rescue.ota import (
    FreqchipOTA,
    OTA_NOTIFY,
    OTA_RX_WRITE,
    OTA_TX_READ,
    ota_packet,
    parse_ota_response,
)


def run(coro):
    return asyncio.run(coro)


def ota_response(result: int, opcode: int, payload: bytes = b"") -> bytes:
    return bytes([result, opcode]) + struct.pack("<H", len(payload)) + payload


class FakeClient:
    def __init__(self, response_func=None, reads=None):
        self.response_func = response_func
        self.reads = reads or {}
        self.notify_handler = None
        self.writes = []
        self.notify_started = []
        self.notify_stopped = []

    async def start_notify(self, uuid, handler):
        self.notify_started.append(uuid)
        self.notify_handler = handler

    async def stop_notify(self, uuid):
        self.notify_stopped.append(uuid)

    async def write_gatt_char(self, uuid, data, response=False):
        data = bytes(data)
        self.writes.append((uuid, data, response))
        if self.response_func is not None:
            raw = self.response_func(data)
            if raw is not None and self.notify_handler is not None:
                self.notify_handler(uuid, raw)

    async def read_gatt_char(self, uuid):
        return self.reads.get(uuid, b"")


def test_ota_packet_uses_little_endian_payload_length():
    assert ota_packet(0x01) == bytes.fromhex("01 00 00")
    assert ota_packet(0x03, struct.pack("<I", 0x0007B000)) == bytes.fromhex("03 04 00 00 b0 07 00")
    assert ota_packet(0x09, b"") == bytes.fromhex("09 00 00")


def test_parse_ota_response_real_probe_logs():
    assert parse_ota_response(bytes.fromhex("00 00 01 00 11")) == (0, 0x00, 1, bytes.fromhex("11"))

    result, opcode, length, payload = parse_ota_response(bytes.fromhex("00 01 04 00 00 c0 02 00"))
    assert (result, opcode, length) == (0, 0x01, 4)
    assert struct.unpack("<I", payload)[0] == 0x0002C000

    result, opcode, length, payload = parse_ota_response(bytes.fromhex("00 03 04 00 00 b0 07 00"))
    assert (result, opcode, length) == (0, 0x03, 4)
    assert struct.unpack("<I", payload)[0] == 0x0007B000


def test_parse_ota_response_rejects_too_short_data():
    with pytest.raises(ValueError, match="too short"):
        parse_ota_response(b"\x00\x01\x02")


def test_cmd_writes_packet_and_returns_payload():
    def responder(pkt):
        assert pkt == bytes.fromhex("00 00 00")
        return ota_response(0, 0x00, b"\x11")

    async def scenario():
        client = FakeClient(responder)
        ota = FreqchipOTA(client, ToolConfig(color=False))
        await ota.start()
        raw, payload = await ota.cmd(0x00)
        assert raw == bytes.fromhex("00 00 01 00 11")
        assert payload == b"\x11"
        assert client.writes == [(OTA_RX_WRITE, bytes.fromhex("00 00 00"), False)]
        await ota.stop()
        assert client.notify_started == [OTA_NOTIFY]
        assert client.notify_stopped == [OTA_NOTIFY]

    run(scenario())


def test_cmd_raises_on_nonzero_result():
    async def scenario():
        client = FakeClient(lambda pkt: ota_response(5, pkt[0], b""))
        ota = FreqchipOTA(client, ToolConfig(color=False))
        await ota.start()
        with pytest.raises(RuntimeError, match="failed: result=5"):
            await ota.cmd(0x06)

    run(scenario())


def test_cmd_timeout_when_no_notification_arrives():
    async def scenario():
        client = FakeClient(lambda pkt: None)
        ota = FreqchipOTA(client, ToolConfig(color=False))
        await ota.start()
        with pytest.raises(TimeoutError, match="No OTA notification"):
            await ota.cmd(0x05, timeout=0.01)

    run(scenario())


def test_read_data_once_inline_payload_path():
    def responder(pkt):
        assert pkt == bytes.fromhex("06 06 00 00 b0 07 00 04 00")
        opcode = pkt[0]
        addr, length = struct.unpack("<IH", pkt[3:9])
        payload = struct.pack("<IH", addr, length) + bytes.fromhex("aa bb cc dd")
        return ota_response(0, opcode, payload)

    async def scenario():
        client = FakeClient(responder)
        ota = FreqchipOTA(client, ToolConfig(color=False))
        await ota.start()
        assert await ota.read_data_once(0x0007B000, 4) == bytes.fromhex("aa bb cc dd")

    run(scenario())


def test_read_data_once_ff00_fallback_path():
    def responder(pkt):
        opcode = pkt[0]
        addr, length = struct.unpack("<IH", pkt[3:9])
        # Echo addr/len only; this forces FreqchipOTA.read_data_once to read FF00.
        return ota_response(0, opcode, struct.pack("<IH", addr, length))

    async def scenario():
        client = FakeClient(responder, reads={OTA_TX_READ: b"hello"})
        ota = FreqchipOTA(client, ToolConfig(color=False))
        await ota.start()
        assert await ota.read_data_once(0x1234, 5) == b"hello"

    run(scenario())


def test_read_flash_uses_multiple_chunks():
    def responder(pkt):
        opcode = pkt[0]
        addr, length = struct.unpack("<IH", pkt[3:9])
        data = bytes(((addr + i) & 0xFF) for i in range(length))
        return ota_response(0, opcode, struct.pack("<IH", addr, length) + data)

    async def scenario():
        client = FakeClient(responder)
        ota = FreqchipOTA(client, ToolConfig(color=False, read_chunk=4))
        await ota.start()
        assert await ota.read_flash(0x10, 10) == bytes(range(0x10, 0x1A))
        assert len(client.writes) == 3

    run(scenario())


def test_page_erase_requires_4k_alignment():
    async def scenario():
        client = FakeClient(lambda pkt: ota_response(0, pkt[0], struct.pack("<I", 0x0007B000)))
        ota = FreqchipOTA(client, ToolConfig(color=False))
        await ota.start()
        with pytest.raises(ValueError, match="4 KB aligned"):
            await ota.page_erase(0x0007B006)

    run(scenario())


def test_reboot_is_tolerant_of_missing_notification():
    async def scenario():
        client = FakeClient(lambda pkt: None)
        ota = FreqchipOTA(client, ToolConfig(color=False))
        await ota.start()
        await ota.reboot()
        assert client.writes[-1][0] == OTA_RX_WRITE
        assert client.writes[-1][1] == bytes.fromhex("09 00 00")

    run(scenario())
