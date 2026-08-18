from __future__ import annotations

import asyncio
import struct

from .config import ToolConfig
from .util import hex_bytes, warn

OTA_TX_READ = "02f00000-0000-0000-0000-00000000ff00"
OTA_RX_WRITE = "02f00000-0000-0000-0000-00000000ff01"
OTA_NOTIFY = "02f00000-0000-0000-0000-00000000ff02"
OTA_VERSION_INFO = "02f00000-0000-0000-0000-00000000ff03"
OTA_SERVICE = "02f00000-0000-0000-0000-00000000fe00"


def ota_packet(opcode: int, payload: bytes = b"") -> bytes:
    # Freqchip-style OTA packet: u8 opcode + u16 little-endian payload length + payload.
    return bytes([opcode]) + struct.pack("<H", len(payload)) + payload


def parse_ota_response(raw: bytes):
    if len(raw) < 4:
        raise ValueError(f"OTA response too short: {raw.hex(' ')}")
    result = raw[0]
    opcode = raw[1]
    length = struct.unpack("<H", raw[2:4])[0]
    payload = raw[4:4 + length]
    return result, opcode, length, payload


class FreqchipOTA:
    def __init__(self, client, cfg: ToolConfig):
        self.client = client
        self.cfg = cfg
        self.q: asyncio.Queue[bytes] = asyncio.Queue()

    def _on_notify(self, sender, data):
        self.q.put_nowait(bytes(data))

    async def start(self):
        await self.client.start_notify(OTA_NOTIFY, self._on_notify)

    async def stop(self):
        try:
            await self.client.stop_notify(OTA_NOTIFY)
        except Exception:
            pass

    def clear(self):
        while not self.q.empty():
            try:
                self.q.get_nowait()
            except asyncio.QueueEmpty:
                break

    async def cmd(self, opcode: int, payload: bytes = b"", timeout: float = 3.0, expect_notify: bool = True):
        pkt = ota_packet(opcode, payload)
        self.clear()

        try:
            await self.client.write_gatt_char(OTA_RX_WRITE, pkt, response=False)
        except Exception:
            await self.client.write_gatt_char(OTA_RX_WRITE, pkt, response=True)

        if not expect_notify:
            return None, b""

        try:
            raw = await asyncio.wait_for(self.q.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"No OTA notification for opcode 0x{opcode:02x}")

        result, rsp_opcode, length, rsp_payload = parse_ota_response(raw)
        if rsp_opcode != opcode:
            warn(f"OTA response opcode 0x{rsp_opcode:02x}, expected 0x{opcode:02x}.", self.cfg.color)
        if result != 0:
            raise RuntimeError(f"OTA command 0x{opcode:02x} failed: result={result}, raw={raw.hex(' ')}")
        return raw, rsp_payload

    async def direct_reads(self):
        print("Direct OTA characteristic reads:")
        for uuid in [OTA_TX_READ, OTA_NOTIFY, OTA_VERSION_INFO]:
            try:
                val = bytes(await self.client.read_gatt_char(uuid))
                print(f"  {uuid}  {hex_bytes(val)}  {val.decode('utf-8', errors='replace')!r}")
            except Exception as e:
                print(f"  {uuid} read failed: {e!r}")

    async def get_nvds_type(self) -> int | None:
        raw, payload = await self.cmd(0x00, b"", timeout=3.0)
        print(f"NVDS/type response raw: {raw.hex(' ')}")
        return payload[0] if payload else None

    async def get_storage_base(self) -> int | None:
        raw, payload = await self.cmd(0x01, b"", timeout=3.0)
        print(f"storage-base response raw: {raw.hex(' ')}")
        if len(payload) < 4:
            return None
        return struct.unpack("<I", payload[:4])[0]

    async def get_fw_version(self) -> int | None:
        raw, payload = await self.cmd(0x02, b"", timeout=3.0)
        print(f"fw-version response raw: {raw.hex(' ')}")
        if len(payload) < 4:
            return None
        return struct.unpack("<I", payload[:4])[0]

    async def read_data_once(self, addr: int, length: int) -> bytes:
        if not (0 <= length <= 0xFFFF):
            raise ValueError("length must fit u16")

        payload = struct.pack("<IH", addr, length)
        raw, rsp_payload = await self.cmd(0x06, payload, timeout=4.0)

        if len(rsp_payload) < 6:
            raise RuntimeError(f"READ_DATA response payload too short: {raw.hex(' ')}")

        echoed_addr, echoed_len = struct.unpack("<IH", rsp_payload[:6])
        inline_data = rsp_payload[6:]

        if echoed_addr != addr or echoed_len != length:
            warn(
                f"READ_DATA echoed addr/len {echoed_addr:#x}/{echoed_len}, expected {addr:#x}/{length}.",
                self.cfg.color,
            )

        if len(inline_data) >= echoed_len:
            return inline_data[:echoed_len]

        await asyncio.sleep(0.05)
        extra = bytes(await self.client.read_gatt_char(OTA_TX_READ))
        if len(extra) != echoed_len:
            raise RuntimeError(
                f"FF00 readback length {len(extra)} != expected {echoed_len}; try reducing read chunk"
            )
        return extra

    async def read_flash(self, addr: int, length: int, chunk: int | None = None) -> bytes:
        chunk = chunk or self.cfg.read_chunk
        out = bytearray()
        while len(out) < length:
            n = min(chunk, length - len(out))
            out += await self.read_data_once(addr + len(out), n)
        return bytes(out)

    async def write_data(self, addr: int, data: bytes, timeout: float = 6.0):
        """OTA WRITE_DATA (0x05). Framing mirrors READ_DATA: u32 addr, u16 len, payload.

        This opcode times out on some firmware, so it is not on any automatic
        path - callers must have proven it works on this cube first (see the
        write capability test). NOR flash only clears bits on a
        write, so the target must be erased or blank.
        """
        if not (0 < len(data) <= 0xFFFF):
            raise ValueError("data length must be 1..65535")

        payload = struct.pack("<IH", addr, len(data)) + data
        raw, rsp_payload = await self.cmd(0x05, payload, timeout=timeout)

        if len(rsp_payload) >= 6:
            echoed_addr, echoed_len = struct.unpack("<IH", rsp_payload[:6])
            if echoed_addr != addr or echoed_len != len(data):
                raise RuntimeError(
                    f"WRITE_DATA echoed addr/len {echoed_addr:#x}/{echoed_len}, "
                    f"expected {addr:#x}/{len(data)}; raw={raw.hex(' ')}"
                )
        return raw

    async def write_flash(self, addr: int, data: bytes, chunk: int | None = None):
        chunk = chunk or self.cfg.write_chunk
        written = 0
        while written < len(data):
            n = min(chunk, len(data) - written)
            await self.write_data(addr + written, data[written:written + n])
            written += n

    async def page_erase(self, sector_addr: int):
        if sector_addr % 0x1000 != 0:
            raise ValueError("sector_addr must be 4 KB aligned")
        raw, payload = await self.cmd(0x03, struct.pack("<I", sector_addr), timeout=8.0)
        print(f"PAGE_ERASE response: {raw.hex(' ')}")
        if len(payload) >= 4:
            echoed = struct.unpack("<I", payload[:4])[0]
            print(f"erased/echoed sector: 0x{echoed:08x}")

    async def reboot(self):
        # Reboot often disconnects before a notification is delivered, so this is tolerant.
        pkt = ota_packet(0x09, b"")
        self.clear()
        try:
            await self.client.write_gatt_char(OTA_RX_WRITE, pkt, response=False)
        except Exception:
            try:
                await self.client.write_gatt_char(OTA_RX_WRITE, pkt, response=True)
            except Exception as e:
                warn(f"Reboot write raised {e!r}; this can happen if the cube reset/disconnected.", self.cfg.color)
                return
        try:
            raw = await asyncio.wait_for(self.q.get(), timeout=1.5)
            print(f"REBOOT response: {raw.hex(' ')}")
        except Exception:
            print("Reboot command sent; no clean notification returned, which is normal if it reset/disconnected.")
