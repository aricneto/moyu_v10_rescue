from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .config import ToolConfig
from .crypto import CubeCrypto, salt_candidates
from .util import hex_bytes, ok, warn

SERVICE = "0783b03e-7735-b5a0-1760-a305d2795cb0"
NOTIFY = "0783b03e-7735-b5a0-1760-a305d2795cb1"
WRITE = "0783b03e-7735-b5a0-1760-a305d2795cb2"

KNOWN_TYPES = {
    0xA1: "cube info",
    0xA3: "facelet state",
    0xA4: "battery",
    0xA5: "move",
    0xAB: "gyro",
    0xAC: "gyro config",
}

MOVE_NAMES_GUESS = {
    0: "F", 1: "F'",
    2: "B", 3: "B'",
    4: "U", 5: "U'",
    6: "D", 7: "D'",
    8: "L", 9: "L'",
    10: "R", 11: "R'",
}


def packet(msg_type: int, payload: bytes = b"") -> bytes:
    if len(payload) > 19:
        raise ValueError("payload too long")
    return bytes([msg_type]) + payload + bytes(19 - len(payload))


def bit_groups_msb(data: bytes, width: int, count: int) -> list[int]:
    bits = []
    for b in data:
        for shift in range(7, -1, -1):
            bits.append((b >> shift) & 1)

    vals = []
    for i in range(count):
        v = 0
        for bit in bits[i * width:(i + 1) * width]:
            v = (v << 1) | bit
        vals.append(v)
    return vals


@dataclass
class A1Info:
    raw: bytes
    decrypted: bytes
    model_bytes: bytes

    @property
    def model_text(self) -> str:
        return self.model_bytes.decode("ascii", errors="replace")


@dataclass
class MoveInfo:
    serial: int
    move_codes: list[int]
    guessed_moves: list[str]
    times_be: list[int]
    times_le: list[int]


def parse_a5_move(pkt: bytes) -> MoveInfo:
    times_be = [int.from_bytes(pkt[1 + 2 * i:3 + 2 * i], "big") for i in range(5)]
    times_le = [int.from_bytes(pkt[1 + 2 * i:3 + 2 * i], "little") for i in range(5)]
    serial = pkt[11]
    move_codes = bit_groups_msb(pkt[12:17], 5, 5)
    guessed_moves = [MOVE_NAMES_GUESS.get(code, f"?{code}") for code in move_codes]
    return MoveInfo(serial, move_codes, guessed_moves, times_be, times_le)


def parse_a3_facelets(pkt: bytes):
    vals = bit_groups_msb(pkt[1:19], 3, 48)
    face_names = ["F", "B", "U", "D", "L", "R"]
    color_guess = ["G", "B", "W", "Y", "O", "R"]
    grouped = {}
    for i, face in enumerate(face_names):
        raw_vals = vals[i * 8:(i + 1) * 8]
        guessed = "".join(color_guess[v] if 0 <= v < len(color_guess) else f"?{v}" for v in raw_vals)
        grouped[face] = (raw_vals, guessed)
    return grouped, pkt[19]


class V10Protocol:
    def __init__(self, client, adv, cfg: ToolConfig):
        self.client = client
        self.adv = adv
        self.cfg = cfg
        self.q: asyncio.Queue[bytes] = asyncio.Queue()
        self.crypto: CubeCrypto | None = None

    def _on_notify(self, sender, data):
        self.q.put_nowait(bytes(data))

    async def start(self):
        await self.client.start_notify(NOTIFY, self._on_notify)

    async def stop(self):
        try:
            await self.client.stop_notify(NOTIFY)
        except Exception:
            pass

    def clear(self):
        while not self.q.empty():
            try:
                self.q.get_nowait()
            except asyncio.QueueEmpty:
                break

    async def write_packet(self, msg_type: int, payload: bytes = b""):
        if self.crypto is None:
            raise RuntimeError("crypto is not initialized; call init_crypto() first")
        plain = packet(msg_type, payload)
        enc = self.crypto.encrypt(plain)
        try:
            await self.client.write_gatt_char(WRITE, enc, response=False)
        except Exception:
            await self.client.write_gatt_char(WRITE, enc, response=True)

    async def wait_for(self, wanted_types: set[int] | None = None, timeout: float = 2.0, skip_gyro: bool = True):
        if self.crypto is None:
            raise RuntimeError("crypto is not initialized")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout

        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None, None
            try:
                raw = await asyncio.wait_for(self.q.get(), timeout=remaining)
            except asyncio.TimeoutError:
                return None, None

            dec = self.crypto.decrypt(raw)
            typ = dec[0]
            if wanted_types is None or typ in wanted_types:
                return raw, dec
            if skip_gyro and typ == 0xAB:
                continue

    async def init_crypto(self) -> A1Info:
        candidates = salt_candidates(self.cfg.manual_mac, self.adv)
        if not candidates:
            raise RuntimeError("No salt candidates. Set --mac to the cube's real MAC address.")

        for crypto in candidates:
            self.crypto = crypto
            self.clear()
            print(f"Trying crypto: {crypto.label}")
            print(f"  salt: {crypto.salt.hex(':')}")

            plain = packet(0xA1)
            enc = crypto.encrypt(plain)
            try:
                await self.client.write_gatt_char(WRITE, enc, response=False)
            except Exception:
                await self.client.write_gatt_char(WRITE, enc, response=True)

            raw, dec = await self.wait_for({0xA1}, timeout=2.0, skip_gyro=True)
            if dec is None:
                print("  no valid A1 response")
                continue

            info = A1Info(raw=raw, decrypted=dec, model_bytes=dec[1:9])
            ok("A1 response decrypted successfully.", self.cfg.color)
            print(f"  raw:       {hex_bytes(raw)}")
            print(f"  decrypted: {hex_bytes(dec)}")
            print(f"  model:     {info.model_bytes.hex(' ')} / {info.model_text!r}")
            return info

        self.crypto = None
        raise RuntimeError("No candidate salt produced a valid A1 response.")

    async def battery(self) -> int | None:
        self.clear()
        await self.write_packet(0xA4)
        raw, dec = await self.wait_for({0xA4}, timeout=2.0, skip_gyro=True)
        if dec is None:
            warn("No A4 battery response.", self.cfg.color)
            return None
        print(f"A4 battery raw: {hex_bytes(dec)}")
        print(f"Battery: {dec[1]}%")
        return dec[1]

    async def gyro_config(self, enabled: bool) -> bytes | None:
        self.clear()
        payload = b"\x00\x01" if enabled else b"\x00\x00"
        await self.write_packet(0xAC, payload)
        raw, dec = await self.wait_for({0xAC}, timeout=1.5, skip_gyro=True)
        if dec is None:
            warn("No AC gyro-config response.", self.cfg.color)
            return None
        print(f"AC response: {hex_bytes(dec)}")
        return dec

    async def facelets(self) -> bytes | None:
        self.clear()
        await self.write_packet(0xA3)
        raw, dec = await self.wait_for({0xA3}, timeout=2.0, skip_gyro=True)
        if dec is None:
            warn("No A3 facelet-state response.", self.cfg.color)
            return None

        print(f"A3 facelets raw: {hex_bytes(dec)}")
        faces, serial = parse_a3_facelets(dec)
        print(f"A3 serial: {serial}")
        for face, (raw_vals, guessed) in faces.items():
            print(f"  {face}: raw={raw_vals} guess={guessed}")
        return dec

    async def watch_moves(self, seconds: float, print_gyro: bool = False):
        self.clear()
        loop = asyncio.get_running_loop()
        end = loop.time() + seconds
        print(f"Watching for {seconds:.1f}s. Turn actual cube layers now.")
        saw_move = False

        while loop.time() < end:
            try:
                raw = await asyncio.wait_for(self.q.get(), timeout=min(0.8, end - loop.time()))
            except asyncio.TimeoutError:
                continue
            if self.crypto is None:
                break
            dec = self.crypto.decrypt(raw)
            typ = dec[0]
            if typ == 0xAB and not print_gyro:
                continue
            print()
            print(f"EVENT type={hex(typ)} {KNOWN_TYPES.get(typ, 'unknown')}")
            print(f"  raw:       {hex_bytes(raw)}")
            print(f"  decrypted: {hex_bytes(dec)}")
            if typ == 0xA5:
                saw_move = True
                move = parse_a5_move(dec)
                print("  MOVE A5")
                print(f"    serial:        {move.serial}")
                print(f"    raw codes:     {move.move_codes}")
                print(f"    guessed moves: {move.guessed_moves}")
                print(f"    times BE:      {move.times_be}")
                print(f"    times LE:      {move.times_le}")
        if saw_move:
            ok("Move packets were detected.", self.cfg.color)
        else:
            warn("No A5 move packets were detected in the watch window.", self.cfg.color)
