from __future__ import annotations

from dataclasses import dataclass
from Crypto.Cipher import AES

from .config import parse_mac

ROOT_KEY = bytes.fromhex("15773A5C670E2D1F17672A139B675257")
ROOT_IV = bytes.fromhex("11232625862A2C3B55067F317E672157")


def salted(root: bytes, salt: bytes) -> bytes:
    out = bytearray(root)
    for i in range(6):
        # This is the V10/GAN-Gen2-style salt behavior observed in the protocol.
        out[i] = (out[i] + salt[i]) % 0xFF
    return bytes(out)


@dataclass
class CubeCrypto:
    label: str
    salt: bytes
    key: bytes
    iv: bytes

    @classmethod
    def from_salt(cls, label: str, salt: bytes) -> "CubeCrypto":
        return cls(label=label, salt=salt, key=salted(ROOT_KEY, salt), iv=salted(ROOT_IV, salt))

    def encrypt(self, data: bytes) -> bytes:
        if len(data) < 16:
            raise ValueError("packet must be at least 16 bytes")
        buf = bytearray(data)
        buf[0:16] = AES.new(self.key, AES.MODE_CBC, self.iv).encrypt(bytes(buf[0:16]))
        if len(buf) > 16:
            buf[-16:] = AES.new(self.key, AES.MODE_CBC, self.iv).encrypt(bytes(buf[-16:]))
        return bytes(buf)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < 16:
            return data
        buf = bytearray(data)
        if len(buf) > 16:
            buf[-16:] = AES.new(self.key, AES.MODE_CBC, self.iv).decrypt(bytes(buf[-16:]))
        buf[0:16] = AES.new(self.key, AES.MODE_CBC, self.iv).decrypt(bytes(buf[0:16]))
        return bytes(buf)


def _add_salt(candidates: list[CubeCrypto], seen: set[bytes], label: str, six: bytes):
    if len(six) != 6:
        return
    if six == b"\x00" * 6 or six == b"\xff" * 6:
        return

    variants = [
        ("reversed bytes", six[::-1]),
        ("same bytes", six),
    ]
    for suffix, salt in variants:
        if salt not in seen:
            seen.add(salt)
            candidates.append(CubeCrypto.from_salt(f"{label}; salt = {suffix}", salt))


def salt_candidates(manual_mac: str, adv) -> list[CubeCrypto]:
    candidates: list[CubeCrypto] = []
    seen: set[bytes] = set()

    if manual_mac:
        mac = parse_mac(manual_mac)
        _add_salt(candidates, seen, f"manual MAC {manual_mac}", mac)

    for company_id, blob in (adv.manufacturer_data or {}).items():
        blob = bytes(blob)
        for i in range(0, max(0, len(blob) - 5)):
            six = blob[i:i + 6]
            _add_salt(candidates, seen, f"mfg 0x{company_id:04x} bytes {i}-{i + 5} = {six.hex(':')}", six)

    return candidates
