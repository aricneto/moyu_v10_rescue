from dataclasses import dataclass
import re


DEFAULT_TARGET_ADDRESS = "CF:30:16:01:8D:D8"
DEFAULT_TARGET_SUFFIX = "8DD8"
DEFAULT_GOOD_MODEL = b"WCU_MY32"


@dataclass
class ToolConfig:
    target_address: str = DEFAULT_TARGET_ADDRESS
    target_name_suffix: str = DEFAULT_TARGET_SUFFIX
    manual_mac: str = DEFAULT_TARGET_ADDRESS
    good_model: bytes = DEFAULT_GOOD_MODEL
    ble_scan_timeout: float = 10.0
    connect_timeout: float = 30.0
    flash_max: int = 0x100000
    default_identity_sector: int = 0x0007B000
    user_region_margin_before: int = 0x8000
    user_region_scan_after: int = 0x30000
    read_chunk: int = 128
    watch_seconds: float = 12.0
    color: bool = True
    assume_yes: bool = False

    @property
    def suffix_bytes(self) -> bytes:
        suffix = (self.target_name_suffix or "").strip()
        return ("_" + suffix).encode("ascii", errors="ignore")

    @property
    def clean_name_bytes(self) -> bytes:
        return self.good_model + self.suffix_bytes


def norm_addr(s: str) -> str:
    """Normalize a BLE address/UUID-like string to uppercase hex-only text."""
    return re.sub(r"[^0-9A-Fa-f]", "", s or "").upper()


def parse_mac(mac: str) -> bytes:
    h = norm_addr(mac)
    if len(h) != 12:
        raise ValueError("MAC must contain exactly 12 hex digits, for example CF:30:16:01:8D:D8")
    return bytes.fromhex(h)


def suffix_from_mac(mac: str) -> str:
    h = norm_addr(mac)
    if len(h) < 4:
        return ""
    return h[-4:]
