from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .config import ToolConfig
from .ota import FreqchipOTA
from .util import ascii_preview, ensure_dir, hexdump, hex_bytes, now_stamp

SECTOR_SIZE = 0x1000


@dataclass
class Finding:
    label: str
    address: int
    pattern: bytes

    @property
    def sector(self) -> int:
        return self.address & ~(SECTOR_SIZE - 1)


@dataclass
class IdentityScanResult:
    storage_base: int | None
    user_start: int | None
    scan_start: int
    scan_end: int
    findings: list[Finding]


# Advertising data type for a complete local name (Bluetooth Core assigned numbers).
AD_TYPE_COMPLETE_LOCAL_NAME = 0x09

# A zero length byte ends a chain of AD records. What follows, up to the next
# structure in the sector, is zero padding.
AD_TERMINATOR = 0x00


def ad_chain_end(sector: bytes, start: int) -> int | None:
    """Offset of the terminator byte ending the AD record chain at `start`.

    Each record is `length, type, data...`, so the next one begins `1 + length`
    bytes on. Returns None if the chain runs off the sector without a
    terminator, which means the layout is not what this code assumes.
    """
    off = start
    while off < len(sector):
        length = sector[off]
        if length == AD_TERMINATOR:
            return off
        off += 1 + length
    return None


@dataclass
class IdentityRecord:
    """The advertising name record as stored in the identity sector.

    The sector holds the advertising payload as literal AD records
    (`length`, `type`, `data`...), so the cube's name lives behind a two-byte
    header and is followed by the manufacturer-data record carrying the MAC.
    """

    header_offset: int   # the AD length byte
    name_offset: int     # first byte of the name
    name: bytes          # model field + "_" + suffix
    tail_offset: int     # first byte after the name, i.e. the next AD record


def flash_model_pattern(a1_model: bytes | None) -> bytes:
    """The model bytes as they appear *in flash*, for searching.

    A1 always returns an 8-byte model field, zero-padded when the real value is
    shorter. Flash stores only the real bytes, immediately followed by the name
    suffix, so searching for the padded field finds nothing whenever the model
    was corrupted to something shorter than 8 bytes. Stripping the padding is a
    no-op when all 8 bytes are real, so it cannot affect the full-length case.
    """
    return (a1_model or b"").rstrip(b"\x00")


def parse_identity_record(
    sector: bytes, a1_model: bytes | None, cfg: ToolConfig
) -> IdentityRecord | None:
    """Locate the advertising name record inside an identity sector.

    Returns None unless the match really looks like a name record: the corrupt
    model bytes can be arbitrary, so a bare byte-pattern hit is not enough to
    justify rewriting anything. Requires the AD type byte and the expected name
    suffix to agree with the located offset.
    """
    pattern = flash_model_pattern(a1_model)
    if not pattern:
        return None

    suffix = cfg.suffix_bytes
    search_from = 0
    while True:
        name_offset = sector.find(pattern, search_from)
        if name_offset == -1:
            return None
        search_from = name_offset + 1

        header_offset = name_offset - 2
        if header_offset < 0:
            continue
        ad_len = sector[header_offset]
        if sector[header_offset + 1] != AD_TYPE_COMPLETE_LOCAL_NAME:
            continue

        name = sector[name_offset:name_offset + ad_len - 1]
        if len(name) != ad_len - 1:
            continue
        if suffix and not name.endswith(suffix):
            continue

        return IdentityRecord(
            header_offset=header_offset,
            name_offset=name_offset,
            name=name,
            tail_offset=name_offset + len(name),
        )


def build_repaired_sector(sector: bytes, record: IdentityRecord, clean_name: bytes) -> bytes:
    """A full sector image with the name record replaced by `clean_name`.

    The repaired name is usually *longer* than the corrupt one, and the records
    after it - including the manufacturer-data block carrying the MAC the AES
    salt comes from - shift up to stay a contiguous chain. What must **not**
    move is whatever follows the chain: an unidentified structure sits at
    sector+0x020 regardless of how long the name record is, and where the name
    record was shortened the gap in front of it is zero padding. That padding
    is where the growth is absorbed, so every absolute offset past it is
    preserved.

    Raises ValueError when the growth cannot be absorbed, rather than moving
    data whose position may be load-bearing.
    """
    head = (
        sector[:record.header_offset]
        + bytes([len(clean_name) + 1, AD_TYPE_COMPLETE_LOCAL_NAME])
        + clean_name
    )
    growth = len(clean_name) - len(record.name)
    if growth == 0:
        return head + sector[record.tail_offset:]

    chain_end = ad_chain_end(sector, record.header_offset)
    if chain_end is None:
        raise ValueError("the advertising records do not end in a terminator byte")

    pad_end = chain_end
    while pad_end < SECTOR_SIZE and sector[pad_end] == 0x00:
        pad_end += 1
    padding = pad_end - chain_end

    if padding < growth:
        raise ValueError(
            f"the corrected name is {growth} bytes longer, but only {padding} padding "
            f"byte(s) follow the advertising records at sector+0x{chain_end:03x}; "
            f"repairing would move the data at sector+0x{pad_end:03x}"
        )

    return (
        head
        + sector[record.tail_offset:chain_end]
        + bytes(padding - growth)
        + sector[pad_end:]
    )


def infer_user_start(storage_base: int | None, cfg: ToolConfig) -> int | None:
    if storage_base and 0 < storage_base < cfg.flash_max // 2:
        return storage_base * 2
    return None


def scan_range_from_storage(storage_base: int | None, cfg: ToolConfig) -> tuple[int, int, int | None]:
    user_start = infer_user_start(storage_base, cfg)
    if user_start is None:
        return 0, cfg.flash_max, None
    start = max(0, user_start - cfg.user_region_margin_before)
    end = min(cfg.flash_max, user_start + cfg.user_region_scan_after)
    return start, end, user_start


async def scan_for_patterns(
    ota: FreqchipOTA,
    patterns: dict[str, bytes],
    start: int,
    end: int,
    cfg: ToolConfig,
    print_context: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    max_pat_len = max(len(p) for p in patterns.values() if p) if patterns else 1
    prev = b""
    addr = start

    print(f"Scanning 0x{start:08x}..0x{end:08x}")

    while addr < end:
        n = min(cfg.read_chunk, end - addr)
        data = await ota.read_flash(addr, n)
        window = prev + data
        window_base = addr - len(prev)

        for label, pat in patterns.items():
            if not pat:
                continue
            pos = window.find(pat)
            while pos != -1:
                abs_addr = window_base + pos
                finding = Finding(label=label, address=abs_addr, pattern=pat)
                findings.append(finding)
                print(f"\nFOUND {label} at 0x{abs_addr:08x}  {hex_bytes(pat)}  {ascii_preview(pat)!r}")

                if print_context:
                    context_start = max(start, abs_addr - 32)
                    context_len = 96
                    try:
                        context = await ota.read_flash(context_start, context_len)
                        hexdump(context, context_start)
                    except Exception as e:
                        print(f"Could not read context: {e!r}")
                pos = window.find(pat, pos + 1)

        prev = window[-(max_pat_len - 1):]
        if addr % 0x1000 == 0:
            print(f"  ...0x{addr:08x}")
        addr += n

    return findings


async def identity_scan(
    ota: FreqchipOTA,
    cfg: ToolConfig,
    a1_model: bytes | None = None,
    *,
    scan_range: tuple[int, int] | None = None,
) -> IdentityScanResult:
    storage_base = None
    try:
        storage_base = await ota.get_storage_base()
        if storage_base is not None:
            print(f"storage_base: {storage_base} / 0x{storage_base:08x}")
    except Exception as e:
        print(f"storage-base probe failed: {e!r}")

    scan_start, scan_end, user_start = scan_range_from_storage(storage_base, cfg)
    if user_start is not None:
        print(f"Inferred user/config start: 0x{user_start:08x}")
    else:
        print("Could not infer user/config start; using broad fallback scan.")

    # An explicit range overrides the inferred window. The default window is
    # centred on user/config space, where the *live* record lives; a pristine
    # factory template can sit below it, in firmware territory.
    if scan_range is not None:
        scan_start, scan_end = scan_range
        print(f"Range override: 0x{scan_start:08x}..0x{scan_end:08x}")

    patterns = {
        "good_model": cfg.good_model,
        "clean_name": cfg.clean_name_bytes,
        "name_suffix": cfg.suffix_bytes,
    }
    model_pattern = flash_model_pattern(a1_model)
    if model_pattern and model_pattern != cfg.good_model:
        patterns["a1_model_bytes"] = model_pattern

    findings = await scan_for_patterns(ota, patterns, scan_start, scan_end, cfg, print_context=True)
    return IdentityScanResult(storage_base, user_start, scan_start, scan_end, findings)


async def backup_sector(ota: FreqchipOTA, sector_addr: int, cfg: ToolConfig, label: str = "identity") -> Path:
    data = await ota.read_flash(sector_addr, SECTOR_SIZE)
    out_dir = ensure_dir("backups")
    path = out_dir / f"{label}_sector_0x{sector_addr:08x}_{now_stamp()}.bin"
    path.write_bytes(data)
    print(f"Saved backup: {path}")
    return path


def sector_from_backup_name(name: str) -> int | None:
    """The sector address encoded by `backup_sector` into the filename.

    Restoring to the wrong address would corrupt an unrelated sector, so the
    address is taken from the file that is actually being restored rather than
    from configuration that may have moved on since the backup was taken.
    """
    match = re.search(r"_sector_0x([0-9a-fA-F]{8})_", name)
    if not match:
        return None
    return int(match.group(1), 16)


def summarize_sector(data: bytes, sector_addr: int, cfg: ToolConfig, a1_model: bytes | None = None):
    print("Sector first 128 bytes:")
    hexdump(data[:128], sector_addr)
    print()
    print(f"all blank/erased: {all(b == 0xFF for b in data)}")
    for label, pat in {
        "good_model": cfg.good_model,
        "clean_name": cfg.clean_name_bytes,
        "name_suffix": cfg.suffix_bytes,
        "a1_model_bytes": flash_model_pattern(a1_model),
    }.items():
        if not pat:
            continue
        pos = data.find(pat)
        if pos == -1:
            print(f"{label:16s}: not found")
        else:
            print(f"{label:16s}: sector+0x{pos:03x} / flash 0x{sector_addr + pos:08x}")


def choose_repair_sector(scan: IdentityScanResult, a1_model: bytes, cfg: ToolConfig) -> int | None:
    # Prefer a match for the current A1 model in inferred user/config space.
    matches = [f for f in scan.findings if f.label == "a1_model_bytes"]
    if scan.user_start is not None:
        matches = [f for f in matches if f.address >= scan.user_start]
    if matches:
        return matches[0].sector
    return None
