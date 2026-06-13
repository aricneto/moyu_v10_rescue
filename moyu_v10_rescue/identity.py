from __future__ import annotations

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


async def identity_scan(ota: FreqchipOTA, cfg: ToolConfig, a1_model: bytes | None = None) -> IdentityScanResult:
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

    patterns = {
        "good_model": cfg.good_model,
        "clean_name": cfg.clean_name_bytes,
        "name_suffix": cfg.suffix_bytes,
    }
    if a1_model:
        patterns["a1_model_bytes"] = a1_model

    findings = await scan_for_patterns(ota, patterns, scan_start, scan_end, cfg, print_context=True)
    return IdentityScanResult(storage_base, user_start, scan_start, scan_end, findings)


async def backup_sector(ota: FreqchipOTA, sector_addr: int, cfg: ToolConfig, label: str = "identity") -> Path:
    data = await ota.read_flash(sector_addr, SECTOR_SIZE)
    out_dir = ensure_dir("backups")
    path = out_dir / f"{label}_sector_0x{sector_addr:08x}_{now_stamp()}.bin"
    path.write_bytes(data)
    print(f"Saved backup: {path}")
    return path


def summarize_sector(data: bytes, sector_addr: int, cfg: ToolConfig, a1_model: bytes | None = None):
    print("Sector first 128 bytes:")
    hexdump(data[:128], sector_addr)
    print()
    print(f"all blank/erased: {all(b == 0xFF for b in data)}")
    for label, pat in {
        "good_model": cfg.good_model,
        "clean_name": cfg.clean_name_bytes,
        "name_suffix": cfg.suffix_bytes,
        "a1_model_bytes": a1_model or b"",
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
