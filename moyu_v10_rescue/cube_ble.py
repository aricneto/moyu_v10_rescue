from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from bleak import BleakScanner

from .config import ToolConfig, norm_addr
from .util import hr, info, warn


@dataclass
class FoundDevice:
    device: Any
    adv: Any

    @property
    def address(self) -> str:
        return self.device.address or ""

    @property
    def name(self) -> str:
        return self.device.name or ""

    @property
    def local_name(self) -> str:
        return self.adv.local_name or ""

    @property
    def rssi(self):
        return self.adv.rssi

    @property
    def all_names(self) -> str:
        return " ".join(x for x in [self.name, self.local_name] if x)


def looks_like_target(device, adv, cfg: ToolConfig) -> bool:
    address = (device.address or "").upper()
    names = " ".join(str(x) for x in [device.name, adv.local_name] if x)
    suffix = cfg.target_name_suffix or ""

    target_match = bool(cfg.target_address) and norm_addr(address) == norm_addr(cfg.target_address)
    suffix_match = bool(suffix) and suffix.upper() in names.upper()
    address_suffix_match = bool(suffix) and norm_addr(address).endswith(suffix.upper())

    return target_match or suffix_match or address_suffix_match


async def scan_for_target(cfg: ToolConfig, verbose: bool = True) -> FoundDevice | None:
    if verbose:
        info(f"Scanning for cube for {cfg.ble_scan_timeout:.1f}s...", cfg.color)

    results = await BleakScanner.discover(timeout=cfg.ble_scan_timeout, return_adv=True)
    matches: list[FoundDevice] = []
    visible: list[FoundDevice] = []

    for device, adv in results.values():
        fd = FoundDevice(device, adv)
        if fd.name or fd.local_name or adv.service_uuids or adv.manufacturer_data:
            visible.append(fd)
        if looks_like_target(device, adv, cfg):
            matches.append(fd)

    matches.sort(key=lambda fd: fd.rssi if fd.rssi is not None else -999, reverse=True)

    if verbose:
        if matches:
            hr(cfg.color)
            for fd in matches:
                print(
                    f"candidate: {fd.address} | dev.name={fd.name!r} | "
                    f"local_name={fd.local_name!r} | rssi={fd.rssi} | "
                    f"uuids={fd.adv.service_uuids}"
                )
                if fd.adv.manufacturer_data:
                    for cid, blob in fd.adv.manufacturer_data.items():
                        print(f"  mfg 0x{cid:04x}: {bytes(blob).hex(' ')}")
        else:
            warn("No target-like cube found.", cfg.color)
            if visible:
                print("Nearby named/service-advertising BLE devices:")
                for fd in sorted(visible, key=lambda x: x.rssi if x.rssi is not None else -999, reverse=True)[:20]:
                    print(
                        f"  {fd.address} | name={fd.all_names!r} | "
                        f"rssi={fd.rssi} | uuids={fd.adv.service_uuids}"
                    )
            else:
                print("No visible BLE devices with names/services/manufacturer data were returned.")

    return matches[0] if matches else None


def print_device_summary(fd: FoundDevice, cfg: ToolConfig):
    hr(cfg.color)
    print("Using device:")
    print(f"  address/id: {fd.address}")
    print(f"  name:       {fd.name!r}")
    print(f"  local name: {fd.local_name!r}")
    print(f"  RSSI:       {fd.rssi}")
    print(f"  services:   {fd.adv.service_uuids}")
    if fd.adv.manufacturer_data:
        print("  manufacturer data:")
        for cid, blob in fd.adv.manufacturer_data.items():
            print(f"    0x{cid:04x}: {bytes(blob).hex(' ')}")
