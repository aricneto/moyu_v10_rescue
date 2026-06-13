from __future__ import annotations

import argparse
import asyncio
import sys

from bleak import BleakClient

from .config import ToolConfig, DEFAULT_TARGET_ADDRESS, DEFAULT_TARGET_SUFFIX, suffix_from_mac
from .cube_ble import scan_for_target, print_device_summary
from .cube_protocol import V10Protocol, SERVICE, NOTIFY, WRITE
from .identity import backup_sector, choose_repair_sector, identity_scan, summarize_sector, SECTOR_SIZE
from .ota import FreqchipOTA, OTA_SERVICE
from .util import banner, color_enabled, fail, hr, info, ok, prompt_exact, prompt_yes_no, section, warn


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="v10_rescue.py",
        description="MoYu WeiLong V10 AI BLE/protocol/identity-sector rescue toolkit.",
    )
    p.add_argument("--address", default=DEFAULT_TARGET_ADDRESS, help="target BLE address when visible")
    p.add_argument("--suffix", default=DEFAULT_TARGET_SUFFIX, help="name/address suffix to match, e.g. 8DD8")
    p.add_argument("--mac", default=None, help="real cube MAC used for protocol AES salt; defaults to --address")
    p.add_argument("--scan-timeout", type=float, default=10.0)
    p.add_argument("--watch-seconds", type=float, default=12.0)
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--yes", action="store_true", help="skip non-destructive confirmations; destructive erase still requires exact phrase")
    p.add_argument(
        "--command",
        choices=["menu", "scan", "test", "verify", "backup", "apply", "reboot"],
        default="menu",
        help="run one command instead of the interactive menu",
    )
    return p


def cfg_from_args(args) -> ToolConfig:
    manual_mac = args.mac or args.address
    suffix = args.suffix
    if not suffix and manual_mac:
        suffix = suffix_from_mac(manual_mac)
    return ToolConfig(
        target_address=args.address,
        target_name_suffix=suffix,
        manual_mac=manual_mac,
        ble_scan_timeout=args.scan_timeout,
        watch_seconds=args.watch_seconds,
        color=color_enabled(not args.no_color),
        assume_yes=args.yes,
    )


async def connect_target(cfg: ToolConfig, *, verbose: bool = True):
    fd = await scan_for_target(cfg, verbose=verbose)
    if fd is None:
        raise RuntimeError("Target cube was not found. Close other BLE apps/scanners, wake the cube, and try again.")
    if verbose:
        print_device_summary(fd, cfg)
    client = BleakClient(fd.device, timeout=cfg.connect_timeout)
    await client.connect()
    return fd, client


async def action_scan(cfg: ToolConfig):
    section("Scan", cfg.color)
    fd = await scan_for_target(cfg, verbose=True)
    if fd is None:
        return
    print_device_summary(fd, cfg)
    ok("Scan found the target cube.", cfg.color)


async def action_test(cfg: ToolConfig):
    section("Protocol test", cfg.color)
    fd, client = await connect_target(cfg)
    try:
        print(f"connected: {client.is_connected}")
        print("\nDiscovered services:")
        for service in client.services:
            print(f"SERVICE {service.uuid}")
            for char in service.characteristics:
                print(f"  CHAR {char.uuid} {char.properties}")

        service_uuids = [s.uuid.lower() for s in client.services]
        if SERVICE not in service_uuids:
            raise RuntimeError("Connected, but the V10 main cube service was not discovered.")

        proto = V10Protocol(client, fd.adv, cfg)
        await proto.start()
        try:
            a1 = await proto.init_crypto()
            if a1.model_bytes == cfg.good_model:
                ok("A1 model field is clean.", cfg.color)
            else:
                warn("A1 model field is not the expected clean model.", cfg.color)

            await proto.battery()
            print("\nTemporarily disabling gyro spam so moves are easier to see...")
            await proto.gyro_config(enabled=False)
            await proto.facelets()
            await proto.watch_moves(cfg.watch_seconds, print_gyro=False)
            print("\nRe-enabling gyro...")
            await proto.gyro_config(enabled=True)
        finally:
            await proto.stop()
    finally:
        await client.disconnect()


async def _get_a1_and_ota(cfg: ToolConfig, client, adv):
    proto = V10Protocol(client, adv, cfg)
    await proto.start()
    try:
        a1 = await proto.init_crypto()
    finally:
        await proto.stop()

    ota = FreqchipOTA(client, cfg)
    await ota.start()
    return a1, ota


async def action_verify(cfg: ToolConfig):
    section("Verify identity state", cfg.color)
    fd, client = await connect_target(cfg)
    try:
        a1, ota = await _get_a1_and_ota(cfg, client, fd.adv)
        try:
            await ota.direct_reads()
            try:
                nvds = await ota.get_nvds_type()
                print(f"NVDS/type: {nvds}")
            except Exception as e:
                warn(f"NVDS/type probe failed: {e!r}", cfg.color)
            try:
                fw = await ota.get_fw_version()
                print(f"fw_version: {fw!r} / {fw:#x}" if fw is not None else "fw_version: None")
            except Exception as e:
                warn(f"fw-version probe failed: {e!r}", cfg.color)

            scan = await identity_scan(ota, cfg, a1.model_bytes)

            print("\nSummary:")
            if not scan.findings:
                print("  No identity-related patterns found in the scan region.")
            else:
                for f in scan.findings:
                    print(f"  {f.label:16s}  0x{f.address:08x}  {f.pattern.hex(' ')}")

            if a1.model_bytes == cfg.good_model:
                ok("A1 reports the clean model. Repair is probably complete.", cfg.color)
            else:
                sector = choose_repair_sector(scan, a1.model_bytes, cfg)
                if sector is not None:
                    warn(f"A1 model is not clean, and the matching live record appears in sector 0x{sector:08x}.", cfg.color)
                else:
                    warn("A1 model is not clean, but those bytes were not found in flash scan.", cfg.color)
                    warn("That often means the old name/model is still cached in RAM; try the reboot option.", cfg.color)
        finally:
            await ota.stop()
    finally:
        await client.disconnect()


async def action_backup(cfg: ToolConfig):
    section("Backup identity sector", cfg.color)
    fd, client = await connect_target(cfg)
    try:
        a1, ota = await _get_a1_and_ota(cfg, client, fd.adv)
        try:
            scan = await identity_scan(ota, cfg, a1.model_bytes)
            sector = choose_repair_sector(scan, a1.model_bytes, cfg)
            if sector is None:
                warn("Could not find a live corrupt record to choose automatically.", cfg.color)
                sector = cfg.default_identity_sector
                warn(f"Using default identity sector 0x{sector:08x}.", cfg.color)
            await backup_sector(ota, sector, cfg)
            data = await ota.read_flash(sector, SECTOR_SIZE)
            summarize_sector(data, sector, cfg, a1.model_bytes)
        finally:
            await ota.stop()
    finally:
        await client.disconnect()


async def action_apply(cfg: ToolConfig):
    section("Apply repair patch", cfg.color)
    warn("This repair patches by erasing the live identity sector, then you reboot separately.", cfg.color)
    warn("It does NOT use OTA WRITE_DATA; that command timed out on this firmware during recovery.", cfg.color)

    fd, client = await connect_target(cfg)
    try:
        a1, ota = await _get_a1_and_ota(cfg, client, fd.adv)
        try:
            if a1.model_bytes == cfg.good_model:
                ok("A1 already reports the clean model. No patch needed.", cfg.color)
                return

            scan = await identity_scan(ota, cfg, a1.model_bytes)
            sector = choose_repair_sector(scan, a1.model_bytes, cfg)

            if sector is None:
                warn("Could not locate the current A1 model bytes in user/config flash.", cfg.color)
                fallback_sector = cfg.default_identity_sector
                current = await ota.read_flash(fallback_sector, SECTOR_SIZE)
                if all(b == 0xFF for b in current):
                    warn(f"Default identity sector 0x{fallback_sector:08x} is already blank.", cfg.color)
                    warn("Run the reboot option. The cube may regenerate a clean identity on boot.", cfg.color)
                    return
                fail("Refusing to erase because the target sector is not obvious.", cfg.color)
                return

            current = await ota.read_flash(sector, SECTOR_SIZE)
            summarize_sector(current, sector, cfg, a1.model_bytes)

            if all(b == 0xFF for b in current):
                warn("This sector is already blank. Do not erase again; run the reboot option.", cfg.color)
                return

            if current.find(a1.model_bytes) == -1:
                fail("Refusing to erase: sector no longer contains the exact A1 model bytes.", cfg.color)
                return

            backup_path = await backup_sector(ota, sector, cfg, label="pre_erase_identity")
            warn(f"Backup saved before erase: {backup_path}", cfg.color)
            warn("The next operation erases exactly one 4 KB sector.", cfg.color)
            expected = f"ERASE {sector:08X}"
            if not prompt_exact(
                f"This will erase sector 0x{sector:08x}. The expected recovery path is to reboot afterwards so firmware regenerates the identity record.",
                expected,
            ):
                warn("Confirmation did not match; aborting erase.", cfg.color)
                return

            await ota.page_erase(sector)
            verify = await ota.read_flash(sector, SECTOR_SIZE)
            if all(b == 0xFF for b in verify):
                ok(f"Sector 0x{sector:08x} is erased/blank.", cfg.color)
                warn("Now run option 6: Reboot cube. The BLE name may not change until reboot.", cfg.color)
            else:
                fail("Erase verification failed; sector is not all 0xFF.", cfg.color)
                summarize_sector(verify, sector, cfg, a1.model_bytes)
        finally:
            await ota.stop()
    finally:
        await client.disconnect()


async def action_reboot(cfg: ToolConfig):
    section("Reboot cube", cfg.color)
    fd, client = await connect_target(cfg)
    try:
        ota = FreqchipOTA(client, cfg)
        await ota.start()
        try:
            await ota.reboot()
            ok("Reboot command sent. The cube should reboot and light up for a few seconds. Wait 10-20 seconds, then scan/test again.", cfg.color)
        finally:
            await ota.stop()
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


def menu_text(cfg: ToolConfig) -> str:
    return f"""
Target address: {cfg.target_address}
Target suffix:  {cfg.target_name_suffix}
Manual MAC:     {cfg.manual_mac}

1) Scan for cube
2) Test BLE/protocol/battery/moves
3) Verify identity/model flash state
4) Backup identity sector
5) Apply repair patch: erase live identity sector
6) Reboot cube
7) Quit
""".strip()


async def interactive_menu(cfg: ToolConfig):
    while True:
        print()
        hr(cfg.color)
        print(menu_text(cfg))
        hr(cfg.color)
        choice = input("Choose an option: ").strip().lower()
        try:
            if choice in {"1", "scan"}:
                await action_scan(cfg)
            elif choice in {"2", "test"}:
                await action_test(cfg)
            elif choice in {"3", "verify"}:
                await action_verify(cfg)
            elif choice in {"4", "backup"}:
                await action_backup(cfg)
            elif choice in {"5", "apply", "patch"}:
                await action_apply(cfg)
            elif choice in {"6", "reboot"}:
                await action_reboot(cfg)
            elif choice in {"7", "q", "quit", "exit"}:
                print("Bye.")
                return
            else:
                warn("Unknown menu option.", cfg.color)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            fail(f"Operation failed: {e!r}", cfg.color)
            warn("The cube may need a BLE toggle/reboot if a previous connection is stuck.", cfg.color)


def validate_cfg(cfg: ToolConfig):
    if not cfg.manual_mac:
        warn("No manual MAC set. Protocol decryption may fail if manufacturer data does not expose MAC bytes.", cfg.color)
    if cfg.target_name_suffix and len(cfg.target_name_suffix) < 4:
        warn("Target suffix is short; scan matching may be broad.", cfg.color)


async def main_async(argv=None):
    args = build_arg_parser().parse_args(argv)
    cfg = cfg_from_args(args)
    banner(cfg.color)
    validate_cfg(cfg)

    command = args.command
    if command == "menu":
        await interactive_menu(cfg)
    elif command == "scan":
        await action_scan(cfg)
    elif command == "test":
        await action_test(cfg)
    elif command == "verify":
        await action_verify(cfg)
    elif command == "backup":
        await action_backup(cfg)
    elif command == "apply":
        await action_apply(cfg)
    elif command == "reboot":
        await action_reboot(cfg)


def main(argv=None):
    try:
        asyncio.run(main_async(argv))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    return 0
