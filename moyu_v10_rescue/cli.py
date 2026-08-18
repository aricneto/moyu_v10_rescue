from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from bleak import BleakClient

from .config import ToolConfig, DEFAULT_TARGET_ADDRESS, DEFAULT_TARGET_SUFFIX, suffix_from_mac
from .cube_ble import scan_for_target, print_device_summary
from .cube_protocol import V10Protocol, SERVICE, NOTIFY, WRITE
from .identity import (
    backup_sector,
    build_repaired_sector,
    choose_repair_sector,
    flash_model_pattern,
    identity_scan,
    parse_identity_record,
    sector_from_backup_name,
    summarize_sector,
    SECTOR_SIZE,
)
from .ota import FreqchipOTA, OTA_SERVICE
from .util import banner, color_enabled, fail, hexdump, hr, info, ok, prompt_exact, prompt_yes_no, section, warn


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
    p.add_argument("--scan-start", default="0x0", help="first address for the full-flash scan")
    p.add_argument("--scan-end", default="0x0", help="last address for the full-flash scan; 0 means flash_max")
    p.add_argument(
        "--write-chunk",
        type=int,
        default=ToolConfig.write_chunk,
        help="bytes per WRITE_DATA packet; lower it if the full-size write test fails",
    )
    p.add_argument(
        "--command",
        choices=[
            "menu", "scan", "test", "verify", "backup", "apply", "reboot",
            "fullscan", "writetest", "repair", "restore",
        ],
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
        scan_start=int(str(args.scan_start), 0),
        scan_end=int(str(args.scan_end), 0),
        write_chunk=args.write_chunk,
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

            if current.find(flash_model_pattern(a1.model_bytes)) == -1:
                fail("Refusing to erase: sector no longer contains the current A1 model bytes.", cfg.color)
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


async def action_full_scan(cfg: ToolConfig):
    """Read-only sweep of the whole flash, looking for a pristine model template.

    The default scan window is centred on user/config space, where the *live*
    record is. A factory template can sit below that, in firmware territory -
    on the 8DD8 cube one did, at 0x000513a5. Whether this cube has one is the
    question that decides if erase-and-reboot has anything to regenerate from.
    """
    section("Full-flash identity scan (read-only)", cfg.color)
    start, end = cfg.scan_start, cfg.scan_end if cfg.scan_end else cfg.flash_max
    info(
        f"Scanning 0x{start:08x}..0x{end:08x} in {cfg.read_chunk}-byte reads. "
        f"That is ~{max(1, (end - start) // cfg.read_chunk)} round trips; expect several minutes.",
        cfg.color,
    )

    fd, client = await connect_target(cfg)
    try:
        a1, ota = await _get_a1_and_ota(cfg, client, fd.adv)
        try:
            scan = await identity_scan(ota, cfg, a1.model_bytes, scan_range=(start, end))

            print("\nSummary:")
            if not scan.findings:
                print("  Nothing found anywhere in the scanned range.")
            for f in scan.findings:
                print(f"  {f.label:16s}  0x{f.address:08x}  {f.pattern.hex(' ')}")

            templates = [f for f in scan.findings if f.label in {"good_model", "clean_name"}]
            live = [f for f in scan.findings if f.label == "a1_model_bytes"]

            print()
            if templates:
                ok(f"A pristine model template exists ({len(templates)} match(es)).", cfg.color)
                info("Erase-and-reboot has a plausible source to regenerate from.", cfg.color)
            else:
                warn("No pristine 'WCU_MY32' bytes anywhere in the scanned range.", cfg.color)
                warn(
                    "The cube that recovered by erase+reboot had one. Without it, erasing "
                    "risks leaving no identity at all - prefer the write repair.",
                    cfg.color,
                )
            if live:
                info(f"Live corrupt record located in sector 0x{live[0].sector:08x}.", cfg.color)
        finally:
            await ota.stop()
    finally:
        await client.disconnect()


async def action_write_test(cfg: ToolConfig):
    """Prove whether OTA WRITE_DATA works, without touching anything live.

    Upstream reported 0x05 timing out, and every repair that can be undone
    depends on it. NOR flash clears bits without an erase, so this writes into
    blank padding at the end of the identity sector and reads it back.

    Two writes, not one. A 4-byte probe answers "does the opcode work at all";
    a full `write_chunk`-sized probe answers "does it work at the size the
    repair uses", and only the second question is the one that matters. The
    repair writes the sector back in `write_chunk` blocks *after* erasing it,
    so a size limit discovered there would strand the cube with a blank
    identity sector - restoring the backup goes through the same writes.
    """
    section("WRITE_DATA capability test", cfg.color)
    fd, client = await connect_target(cfg)
    try:
        a1, ota = await _get_a1_and_ota(cfg, client, fd.adv)
        try:
            sector = cfg.default_identity_sector
            chunk_addr = sector + SECTOR_SIZE - cfg.write_chunk
            small_addr = chunk_addr - 8
            probe_len = 8 + cfg.write_chunk

            current = await ota.read_flash(small_addr, probe_len)
            print(f"Probe area 0x{small_addr:08x}..0x{small_addr + probe_len:08x}")
            if any(b != 0xFF for b in current):
                print(current.hex(' '))
                fail("Probe area is not blank; refusing to write over existing bytes.", cfg.color)
                return
            print("  blank, as expected")

            await backup_sector(ota, sector, cfg, label="pre_write_test")
            warn(
                f"This writes 4 bytes, then {cfg.write_chunk} bytes, into unused padding at the "
                "end of the identity sector. It does not touch the identity record, and a later "
                "repair erases the sector anyway.",
                cfg.color,
            )
            if not cfg.assume_yes and not prompt_yes_no("Run the write test?", default=False):
                warn("Skipped.", cfg.color)
                return

            probe = bytes.fromhex("a5 5a a5 5a")
            try:
                raw = await ota.write_data(small_addr, probe)
                print(f"WRITE_DATA response: {raw.hex(' ')}")
            except TimeoutError as e:
                fail(f"WRITE_DATA timed out: {e}", cfg.color)
                warn("This firmware does not accept writes. Only the erase-only path remains.", cfg.color)
                return
            except Exception as e:
                fail(f"WRITE_DATA rejected: {e!r}", cfg.color)
                return

            readback = await ota.read_flash(small_addr, 4)
            print(f"Readback:            {readback.hex(' ')}")
            if readback != probe:
                if all(b == 0xFF for b in readback):
                    fail("Write was accepted but nothing changed - the command is a no-op here.", cfg.color)
                else:
                    fail("Readback does not match what was written; do not use the write repair.", cfg.color)
                return
            ok("WRITE_DATA works for a 4-byte payload.", cfg.color)

            # The full-size packet is 9 + write_chunk bytes and has to survive the
            # negotiated ATT MTU, which the 4-byte probe never exercised. A counting
            # pattern makes a truncated write show up as the offset it stopped at.
            block = (bytes(range(256)) * (cfg.write_chunk // 256 + 1))[:cfg.write_chunk]
            smaller = max(4, cfg.write_chunk // 4)
            info(f"Writing a full {cfg.write_chunk}-byte block at 0x{chunk_addr:08x}...", cfg.color)
            try:
                await ota.write_data(chunk_addr, block)
            except Exception as e:
                fail(f"Full-size WRITE_DATA failed: {e!r}", cfg.color)
                warn(f"Retry this test with --write-chunk {smaller} before using the write repair.", cfg.color)
                return

            readback = await ota.read_flash(chunk_addr, cfg.write_chunk)
            if readback == block:
                ok(f"WRITE_DATA works at {cfg.write_chunk} bytes. The reversible write repair is available.", cfg.color)
            else:
                landed = next(
                    (i for i, (a, b) in enumerate(zip(readback, block)) if a != b),
                    min(len(readback), len(block)),
                )
                fail(f"Only the first {landed} bytes read back correctly.", cfg.color)
                warn(f"Retry this test with --write-chunk {smaller} before using the write repair.", cfg.color)
        finally:
            await ota.stop()
    finally:
        await client.disconnect()


async def action_repair_write(cfg: ToolConfig):
    """Erase the identity sector and write back a corrected image.

    Reversible: the pre-image is saved first, and a failed write leaves the
    sector erased - the same state the erase-only repair produces, from which
    this can simply be retried or the backup restored.
    """
    section("Repair by rewriting the identity record", cfg.color)
    warn("Requires WRITE_DATA to work on this cube. Run the write test first.", cfg.color)

    fd, client = await connect_target(cfg)
    try:
        a1, ota = await _get_a1_and_ota(cfg, client, fd.adv)
        try:
            if a1.model_bytes == cfg.good_model:
                ok("A1 already reports the clean model. No repair needed.", cfg.color)
                return

            scan = await identity_scan(ota, cfg, a1.model_bytes)
            sector = choose_repair_sector(scan, a1.model_bytes, cfg)
            if sector is None:
                fail("Could not locate the live record in user/config flash; refusing to write.", cfg.color)
                return

            current = await ota.read_flash(sector, SECTOR_SIZE)
            summarize_sector(current, sector, cfg, a1.model_bytes)

            record = parse_identity_record(current, a1.model_bytes, cfg)
            if record is None:
                fail("Found the model bytes but they are not inside an advertising name record.", cfg.color)
                warn("Refusing to rewrite a record whose structure is not understood.", cfg.color)
                return

            clean_name = cfg.clean_name_bytes
            print(f"\nCurrent name: {record.name.hex(' ')}  {record.name!r}")
            print(f"Repaired name: {clean_name.hex(' ')}  {clean_name!r}")
            try:
                repaired = build_repaired_sector(current, record, clean_name)
            except ValueError as e:
                fail(f"Refusing to rewrite: {e}", cfg.color)
                return

            print("\nBefore (first 64 bytes):")
            hexdump(current[:64], sector)
            print("After (first 64 bytes):")
            hexdump(repaired[:64], sector)

            backup_path = await backup_sector(ota, sector, cfg, label="pre_write_identity")
            warn(f"Backup saved: {backup_path}", cfg.color)
            warn("The next operation erases one 4 KB sector and writes the image above.", cfg.color)
            expected = f"WRITE {sector:08X}"
            if not prompt_exact(
                f"This erases sector 0x{sector:08x} and writes back a corrected identity record. "
                f"If the write fails, the sector stays erased and this backup can be restored.",
                expected,
            ):
                warn("Confirmation did not match; aborting.", cfg.color)
                return

            await ota.page_erase(sector)
            blank = await ota.read_flash(sector, SECTOR_SIZE)
            if not all(b == 0xFF for b in blank):
                fail("Erase verification failed; not writing on top of a dirty sector.", cfg.color)
                return

            # Erased flash already reads 0xFF, so only the meaningful head needs writing.
            payload = repaired.rstrip(b"\xFF")
            info(f"Writing {len(payload)} bytes at 0x{sector:08x}...", cfg.color)
            await ota.write_flash(sector, payload)

            verify = await ota.read_flash(sector, SECTOR_SIZE)
            if verify == repaired:
                ok("Sector rewritten and verified.", cfg.color)
                warn("Now run the reboot option, then re-scan. A1 should report WCU_MY32.", cfg.color)
            else:
                fail("Readback does not match the intended image.", cfg.color)
                summarize_sector(verify, sector, cfg, a1.model_bytes)
                warn(f"Restore from {backup_path} or retry before rebooting.", cfg.color)
        finally:
            await ota.stop()
    finally:
        await client.disconnect()


async def action_restore(cfg: ToolConfig):
    """Write a previously saved sector image back - the undo for any write repair."""
    section("Restore identity sector from a backup", cfg.color)

    path_text = input("Path to backup .bin: ").strip()
    path = Path(path_text)
    if not path.is_file():
        fail(f"No such file: {path}", cfg.color)
        return

    data = path.read_bytes()
    if len(data) != SECTOR_SIZE:
        fail(f"Backup is {len(data)} bytes; expected exactly {SECTOR_SIZE}.", cfg.color)
        return

    sector = sector_from_backup_name(path.name)
    if sector is None:
        fail("Could not read a sector address out of the filename; aborting.", cfg.color)
        return
    info(f"Restoring to sector 0x{sector:08x}", cfg.color)

    fd, client = await connect_target(cfg)
    try:
        ota = FreqchipOTA(client, cfg)
        await ota.start()
        try:
            expected = f"RESTORE {sector:08X}"
            if not prompt_exact(
                f"This erases sector 0x{sector:08x} and writes back {path.name}.",
                expected,
            ):
                warn("Confirmation did not match; aborting.", cfg.color)
                return

            await ota.page_erase(sector)
            blank = await ota.read_flash(sector, SECTOR_SIZE)
            if not all(b == 0xFF for b in blank):
                fail("Erase verification failed; not writing on top of a dirty sector.", cfg.color)
                return

            await ota.write_flash(sector, data.rstrip(b"\xFF"))
            verify = await ota.read_flash(sector, SECTOR_SIZE)
            if verify == data:
                ok("Sector restored and verified.", cfg.color)
            else:
                fail("Readback does not match the backup.", cfg.color)
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

Read-only
  1) Scan for cube
  2) Test BLE/protocol/battery/moves
  3) Verify identity/model flash state
  4) Backup identity sector
  8) Full-flash identity scan (is there a pristine template?)
  9) WRITE_DATA capability test (writes into blank padding, small then full-size)

Repair
 10) Rewrite identity record   (erase + write; reversible, needs 9 to pass)
  5) Erase live identity sector (erase only; NOT reversible)
 11) Restore identity sector from a backup file
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
            elif choice in {"8", "fullscan"}:
                await action_full_scan(cfg)
            elif choice in {"9", "writetest"}:
                await action_write_test(cfg)
            elif choice in {"10", "repair"}:
                await action_repair_write(cfg)
            elif choice in {"11", "restore"}:
                await action_restore(cfg)
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
    elif command == "fullscan":
        await action_full_scan(cfg)
    elif command == "writetest":
        await action_write_test(cfg)
    elif command == "repair":
        await action_repair_write(cfg)
    elif command == "restore":
        await action_restore(cfg)


def main(argv=None):
    try:
        asyncio.run(main_async(argv))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    return 0
