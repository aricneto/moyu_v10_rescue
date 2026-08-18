# MoYu WeiLong V10 AI Rescue Toolkit

A small Python toolkit for debugging and recovering a MoYu WeiLong V10 AI smart cube whose BLE name/model identity record became corrupted.

This package is based on the troubleshooting flow that worked for the cube with:

```text
MAC:           CF:30:16:01:8D:D8
Garbled name:  "��`��S_8DD8
Good model:    WCU_MY32
Main service:  0783b03e-7735-b5a0-1760-a305d2795cb0
Write char:    0783b03e-7735-b5a0-1760-a305d2795cb2
Notify char:   0783b03e-7735-b5a0-1760-a305d2795cb1
OTA service:   02f00000-0000-0000-0000-00000000fe00
```

The successful repair path was **not** a normal BLE rename. The cube did not expose the standard GAP Device Name characteristic. Instead, the corrupt live identity record was in flash. Erasing that one identity sector and rebooting made the firmware regenerate/load a valid identity again.

## Safety notes

This tool can erase one 4 KB flash sector when you choose the repair option. Use the read-only options first.

> **Find out what broke the cube before you repair it.** The corruption is usually
> caused by an app connecting with the wrong MAC: a wrong MAC is a wrong AES key,
> and the cube has no authentication step, so it decrypts the write with *its* key
> and executes the resulting 20 bytes as a command. It is deterministic - repair
> the cube, reconnect the same app, and it breaks again identically. We watched it
> happen. See [`docs/what-corrupts-the-identity-record.md`](docs/what-corrupts-the-identity-record.md).

The main repair flow intentionally does **not** use OTA `WRITE_DATA` because this firmware timed out on `0x05 WRITE_DATA` during recovery. The proven repair path was:

1. Verify the corrupt A1 model bytes.
2. Find those exact bytes in the user/config flash region.
3. Back up the sector.
4. Erase only that sector.
5. Reboot the cube.
6. Confirm A1 reports `WCU_MY32`.

Do not write to random OTA characteristics, do not use chip erase, and do not attempt firmware-update writes unless you have a complete firmware/recovery process.

## Requirements

Python 3.10+ is recommended.

Install dependencies:

```powershell
py -m pip install -r requirements.txt
```

or:

```bash
python -m pip install -r requirements.txt
```

Dependencies:

```text
bleak
pycryptodome
```

## Quick start

Open a terminal, then run:

```bash
python ./v10_rescue.py
```

By default, the tool targets:

```text
BLE address: CF:30:16:01:8D:D8
suffix:  8DD8
MAC address: CF:30:16:01:8D:D8
```

You will want to change those values to match your cube.
You can find your cube's MAC and (corrupted) advertised name with a BLE scanner app on your phone or computer (such as nRF Connect).

The BLE address is often the real MAC.

The suffix is the last 4 characters of the corrupted device name, which also happens to be the last 4 characters of the real MAC (8DD8), but confirm with a scanner (it'll look something like <corrupted_stuff>_8DD8).

Then, run the tool with your cube's correct values:

```powershell
py .\v10_rescue.py --address AA:BB:CC:DD:EE:FF --mac AA:BB:CC:DD:EE:FF --suffix EEFF
```

On macOS, Bleak may not show the real BLE MAC address. In that case, still pass `--mac` with the cube's real MAC if you know it, and use `--suffix` to match the advertised name suffix.

## Menu options

Each menu option will scan for the cube for 10s. Make sure the cube is awake (turn a face), close to your bluetooth adapter, and no other devices are interfering. You may need to run the scan option 2-3 times for it to find the cube. Read the entire README before attempting the repair, and do not skip steps.

### 1. Scan for cube

Scans BLE devices and prints target-like matches, including name, RSSI, advertised services, and manufacturer data.

Use this first to confirm the computer can see the cube.

### 2. Test BLE/protocol/battery/moves

Connects to the cube, discovers services, decrypts the protocol, and checks:

- `A1` cube info/model bytes
- `A4` battery level
- `A3` facelet/state response
- `A5` move events during a watch window

A healthy protocol connection should show a valid `A1` response and battery percent. If you turn layers during the watch window, you should see `A5 move` events.

### 3. Verify identity/model flash state

Read-only. This option:

- reads the current `A1` model bytes
- probes OTA info
- infers the user/config flash region from `storage_base`
- scans for:
  - the current A1 model bytes
  - `WCU_MY32`
  - `WCU_MY32_<suffix>`
  - `_<suffix>`

If the A1 model is corrupt and those exact bytes are found in user/config flash, the tool identifies the likely live identity sector.

Write down that sector's address. You will need it for the patch.

If A1 is corrupt but the bytes are not found in flash, the old corrupt name/model may just be cached in RAM; try the reboot option.

### 4. Backup identity sector

Reads and saves the likely identity sector into `backups/`.

Example output:

```text
backups/pre_erase_identity_sector_0x0007b000_20260101_120000.bin
```

Backups are binary sector dumps. Keep them.

### 5. Full-flash identity scan (read-only)

Options 3 and 4 scan a window around user/config space, which is where the *live*
record is. This one sweeps the whole flash (`--scan-start` / `--scan-end` to narrow
it) looking for pristine `WCU_MY32` bytes anywhere.

That matters because the cube this tool originally recovered had a clean template
at `0x000513a5`, below user/config space, which is the most likely thing the
firmware regenerated the identity from after erase. A cube without one is not the
same situation, and erase-only is a much larger bet there.

The scan is slow - roughly one BLE round trip per `--read-chunk` bytes, so a full
1 MB sweep is several minutes.

### 6. WRITE_DATA capability test

Writes into blank padding at the end of the identity sector and reads it back.
Nothing live is touched, and a backup is taken first.

It writes twice: four bytes, then a full `--write-chunk`-sized block. The second
write is the one that matters. Option 7 writes the sector back in `--write-chunk`
blocks *after* erasing it, and restoring the backup goes through the same writes,
so a size limit found only at that point would leave the cube with a blank
identity sector and no way back. If the small write passes and the big one does
not, re-run with a smaller `--write-chunk` until it passes, and use the same value
for the repair.

`WRITE_DATA` (`0x05`) timed out during the original recovery, so it is not used on
any automatic path. This is how you find out whether *this* cube accepts it, which
decides whether option 7 is available.

### 7. Rewrite identity record (erase + write)

The repair to prefer when option 6 passes. Reads the sector, locates the
advertising name record, rebuilds it with the correct model name - fixing the AD
length byte and moving the manufacturer-data record up to keep the record chain
contiguous - then erases the sector and writes the corrected image back.

What it will not move is anything past the advertising records. Both cubes this
tool has sector bytes for carry an unidentified structure at `sector+0x020`, and
on the cube whose name record was *shortened* the gap in front of it is zero
padding - that is, the firmware kept the structure's offset rather than sliding it
down. The AD chain terminates before it, so nothing can be reaching it by walking
records. Growth is therefore absorbed by that padding, and the repair refuses if
there is not enough of it rather than shifting data whose position may matter.

It refuses unless the model bytes are found *inside a real AD name record*
(`0x09` type byte in front, expected suffix at the end). Corrupt bytes can be
anything, so a bare pattern hit is not enough to justify rewriting.

The important property is that it is **reversible**: the pre-image is saved first,
and if the write fails the sector is simply left erased - the same state option 8
produces, from which you can retry or restore.

### 8. Apply repair patch: erase live identity sector

This is the destructive repair option.

It only proceeds when it can find the exact current A1 model bytes inside a likely user/config sector. Before erase, it saves a backup. Then it requires an exact confirmation phrase like:

```text
ERASE 0007B000
```

After erase, it verifies the sector is all `0xFF`.

This option does **not** automatically reboot. Run option 10 afterward.

### 9. Restore identity sector from a backup

Erases the sector and writes a saved `.bin` back over it. The target address comes
from the backup's filename, not from configuration, so a restore cannot land on
the wrong sector.

### 10. Reboot cube

Sends the OTA reboot command. The cube may disconnect/reset without returning a clean notification; that can be normal.

After reboot, the cube will light up for a few seconds, wait 10-20 seconds, wake the cube, then run option 2 again.

Success looks like:

```text
model: 57 43 55 5f 4d 59 33 32 / 'WCU_MY32'
```

and apps such as WCU/Cubeast/csTimer should have a much better chance of recognizing the cube again.

## One-shot command mode

You can run menu options directly:

```powershell
py .\v10_rescue.py --command scan
py .\v10_rescue.py --command test
py .\v10_rescue.py --command verify
py .\v10_rescue.py --command backup
py .\v10_rescue.py --command fullscan
py .\v10_rescue.py --command writetest
py .\v10_rescue.py --command repair
py .\v10_rescue.py --command apply
py .\v10_rescue.py --command restore
py .\v10_rescue.py --command reboot
```

## Suggested repair flow

Gather evidence first, then pick a repair based on what it says:

```text
1. scan
2. test
3. verify          -> is the live record located?
4. backup
5. fullscan        -> does a pristine WCU_MY32 template exist?
6. writetest       -> does this firmware accept WRITE_DATA, at the size repair uses?
```

Then:

| writetest | fullscan | Do this |
|-----------|----------|---------|
| passes    | either   | `repair` (option 7) - reversible, with the same `--write-chunk` the test passed at |
| fails     | template found | `apply` (option 8), then `reboot` - the upstream path |
| fails     | no template    | Stop. Erasing may leave no identity to regenerate from, and the manufacturer data that seeds the AES salt lives in the same record. A cube with a corrupt *name* is still usable by software that does not filter on it; a cube with no identity record may not be. |

Finish with `reboot`, then `test` again. Success is `A1` reporting `WCU_MY32`.

Do not run `apply` repeatedly. If the sector is already blank, run `reboot` instead.

## Generated files

The tool may create:

```text
backups/*.bin
```

These are raw flash sector backups. They are cube-specific.

## Troubleshooting

### The cube scans but protocol decrypt fails

Check `--mac`. The V10 protocol encryption uses MAC-derived salt. On Windows/Linux, the displayed BLE address may be the real MAC. On macOS, it usually is not, so you may need the real MAC from another scanner/device.

### The cube shows `uuids=[]` in the advertisement

That can happen. The V10 service may only appear after connecting and discovering GATT services. This tool matches by MAC/suffix first, then checks services after connecting.

### `WRITE_DATA` timeouts

This tool's main repair path avoids `WRITE_DATA`. During the original recovery, erase worked but `0x05 WRITE_DATA` timed out. Erasing the corrupt identity sector and rebooting was enough for the firmware to recover the identity record.

### BLE scanner still shows the old garbled name after repair

The OS or scanner may cache old names. Reboot the cube using option 10, toggle Bluetooth, remove/forget the device, scan from a second device, or run the protocol test. The reliable success check is `A1` showing `WCU_MY32`.

### The corrupt model is shorter than 8 bytes

`A1` always returns an 8-byte model field and zero-pads it, but flash stores only
the real bytes followed immediately by the name suffix. When the corruption is
shorter than 8 bytes - e.g. `e5 a7 01 8b 01` in place of `WCU_MY32`, with the AD
length byte rewritten from `0x0e` to `0x0b` - searching flash for the padded field
finds nothing, and every locate-based safety check refuses.

The scan strips that padding before searching, which is a no-op when all eight
bytes are real, so the full-length case behaves exactly as before.

### The verify option says A1 is corrupt but flash does not contain those bytes

That usually means the old identity is still cached in RAM. Run the reboot option and test again.

## Project layout

```text
v10_rescue.py                 entry point
moyu_v10_rescue/config.py     constants and target configuration
moyu_v10_rescue/cube_ble.py   BLE scanning and target matching
moyu_v10_rescue/crypto.py     AES/salt handling for V10 packets
moyu_v10_rescue/cube_protocol.py  A1/A3/A4/A5/AB/AC protocol tools
moyu_v10_rescue/ota.py        Freqchip-style OTA read/erase/reboot helpers
moyu_v10_rescue/identity.py   identity-sector scanning and backups
moyu_v10_rescue/cli.py        terminal interface
```


## Running tests

The package includes an offline pytest suite. The tests are designed to avoid real BLE connections and avoid flash erases; hardware-facing behavior is tested with fake clients/mocks.

Install test dependencies:

```powershell
py -m pip install -r requirements-dev.txt
```

or:

```bash
python -m pip install -r requirements-dev.txt
```

Run tests:

```powershell
py -m pytest
```

or with a simple coverage report:

```powershell
py -m pytest --cov=moyu_v10_rescue --cov-report=term-missing
```

The tests use fixtures derived from the recovery logs and sector dumps:

```text
tests/fixtures/logs/protocol_success.log
tests/fixtures/logs/flash_scan_before_erase.log
tests/fixtures/logs/flash_scan_after_failed_write.log
tests/fixtures/logs/recovery_blank_sector.log
tests/fixtures/sectors/v10_sector_0x0007b000.bak.bin
tests/fixtures/sectors/v10_sector_0x0007b000_patched.bin
```

Important test groups:

```text
test_crypto_vectors.py       decrypt/encrypt vectors from the real cube logs
test_protocol_parsing.py     A1/A3/A4/A5 packet construction and parsing
test_ota.py                  Freqchip OTA framing, readback, erase alignment, reboot tolerance
test_identity.py             flash scan ranges, pattern detection, repair-sector selection
test_sector_fixtures.py      validates the backed-up and patched identity-sector fixtures
test_cli_safety.py           verifies the destructive apply flow refuses unsafe states
test_ble_matching.py         target matching by MAC, suffix, and garbled-name suffix
```

Some tests import `bleak` and `pycryptodome`. If those dependencies are not installed, pytest will skip the affected tests and report that in the summary.


# License (GNU GPL v3)

    Copyright (C) 2026  Ariovaldo Neto

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.