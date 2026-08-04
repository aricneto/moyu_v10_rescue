"""Identity-sector bytes from the two cubes this tool has data for.

Shared so there is exactly one answer to "what does cube X's identity sector
look like". Two test modules keeping their own copies is how the repair came to
be designed against a sector tail that one copy was missing.

  8DD8 (tests/fixtures/sectors/v10_sector_0x0007b000.bak.bin)
      the 8-byte model was overwritten with 8 junk bytes, so the record kept
      its original length and the A1 model bytes appeared verbatim in flash.

  1322 (rescue_tool_session_output.txt, 2026-08-04, option 4 sector dump)
      the 8-byte model was replaced by 5 junk bytes and the AD length byte was
      rewritten to match, so the record is 3 bytes shorter, the A1 field --
      always 8 bytes wide -- comes back zero-padded, and the 3 bytes the record
      gave up became zero padding in front of the structure at sector+0x020.
"""

from pathlib import Path

from moyu_v10_rescue.identity import SECTOR_SIZE


def sector_from(head: bytes) -> bytes:
    return bytes(head) + b"\xFF" * (SECTOR_SIZE - len(head))


# Sector 0x0007b000, cube CF:30:16:02:13:22. Model field is 5 junk bytes.
SECTOR_1322 = sector_from(bytes.fromhex(
    "25 12 23 cb"                          # record header (unidentified)
    "0b 09"                                # AD: length 11, type 0x09 complete local name
    "e5 a7 01 8b 01 5f 31 33 32 32"        # corrupt model + "_1322"
    "0c ff 00 00 00 00 30 22 13 02 16 30 cf"  # AD: manufacturer data, reversed MAC
    "00 00 00"                             # AD terminator + padding, up to 0x020
    "19 02 24 bc 3a 00 ff ff 13 06 25 ac d2 0f"  # unidentified, fixed at 0x020
))

# Sector 0x0007b000, cube CF:30:16:01:8D:D8, read off the cube. Its model field is
# 8 junk bytes, so the advertising area is exactly full: the AD length byte is the
# original 0x0e and there is no padding in front of the 0x020 structure.
SECTOR_8DD8 = (Path(__file__).parent / "fixtures" / "sectors" / "v10_sector_0x0007b000.bak.bin").read_bytes()

A1_MODEL_1322 = bytes.fromhex("e5 a7 01 8b 01 00 00 00")  # 5 real bytes + A1 padding
A1_MODEL_8DD8 = bytes.fromhex("22 f9 81 60 bb e0 96 53")  # all 8 bytes real

MFG_RECORD_1322 = bytes.fromhex("0c ff 00 00 00 00 30 22 13 02 16 30 cf")
