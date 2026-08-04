# What corrupts the identity record in the first place

This tool repairs a cube whose advertising identity record was overwritten with
junk. This note is about **how cubes get into that state**, because the answer
turns out to be a bug pattern that any MoYu client can have — including the app
you use every day, and including this tool's own key-guessing fallback if you
write one.

If you repair a cube and then reconnect the app that broke it, it breaks again
immediately. We learned that the hard way.

## A wrong key is not a rejected packet

The cube derives its AES-128 key and IV from a fixed root key/IV plus its own MAC,
reversed, as a salt. There is no handshake, no authentication step, and no error
for a bad key.

So when a client encrypts a command under the wrong MAC, the cube does not ignore
it. The cube decrypts it with *its* key, gets 20 bytes of plausible-looking
garbage, and **executes it as a command** — a random opcode carrying a random
payload.

Writing under an unverified key is not "a connection that will fail". It is
fuzzing the cube's command interface, with the cube's own flash as the target.

## A worked example

A client whose configured MAC was `CF:30:16:00:EE:D3` connected to a cube whose
real MAC is `CF:30:16:02:13:22`, and sent the ordinary `0xA1` "request cube info"
packet that every client sends on connect:

```
client sends (plain)   a1 00 00 00 00 00 …        request cube info
encrypted under        CF:30:16:00:EE:D3          wrong MAC → wrong key
cube decrypts to       ad 05 e5 a7 01 8b 01 9e bc f7 …
                       ^^ ^^ ^^^^^^^^^^^^^^
                       │  │  └─ payload, 5 bytes
                       │  └──── length = 5
                       └─────── opcode 0xAD, undocumented
```

`0xAD` appears to be "set device name". The firmware stored
`<payload>_<mac suffix>` in the identity sector and rewrote the AD length byte to
match — `0x0b` = 1 type byte + 5 payload + 5 suffix. That is byte for byte the
record we then recovered from the cube's flash at `0x0007b000`:

```
0b 09 e5 a7 01 8b 01 5f 31 33 32 32        advertises as "\x01\x01_1322"
```

Downstream: the cube no longer advertises a `WCU_MY32` prefix, so the official app
cannot find it, every `namePrefix` filter misses it, and any client deriving the
MAC from fixed offsets in the name rejects it outright.

You can reproduce the whole thing offline with this repo's `crypto.py` — no cube
required.

**It is deterministic.** AES with a fixed key and IV always produces the same
ciphertext, so the same wrong MAC and the same packet corrupt the cube the same
way every time. That is why a repaired cube re-broke identically on the next
connect, and why the junk bytes were bit-for-bit equal both times.

## What client authors should do

1. **Read the MAC from the advertisement.** The cube broadcasts it in
   manufacturer-specific data, reversed. On Python/bleak, Android and desktop
   native you get it free in the scan result. On Web Bluetooth you need
   `watchAdvertisements()` before connecting — the cube stops advertising once
   connected, so the ordering matters.
2. **Confirm the key on the read path before writing anything.** The cube streams
   `0xAB` gyro packets unprompted. Subscribe, wait for one, and check that it
   decrypts to a known opcode. A wrongly decrypted *inbound* packet harms nothing;
   a wrongly encrypted *outbound* one is a command.
3. **If you must guess, guess on reads.** Only the last two MAC bytes are in the
   name and only one byte is genuinely unknown in practice, so it is tempting to
   probe by writing a `0xA1` under each candidate. Every wrong candidate is a
   random command. Prefer waiting for the cube to talk first.
4. **Never ship a real MAC as a default.** "User never opened settings" should be
   an obvious no-op, not a live wrong key aimed at every cube it meets.
5. **Treat a name/MAC mismatch as fatal, not advisory** — and check it even when
   the name looks wrong, since a corrupted cube is exactly when it matters most.

## Caveat

`0xAD` is not in any protocol documentation we have. The "set name" reading is
inferred from an exact fit — opcode, length byte, payload bytes and the resulting
flash record all agree — not from reading firmware. The mechanism (wrong key →
garbage command → flash write) is solid regardless of what `0xAD` is called.
