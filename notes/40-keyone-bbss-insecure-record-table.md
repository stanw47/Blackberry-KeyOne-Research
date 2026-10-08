# notes/40 — `bbss_insecure` resolved to a record table (part 1)

Date: 2026-10-08
Follow-up to notes/39. This is the highest-leverage non-corruption path.

## The BBSS/BSI store is a name/ID record table

- `bbss_info_parse` @ `0x8f6547fc`:
  - reads record id `0x87` via `0x8f6045cc` (which indexes a table built by
    `0x8f602b94`; table pointer cached at `0x8f7ac4a4`),
  - looks tags up **by name**: `0x8f63a844(name, default)` →
    `0x8f671640(table, name, default)`;
    writer variant `0x8f63a890` → `0x8f671694`.
- Tags observed parsed at boot:
  - `"bbss_insecure"` (`0x8f6db488`) → if value matches a string constant,
    sets global **`0x8f79488c + 0x18`** (i.e. `0x8f7948a4`) to 1.
  - `"bbss_wp_type"` (`0x8f6db4a8`) → `0x8f79488c + 0x1c` (0/1/2).
  - further tags → rollback counters at `0x8f79488c` and `+4`
    (matching the `"BBSS:%u, SBL:%u, LK:%u, SBLR:%u, LKR:%u"` logger at
    `0x8f654678`).
- Record values parsed with `0x8f671500` (numeric, bounded `<= 0xFF`).

## Why it matters (gating evidence)

- `"Ignoring auth failure on insecure device"` (`0x8f6e1268`) is referenced
  **inside the token/signature parser** at `0x8f653d60` — i.e. when the
  insecure flag is set, signature/auth failures are tolerated.
- `"Insecure bootchain detected. Skipping fuse verification check"`
  (`0x8f6e0f60`) at `0x8f64b4a8` — fuse-verification skip in insecure mode.

So: **`bbss_insecure=true` relaxes image authentication at boot.** If that
record can be written (or the global `0x8f7948a4` set via any primitive), an
unsigned/patched boot image can be loaded.

## Open questions (next)

1. What backs the record table? Trace `0x8f602b94` and the partition/file it
   reads (`"Unable to find BBSS partition"` @ `0x8f6dc15c` suggests a
   partition; candidate: `sec`/`oem`/`persist`, or RPMB via TZ).
2. Is the write path (`0x8f63a890`) PMT/RPMB-protected? If the store is plain
   flash, EDL or root can flip `bbss_insecure` directly — no memory
   corruption needed.
3. Does insecure mode also relax the RTAS `flash:` gate, or only image
   verification? (audit `authboot_check_permission` for insecure-state
   short-circuits).

## Relation to the exploit plan

- Memory-corruption route: any write primitive in aboot → write `1` to
  `0x8f7948a4` (or patch the branch at `0x8f653d60`) → boot unauthenticated.
- Data route: flip the backing record → same effect, persistent.
- Either way this avoids needing to defeat the P-521 image signatures.

## BIDE/ECC diff (from notes/39, status)

- The new AAL093 messages live in a quoted message table without direct
  movw/movt refs; locate the pointer table to map the consumer functions.
- AAK399 lacks them → weaker validation baseline; candidate for a
  downgrade-then-exploit strategy (KEY2/kibo model).
