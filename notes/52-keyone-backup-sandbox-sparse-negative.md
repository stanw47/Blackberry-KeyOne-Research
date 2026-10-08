# notes/52 — Live backup-chain (AAK171) sandbox session: sparse fuzzing negative

Date: 2026-10-09 (evening, live device session)
Device: BBB100-3 `1164118297`, running **backup bootchain AAK171** (April 2017).
Related: notes/49 (write channel), notes/51 (backup sandbox plan), notes/45/46/50
(pre-fix premise + corrections).

## 1. Sandbox established

- Backup chain has full fastboot; `flash tz` (stock no-op) → **OKAY** (writable).
- Command sweep (read-only probes): same authboot walls as ABL766 —
  `oem device-info` / `getvarp:version` / `mmcinfo` / `bootlog` / `console` /
  `read:aboot` / `flashing get_unlock_ability` → `authboot command permission
  denied`; `oem dmesg` / `bootmetrics` / `lks` → `unknown command`.
  No weaker surface in April 2017.

## 2. Sparse-writer fuzzing (live, on `cache`)

Format discovery (from the real ABL766 `system.img` sparse header):

- This bootloader's sparse chunks use **`total_sz = 12 + data`** (chunk header
  included): real chunk0 = `0xCAC1, chunk_sz=1, total_sz=4108`.
  Android-spec images (`total_sz=4096`) are rejected `Bogus chunk size ... Raw`.

Probe matrix (all flashed to `cache`, stock cache restored afterwards):

| probe | result |
|---|---|
| well-formed raw 1 block (+12 convention) | **OKAY** |
| raw `chunk_sz=2` but 1 block of data | `Bogus chunk size ... Raw` (graceful) |
| raw `chunk_sz=1`, 2 blocks of data | OKAY (extra ignored) |
| raw `chunk_sz=0` | `sparse image write failure` |
| FILL correct (total_sz=16) | OKAY |
| FILL total_sz=12 (missing 4 B) | `Bogus chunk size ... FILL` |
| DONTCARE | OKAY |
| CRC chunk (`0xCAC4`) | `Bogus chunk size ... CRC` |

**No hang/crash in any case.** The April-2017 sparse parser is already defensive.

## 3. Static cross-check (AAK399 proxy)

AAK399 aboot already contains:

- `ERROR: Integer overflow in boot image header %s` (5 xrefs in the mmc/boot
  path `0x8f62acfc`…`0x8f62ad7c`; 2 in the flash path `0x8f62bb0c`, `0x8f62bb2c`)
- `Integer overflow detected in bootimage header fields` /
  `... fields %u %s` (`0x8f6d434c`, `0x8f6d4384`)
- `Cannot read boot image header after page size updated` (`0x8f6d3ad4`)

So the overflow guards **pre-date 2018**; the ABL766 delta is a refinement.
The "downgrade → exploit pre-fix parser" premise (notes/45/46/50) is
**downgraded to a hypothesis without support** as of today.

## 4. Session state / hygiene

- `cache` restored to stock (`cache.img` from ABL766 package) → OKAY.
- Nothing else was written; `boot`/`aboot` untouched this session.
- Device still in the backup sandbox; a normal reboot returns to primary
  ABL766 (backup selection is per-boot, key combo).

## 5. Where this leaves the bootloader lane

Remaining candidate surfaces in the sandbox, by expected value:

1. **Token/record parsers** (208-byte `bootsig` written live, parsed at boot or
   in `oem info`; RTAS/nvverify record path). Small, bounded; needs reboot
   cycles into the backup chain (user key combo) — low throughput.
2. **`download:` / fastboot core** on AAK171 (paths partly fuzzed on ABL766;
   no crash found).
3. Accept the documented verdict: **the KEYone boot chain is sound**; the one
   real reachable hole remains KGSL/IOMMU (notes/24–32). The guard-bypass work
   for a KGSL escalation is the more promising research direction than more
   bootloader parser fuzzing.
