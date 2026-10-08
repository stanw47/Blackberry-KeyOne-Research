# notes/45 — Function-level bindiff: the 2017→2018 fix list (kibo-style oracle)

Date: 2026-10-08
Tool: `tools/lk_bindiff.py` (function-boundary discovery via branch targets +
normalized disassembly fingerprints; string-refs annotated).

## Result: AAN355 (2017-08, vulnerable era) vs ABL766 (2018-07)

- A: 2078 functions, B: 2082 functions
- **2023 identical** (same fingerprint modulo addresses)
- only-in-A: 55 (functions changed/removed), only-in-B: 59 (changed/added)
  → ~2.6% of the bootloader differs; the delta set is small and readable.

## Security-relevant changed functions (A address/size → B address/size)

| Function (by refs) | AAN355 | ABL766 | Δ |
|---|---|---|---|
| Sparse image write | `0x8f62d43c` (408) | `0x8f62d728` (440) | +32 |
| Boot image load/parse (`Invalid boot image header/pagesize`) | `0x8f62b914` (972) | `0x8f62bb94` (1012) | +40 |
| Boot image verify (`No sig partition`) | `0x8f62ac44` (812) | `0x8f62aed4` (812) | = |
| Uncompress/patched-kernel detect | `0x8f62a948` (764) | `0x8f62abd8` (764) | = |
| Flash/write path (`writing %d bytes to '%s'`) | `0x8f62d9ac` (736) | `0x8f62ddb4` (620) | −116, **adds `Verified the BOOT_MAGIC in image header`** |
| Kernel/ramdisk load | `0x8f62b454` (584) | `0x8f62b6f8` (592) | +8 |
| ANDROID-BOOT! bootstate | `0x8f62b69c` (544) | `0x8f62b948` (544) | = |
| MEID/BBSS info (`bbss_antirollback`, `msm_id`) | `0x8f6321b8` (548) | `0x8f6324a4` (764) | **+216** |
| Bootchain Software info | `0x8f631db0` (292) | `0x8f63217c` (292) | = |
| Recovery command | `0x8f62fd78` (320) | `0x8f63010c` (352) | +32 |
| — new in B | — | `0x8f617944` `Qseecom Init Done in Appsbl` | new |
| — new in B | — | `0x8f62cf88` `Cannot flash: image size mismatch` | new |
| — new in B | — | `0x8f62dc28` (`ANDROID!`,`recovery`) | new |

Notes:
- The `Command line length is %d, maximum is %d` check exists in **all**
  builds (AAK399/AAL093/AAN355/ABL766) — not the CVE fix.
- The changed set maps naturally onto **CVE-2018-5854** (“stack-based buffer
  overflow in fastboot”, June 2018 CAF bulletin, CWE-787, no auth needed):
  the 2018 build adds validation (`BOOT_MAGIC`, image size mismatch) in the
  flash/image path, and reworks sparse/boot-image parsing.
- Old builds are unaffected: AAK399/AAL093/AAN355 carry the pre-fix code and
  are **signed + downgradeable** → the kibo playbook (downgrade → exploit)
  has concrete targets.

## Next

1. Instruction-level diff of the top pairs (sparse write, boot image load,
   flash path) to extract exactly what check was added — each one is a
   vulnerability hypothesis for the 2017 builds.
2. Confirm the same deltas exist between AAK399/AAL093 and ABL766 (run the
   bindiff pairwise).
3. Fuzz the corresponding host-controlled inputs (sparse header fields,
   image header fields, flash sizes) against a downgraded build with the raw
   USB harness.
