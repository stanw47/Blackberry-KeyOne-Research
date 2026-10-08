# notes/35 — KEYone unlock-denial archaeology: AAL093 / AAN355 / ABL766

Date: 2026-10-08
Target: `emmc_appsboot.mbn` (LK aboot) from three signed retail builds.

## Builds compared

| Build | Date (package) | aboot size | sha256 (short) |
|---|---|---|---|
| AAL093 (first OTA, `user-common`) | 2017-05-05 | 1,925,631 | `2514B7B79B0436C4…` |
| AAN355 (Aug SMR, `alldevices`) | 2017-08-07 | 1,949,815 | `4FF3615E80C3F088…` |
| ABL766 (Sprint 7.1.1, `Hn03`) | 2018-07 | 1,952,062 | `14F90B3C1CF2EE84…` |

## Result: the unlock-denial is present in ALL of them

`set_device_unlock` (r0=type, r1=value):

| Build | function VA | deny path |
|---|---|---|
| AAL093 | `0x8f62c194` | `cmp r1,#0` → `bne` → `"oem unlock is not allowed"` (`0x8f6d4834`) |
| AAN355 | `0x8f62c1cc` | same logic, `"…not allowed"` (`0x8f6d73e0`) |
| ABL766 | `0x8f62c484` | same logic, `"…not allowed"` (`0x8f6d7954`) |

- `cmd_oem_unlock` calls `set_device_unlock(0,1)` → always denied on a locked unit.
- `cmd_oem_unlock_go` only proceeds if `devinfo+0x10` (is_unlocked) is already 1.
- Only `r1 == 0` (locking) ever reaches the `write_device_info` worker.

## The verification-skip path is dead in the retail line

`"Device is unlocked! Skipping verification..."` exists as a string in all three
builds but has **zero literal references** (movw/movt scan and full dword scan,
`lk_analyze.py`). AAL093 → AAN355 → ABL766 never grew a consumer. Retail
verification does not consult the unlock flag via that path — the "unlock state
relaxes verification" behaviour lives in engineering builds, not these.

## Other findings

- Sparse-header validation (`"buffer overreads occured due to invalid sparse
  header"`) is present in **all three** builds — it is a QTI-inherited check,
  not a later BlackBerry fix. Not a regression-window bug marker.
- `bbss_insecure` machinery (readers + `"Unable to update bsi bbss_insecure"`
  writers) is present in all three builds (writer cluster stays adjacent to the
  WP manager; AAL093 `0x8f652bbc`–`0x8f652de4`, AAN355 `0x8f654484`–`0x8f6546ac`,
  ABL766 `0x8f654848`–`0x8f654a70`).
- Function layouts are stable; deltas are small function-body edits/compiler
  shifts between 2017-05 and 2018-07 (≈26 KB total aboot growth).

## Conclusions

1. **No evidence a retail build was ever unlockable via `oem unlock`.** The
   denial exists in the first public update (AAL093, 2017-05-05), the August SMR
   (AAN355) and the 2018 Sprint build (ABL766). The community claim "was
   unlockable before it got a patch" is unsupported for AAL/AAN/ABL.
2. Remaining data point to fully close it: the **launch builds (AAK399/AAK879,
   April 2017)** — packages exist on the same mirror. If AAK also denies, the
   claim is engineering-unit / KEY2 confusion.
3. Any unlock via software still requires a **memory-corruption primitive in
   aboot** to (a) patch the deny branch / call the writer, or (b) attack the
   `bbss_insecure` state. Because the skip-verification consumer is dead in
   retail code, persistence semantics must be confirmed before promising
   custom-ROM boots.

## Tooling

- `tools/lk_xref.py` — string xrefs (movw/movt) in MBN-wrapped aboot.
- `tools/lk_disasm.py` — annotated region disassembler (new, committed with
  this note).
- `tools/lk_analyze.py` — string + literal-pool scan.

Artifacts (local, gitignored): `firmware/keyone-aal093/`, `firmware/keyone-aan355/`,
`firmware/keyone-abl766/`.
