# notes/51 — Aboot downgrade attempt (negative) + backup-chain sandbox pivot

Date: 2026-10-09 (evening)
Device: BBB100-3 `1164118297`. Related: notes/37 (ARB), notes/43 (backup
bootchain), notes/49 (write channel), notes/50 (pre-fix parser groundwork).

## Attempt

1. Baseline: Primary ABL766, Backup AAK171, device healthy (Android setup,
   USB debugging on).
2. Flashed **AAN355 `emmc_appsboot.mbn`** to the primary `aboot` partition via
   packaged fastboot → `OKAY`; oracle confirmed byte-exact (`bf9ac5e7…`).
3. Reboot → **primary boot refused** (no Android, no usable primary state);
   the device had to be started in the **backup bootchain manually**
   (POWER+VOL_UP, per user). Not an automatic fallback.
4. While running the backup chain: `oem info` shows **Backup Version: AAK171**
   (no Primary line); `oem parthash` → `unknown command` (AAK171 predates it;
   AAN355/ABL766 both contain the string — handy build fingerprint).
5. Recovery: from the **backup fastboot**, `flash aboot <ABL766 emmc_appsboot.mbn>`
   → `OKAY` (backup chain can write the primary partitions). Reboot → Android
   up; `oem info` shows **Primary Version: ABL766** again.

## Conclusions

- **aboot-only downgrade is blocked** (SBL1/boot-chain version enforcement —
  consistent with notes/37's ARB/version model). Do not repeat ad hoc.
- **Recovery net verified end-to-end**: backup bootchain = manual entry,
  full fastboot, can reflash the primary chain. Primary writes from backup
  work.
- **Better route found — use the backup bootchain as the vulnerable sandbox:**
  AAK171 (April 2017) is a *runnable, writable* pre-fix aboot. The device stays
  on ABL766 primary between sessions; for exploit sessions the user enters
  backup mode (POWER+VOL_UP) and we run the vulnerable parser there.
  Writes from backup land in the shared (primary) partitions — recover by
  reflashing stock from the same backup fastboot.
- **Static proxy**: AAK399 (April 2017, retail sibling of the backup era) is
  preserved locally; bindiff evidence saved at
  `recon/bindiff-aak399-vs-abl766.txt` (2062 vs 2082 fns, 1983 identical,
  79/99 divergent). AAK399 lacks `parthash` too — consistent with AAK171.

## Revised exploit plan (downgrade lane → backup-sandbox lane)

1. **Offline**: map the AAK399 flash-writer parser (sparse + boot-image write
   paths; pre-fix counterparts of AAN355 `0x8f62d43c`/`0x8f62d9ac` and
   ABL766 `0x8f62d728`/`0x8f62ddb4`) and reconstruct a minimal crash/control
   input.
2. **Live session** (user enters backup mode): flash crafted input to a
   scratch partition (`oem`/`cache`/`userdata` class permitted per notes/49;
   `persist` gated) via the backup fastboot; observe crash behaviour
   (hang/reset = parser hit); recover by reflashing stock.
3. Only if a controllable primitive appears: escalate to the boot/verification
   path; keep primary ABL766 flashable at all times.

## Do-not

- Do not flash an older `aboot` to the primary again without a full-chain
  plan; manual backup entry is required to recover.
- Do not flash `sbl1` from old packages as a probe (untested refusal class;
  PBL-level risk).
