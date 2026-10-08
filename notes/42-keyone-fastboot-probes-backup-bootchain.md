# notes/42 — Fastboot pre-auth probes: backup bootchain AAK171 + gptinfo wedge

Date: 2026-10-08
Experiment #3 (pre-auth fastboot surface) — first pass.

## What was probed (all on the live BBB100-3, serial 1164118297)

- `fastboot getvar all` (saved): `version:0.5`, `bootmode:PRODUCT_MODE`,
  `gpt_version:0x0005`, `max-download-size:0x20000000`,
  `variant:usa`, `subvariant:sprint`, `product:MSM8953`,
  battery/voltage/off-mode-charge readable.
- `fastboot oem device-info` → clean denial
  `authboot command permission denied` (not whitelisted, fast-fail).
- `fastboot oem info` → **allowed pre-auth** and leaks state (see below).
- `fastboot oem gptinfo` → **hangs the USB interface** (see below).

## Discovery 1 — factory **backup bootchain AAK171**

`oem info` (live):

```
Bootchain Software:
 Primary Version: ABL766
 Backup Version:  AAK171        <-- factory backup bootchain, April 2017
Security:
  Insecure:  false
  WP Type:   permanent
Hardware Information:
  Product: bbb100  Variant: usa  Subvariant: sprint
Product Identifiers: PIN 0x2c48d4c8, BSN 1164118297 (IMEI/MEID redacted)
HLOS boot image: Type sfi  Build ABL766
```

- The unit carries an **older backup bootchain (AAK171)** — pre-dates AAK399
  (2017-04-28) and likely lacks the BIDE/ECC validation added in AAL093.
- aboot contains `"Backup bootchain: booting to fastboot mode"`; the community
  Lua documents `POWER+VOL_UP` as the backup-bootchain entry.
- This is a physical, user-actionable target: boot the backup chain and
  interrogate *its* bootloader (`oem info`, `getvar all`,
  `flashing get_unlock_ability`) — a different, older image with possibly
  weaker validation. Where it is stored (hidden partition) is open; the `bbss`
  hidden partition (notes/41) and the BSI tags are candidates.
- `Insecure: false` confirms the BSI flag is live-readable and the insecure
  mode is off in retail.

## Discovery 2 — `oem gptinfo` wedges fastboot (DoS-class)

- First `oem gptinfo` invocation: `AdbWriteEndpointSync failed: semaphore
  timeout (121)`.
- Afterwards **all** fastboot commands fail the same way (even `oem info`,
  `fastboot reboot`); enumeration (`fastboot devices`) still succeeds.
- Device must be reset physically (hold Power ~15 s).
- Interpretation: the RTAS-gated command path (type 3 → RTAS 0x1001) enters a
  state where the USB bulk endpoint stops servicing — a hang in a privileged
  command handler. Candidate denial-of-service bug; retest with the raw-libusb
  harness to characterise (hang vs crash, recoverability, which command classes
  trigger it).

## Status / next

- `getvar all` baseline saved at `%TEMP%\opencode\keyone-fb\getvar-all.txt`.
- Next experiments:
  1. Boot the **backup bootchain** (POWER+VOL_UP) and run the same read-only
     probes + `flashing get_unlock_ability` there.
  2. Characterise the `gptinfo` wedge (raw libusb; test adjacent RTAS types).
  3. Continue AAK→AAL code diff (structural function diff; the new BIDE
     messages are not absolutely referenced, likely a log-string blob).
