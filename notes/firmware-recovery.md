# KEYone BBB100-3 (Sprint) — firmware / unbrick insurance

Keep a **known-good stock autoloader** on hand before any bootloader/EDL
experimentation. Autoloaders are TCL/BlackBerry-signed factory images + a
`flashall` script; they restore the device even from a soft-brick and reset FRP.
BlackBerry's own download portal shut down in 2022, so only community mirrors
remain.

## Our target
- Model **BBB100-3**, subvariant **sprint**, product `bbb100usasprint`
- Current build **ABL766** (Android 7.1.1, patch 2018-12-05)
- Sprint CDMA units never received Oreo.

## Known BBB100-3 / Sprint images (from research)
| Name | Notes | Source |
|---|---|---|
| `RomKEYoneSprintGoc.drtiendiep-018` | Sprint-branded ROM | HalabTech `id=129132` |
| `bbry_qc8953_autoloader_user-all-AAS212.7z` | "all" variant autoloader | AndroidFileHost Jcrutchvt10 |
| `bbry_qc8953_autoloader_user-all-*` | generic all-device autoloaders (AAN355/AAM481/AAO472/AAO548/AAN358…) | HalabTech / AFH |
| `ABT974.7z`, `ABG366.7z`, `AAX863Universal.7z`, `AAV222.7z` … | later universal builds | AFH `?flid=204896` |
| `black-berry-key-one` item | firmware + apps + user guides | archive.org |

Autoloader contents typically: signed partition images (aboot/abl, sbl1, rpm,
tz, modem, boot, system, …), a Windows `fastboot` binary, and
`flashall.bat`/`.sh`.

## Important
- Firmware is only compatible **within the same model** (BBB100-3). Flashing a
  different model's image can brick / lose radio.
- Remove Google account + screen lock before flashing to avoid FRP lock.
- **No confirmed Linux autoloader** historically; community `flashall.sh`
  derivatives exist. Keep a Windows box or Wine handy.

## To do (when needed)
- [ ] Download an exact BBB100-3 / AAS212 (or ABL766-era) autoloader and store
      under `keyone/dumps/firmware/` (verify hash).
- [ ] Extract and inventory the images (esp. `abl`/`aboot`, `sbl1`).
- [ ] Check autoloader for any `prog_emmc_firehose_8953*` / firehose programmer
      (would unlock the EDL route).
