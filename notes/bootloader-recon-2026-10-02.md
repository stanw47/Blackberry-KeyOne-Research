# KEYone BBB100-3 bootloader recon — 2026-10-02

Device: BBB100-3, `bbb100usasprint`, build ABL766, PRD-63118-003.
Entered fastboot via `adb reboot bootloader` (worked). Raw log:
`keyone/dumps/2026-10-02/fastboot-recon.txt`.

## What fastboot revealed

`fastboot getvar all` **works** (read-only) despite authboot. Full dump:

| var | value | meaning |
|---|---|---|
| product | `MSM8953` | SoC confirmed |
| kernel | **`lk`** | bootloader is **Little Kernel**-based `aboot` (not UEFI ABL) |
| bootmode | **`PRODUCT_MODE`** | not factory mode |
| authboot_api_ver | **`2.0`** | authboot token API version |
| security | **`enabled`** | secure boot on |
| is-password-set | `no` | no device unlock password set |
| hlos_unsigned.tkn | **`disabled`** | — |
| hlos-sig-tag | `sprint` | carrier signing tag |
| hlos_signature.tkn | `NONE` | — |
| subvariant / variant / device | `sprint` / `usa` / `bbb100` | |
| prd | **`PRD-63118-003`** | precise product variant |
| jdm_bsn | `AAKH11BPDKA00VV` | board serial |
| gpt_version | `0x0005` | |
| partition oem | 0x20000000 (512 MB) ext4 | |
| partition cache | 0x40000000 (1 GB) ext4 | |
| partition system | 0x120000000 (4.5 GB) ext4 | |
| partition userdata | 0x5a7bfbe00 (~24 GB) ext4 | |

## What is DENIED (the authboot wall, confirmed live)
```
fastboot oem device-info          -> FAILED (remote: 'authboot command permission denied')
fastboot oem device-info preflash -> FAILED (authboot command permission denied)
fastboot oem gptinfo              -> FAILED (authboot command permission denied)
fastboot flashing get_unlock_ability -> FAILED (authboot command permission denied)
fastboot oem lks                  -> FAILED (remote: 'unknown command')
fastboot getvar unlocked/secure/version-bootloader -> empty (no value)
```

## Analysis
- The bootloader is **LK/aboot** (`kernel:lk`) — same family the KEY2 work
  targets. `authboot_api_ver 2.0` + `security:enabled` are the gates.
- We are pinned to **PRODUCT_MODE**; the KEY2 CVE-2021-1931 path needed
  **FACTORY_MODE** + a modded boot image. `oem set-factory-mode` is authboot-
  denied. This is the exact wall.
- `hlos_unsigned.tkn: disabled` / `hlos_signature.tkn: NONE` are worth
  understanding — they relate to whether an unsigned HLOS token is accepted.
- Getvars are an information win but do not unlock anything.

## Next probes (still read-only) when in fastboot
- `fastboot getvar all` variants: `getvar token`, `getvar slot`, `getvar
  serialno`, `getvar partition-type:*`.
- Try benign `fastboot oem` commands known to be read-only if any are not gated
  (e.g. `oem cpu`, `oem rsn`) — most will be `unknown command`/denied.
- Do **NOT** run `oem unlock`, `oem set-factory-mode`, `flash`, or `erase`.
