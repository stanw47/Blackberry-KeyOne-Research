# BlackBerry KEYone — Complete Device Map

How the KEYone was fully enumerated with **devmap**, a standardized,
OS-agnostic, access-level-agnostic device-mapping framework. The result is a
single machine-readable map (`devmaps/keyone-bbb100-3.json`) that records
everything visible from USB, fastboot, and an unprivileged ADB shell — and
which level was required to observe each data point.

This article covers the standard, the live KEYone map, and how the same schema
maps BB10/QNX devices (Classic, Passport) for direct comparison.

## Why a standard

Device research tends to produce scattered outputs: `getprop` dumps, `ls` of
this or that, notes in different formats per platform. Comparing two devices —
or the same device across firmware versions — becomes manual diffing.

devmap fixes that with **one schema, many probes, one map per device**:

- Works from whatever access you have: raw USB → fastboot → unprivileged ADB
  → root → QNX/BB10 → EDL.
- A map records the highest level reached and tags data by the level required.
- Missing data means "not visible at this level", not "absent".
- Maps from different OS families (Android, BB10/QNX) normalize into the same
  keys, so they can be diffed.

The full standard lives in [`devmap/STANDARD.md`](devmap/STANDARD.md).

### Access levels

| Level | Name | Transport | What it unlocks |
|-------|------|-----------|-----------------|
| L0 | `usb` | raw USB | VID/PID, interfaces, endpoints, strings |
| L1 | `fastboot` | bootloader | vars, `oem info`, partition sizes |
| L2 | `adb` | unprivileged shell (uid 2000) | props, `/proc`, `/sys`, mounts, services, sockets, device nodes |
| L3 | `root` / `adb-root` | rooted shell | block devices, NVRAM, kernel maps, write primitives |
| L4 | `qnx` | BB10 dev-mode SSH | QNX devctl, `/dev/emmc`, PPS, pathtrust |
| L5 | `edl` | Qualcomm EDL (9008) | raw flash, firehose |

### Schema

One JSON object per device: `identity`, `access`, `hardware`,
`storage_layout`, `boot`, `security`, `surface`, `findings`, plus `provenance`
(live probe vs. corpus import). See the standard for the full field list.

## The KEYone map (live, L0–L2)

Device: **BBB100-3** (Sprint), build **ABL766**, Android 7.1.1, security patch
2018-12-05, MSM8953, serial `1164118297`.

### Identity

```json
{
  "serial": "1164118297",
  "model": "BBB100-3",
  "codename": "bbb100",
  "manufacturer": "BlackBerry",
  "os": {"family": "android", "version": "7.1.1", "build": "ABL766",
         "patch": "2018-12-05"},
  "soc": {"name": "msm8953", "hwid": ""}
}
```

### Access (what an unprivileged shell can see)

```json
{
  "level": "adb",
  "levels_seen": ["usb", "adb", "fastboot"],
  "capabilities": {
    "shell_uid": "uid=2000(shell)",
    "selinux": "Enforcing",
    "block_rw": false,
    "packages": true
  }
}
```

The map is a **merge** of two probes: one while booted (L0+L2) and one in the
bootloader (L0+L1), because a device can only be in one mode at a time.

### Hardware — 20 I2C peripherals

Enumerated read-only from `/sys/bus/i2c/devices/*/name`:

| Peripheral | Role |
|---|---|
| `wsa881x-i2c-codec` ×4 | speaker amps |
| `smb1351-charger` | charging |
| `focaltech_ts` | touchscreen |
| `nq-nci` | NFC controller (PN548) |
| `stmpe-keypad` | keyboard controller |
| `leds-fan5702`, `leds-ktd2026` | LED drivers |
| `adv7533` | HDMI bridge |
| `dsx`, `ohio` | sensors / misc |
| `MSM-I2C-v2-adapter` ×6 | bus controllers |

### Storage & mounts

34 mounts captured; `/system` is `dm-0` dm-verity read-only, `/data` is
`dm-1` encrypted. Boot verification state:

```json
{"verified_boot_state": "", "flash_locked": "1", "dm_verity": "enforcing"}
```

### Surface

- **151 binder services**, **74 unix sockets**.
- **11 device nodes** probed by path (directory listing of `/dev` is
  SELinux-denied for shell, so the probe stats a candidate list):

| Device | Mode | Owner | Significance |
|---|---|---|---|
| `/dev/kgsl-3d0` | 666 | system:system | Adreno GPU — the KGSL IOMMU finding |
| `/dev/binder` | 666 | root:root | binder driver |
| `/dev/ashmem` | 666 | root:root | shared memory |
| `/dev/pathtrust` | 666 | root:root | pathtrust ioctl (fput leak class) |
| `/dev/ion` | 664 | system:system | ION allocator |
| `/dev/adsprpc-smd` | 664 | system:system | ADSP RPC |
| `/dev/ttyHSL0` | 600 | root:root | serial |
| plus `/dev/random`, `/dev/urandom`, `/dev/zero`, `/dev/null` | | | |

### Fastboot (L1)

`oem info` is un-gated even though RTAS commands are not:

```json
{"BSN": "1164118297", "Build": "ABL766", "Product": "bbb100",
 "Variant": "usa", "Subvariant": "sprint", "WP Type": "permanent",
 "Insecure": "false", "Time": "20181127.133122"}
```

32 `getvar` values captured, including `authboot_api_ver: 2.0`,
`hlos-sig-tag: sprint`, `hlos_signature.tkn: NONE`,
`hlos_unsigned.tkn: disabled`, and partition sizes
(`system: 0x120000000`).

### Security gates

| Gate | Blocks |
|---|---|
| authboot / RTAS2 | gated fastboot ops (`erase`, `flash`, `oem getvarp:*`) |
| SBL1 signature verification | unsigned boot chain (fused key) |
| `bbss.insecure` in boot0 | permanently write-protected (`WP Type: permanent`) |
| dm-verity | `/system` modification |
| SELinux enforcing | shell → block devices, `/dev` listing |
| BIDE | section hashing / integrity detection |

## Cross-device: the same schema on BB10/QNX

The framework was exercised against the BB10 corpus (`devmaps/`):

- `classic-sqn100-1.json` — Classic (MSM8960), root + EDL, QNX `pathtrust`,
  hardware eMMC boot write-protect, EDL OS-install seal.
- `passport-sqw100-1.json` — Passport (MSM8974AA), root, PBL debug exploit
  tooling, imggen boot0 build.

Both are marked `provenance.method: corpus-import` so they are never mistaken
for fresh probes. `devmap diff` between them reports the SoC, boot-chain,
partition-layout, and gate differences — the same comparison workflow used for
KEYone vs KEY2.

## Reproducing

```bash
# while booted (L0 + L2)
py tools/devmap.py probe --out devmaps/keyone-bbb100-3.adb.json

# in bootloader (L0 + L1)
adb reboot bootloader
py tools/devmap.py probe --out devmaps/keyone-bbb100-3.fastboot.json
fastboot reboot

# combine into the final map
py tools/devmap.py merge devmaps/keyone-bbb100-3.adb.json \
    devmaps/keyone-bbb100-3.fastboot.json \
    --out devmaps/keyone-bbb100-3.json

# compare any two devices
py tools/devmap.py diff devmaps/keyone-bbb100-3.json devmaps/classic-sqn100-1.json
```

All probes are read-only. The map artifacts are committed under
[`../devmaps/`](../devmaps/).

## What the map enables

- **Surface review at a glance** — which world-writable device nodes exist, which
  services are exposed, which fastboot variables leak state.
- **Firmware-change tracking** — re-probe after an update and `diff` the maps to
  see exactly what changed in the security posture.
- **Cross-platform comparison** — Android vs BB10/QNX on the same keys, without
  translating notes by hand.
- **Finding context** — the KGSL IOMMU DoS
  ([public write-up](KEYone-kgsl-IOMMU-public-writeup.md)) is one line in the
  KEYone map's surface; the map shows what else is reachable at the same level.
