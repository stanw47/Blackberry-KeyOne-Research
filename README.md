# BlackBerry KEYone (BBB100-3) — Research

> Boot-chain enforcement, full attack-surface mapping, and a reachable Adreno
> **KGSL/IOMMU kernel vulnerability** on the BlackBerry **KEYone** (Android 7.1.1,
> MSM8953) — a permanently-locked, server-authenticated Android phone.
>
> Part of the **[Blackberry-Research](https://github.com/stanw47/Blackberry-Research)**
> collection · [Williamson Security Solutions](https://williamsonsecuritysolutions.com)

---

## Disclaimer

> **Research aid, not a flashing guide.** Unlocking bootloaders or flashing
> firmware can **permanently brick** the device. The KGSL PoCs here include a
> **kernel-panic DoS** — run them only on a device you own and can lose. For
> educational / defensive research. **At your own risk.**

---

## Device Details

| Field | Value |
|---|---|
| Model | BlackBerry KEYone **BBB100-3 V015** |
| Codename | `bbb100` / "Mercury" |
| SoC | Qualcomm **MSM8953** (Snapdragon 625), arm64-v8a |
| OS / software | **Android 7.1.1** |
| Current build | `NMF26F` / display **`ABL766`**, patch 2018-12-05 |
| Previous builds | (Sprint/CDMA variant never received Oreo) |
| Carrier / unlock | **Sprint (CDMA)**; carrier-locked; bootloader locked |
| SIM | single |

---

## Current Status

The boot chain is **silicon-rooted and server-authenticated** — no software-only
unlock or root exists. The one genuine hole is an **unpatched KGSL/IOMMU
range-validation bug** reachable from an unprivileged `shell`: a **denial of
service** today, with an exploitation path under analysis.

---

## Completed

- **Boot-chain model** — PBL->SBL1->aboot with fused root key; a patched `aboot`
  is rejected by SBL1 (inferred from the Priv eMMC incident, where a patched
  `aboot` bricked the device until recovered — not directly tested on the
  KEYone). The `flash` write path is **per-partition**: boot/recovery/bootchain
  accept arbitrary bytes pre-auth, but all images are ECDSA-verified at boot
  (notes/49).
- **`authboot`/RTAS2 protocol** — full command-permission model decoded.
- **Reachable-surface map** — WLAN, Diag/QMI, TrustZone, Binder, KGSL.
- **KGSL/IOMMU bug** — confirmed live from `shell` (safe + corruption PoCs).
- **Autoloader teardown** — signed MSM8953 firehose programmer + symbolized `aboot`.
- **TCL FOTA analysis** — system-UID OTA agent; recovery trust anchor.

## Achieved

- **KGSL/IOMMU bug reproduced live** (CVE-2020-11261 / CVE-2023-33107 class)
  from unprivileged `shell` — safe PoC accepted an out-of-SVM address.
- **Kernel panic primitive** — global-region overlap overwrites the GPU's
  global page-table entries.
- **Signed firehose programmer extracted** from the official autoloader (EDL-ready).
- **`devinfo` unlock byte mapped** (offset `0x10`).

## In Progress

- **KGSL kernel R/W.** Turning the DoS primitive into a controllable read/write
  to reach root. [`notes/24–31`](notes/)

## Failed

- **Software unlock** — `authboot` denies every privileged command; `oem
  set-factory-mode` is RTAS-gated; `oem unlock` is not even whitelisted.
- **Patching `aboot`** — rejected by SBL1's re-verification (mechanism; the brick
  was observed on the Priv, not directly on the KEYone).
- **Binder/ashmem UAFs** — neutralised by grsecurity slab isolation.
- **WLAN CVEs** — status unresolved: [`notes/21`](notes/21-wcnss-wlan-and-reachable-surface-map.md)
  reports CVE-2019-10526 unpatched (and the best remaining LPE candidate), while
  [`notes/23`](notes/23-bootchain-model-and-patch-rationale.md) claims the fix is
  present. See [`notes/22`](notes/22-wlan-cve-2019-10526-status.md).
- **EDL by software** — no software trigger; entry is hardware-only.

## Future Plans

1. Complete the **KGSL exploitation chain** root.
2. Or **physical EDL** (test points) patch `devinfo` unlock.

---

## Community Activity

- **No public unlock or root.** XDA threads exist ("Unlock Blackberry Keyone
  (AT&T)") but there is no retail method; the community reaches only **debloat**,
  **FRP bypass**, and stock restore.
- **TWRP 3.2.1** exists for the KEYone but only runs on
  **engineering/factory-unlocked** units - not retail.
- **Sugar QCT** (an Alcatel/TCL OS-flash tool) can reload stock firmware; the
  BBB100-3 product model is **63118**.
- Custom ROMs: **none stable**; the community focuses on de-Googling/debloat,
  and an enthusiast "Frankenstein" revival has been discussed.
- The KGSL/IOMMU class (CVE-2020-11261) is publicly known and was exploited in
  the wild on other MSM8953 devices.

## Repository layout

| Path | Contents |
|---|---|
| `notes/` | KEYone session notes (`01–31` + the 2026-10 audit) |
| `docs/` | [research arc](docs/KEYone-research-arc.md), [KGSL public write-up](docs/KEYone-kgsl-IOMMU-public-writeup.md), [KGSL full technical](docs/KEYone-kgsl-IOMMU-vulnerability.md), [device map](docs/KEYone-device-map.md) |
| `tools/` | KGSL PoCs (`kgsl_bugA_poc.c`, `kgsl_global_overlap_poc.c`, …), `keyone_unlock.py`, `authboot_client.py` |
| `ref/` | BlackBerry msm8953 `ABY299` KGSL/IOMMU kernel sources |
| `recon/` | live recon (props, partitions, SELinux policy, kallsyms) + 2026-10 audit |
| `devmaps/` | KEYone device maps (schema v1.0) |
| `firmware/`, `abl/`, `edl/`, `exploit/`, `kernel/` | work areas (firmware not committed) |

---

## Related repos

- **Hub:** [Blackberry-Research](https://github.com/stanw47/Blackberry-Research)
- **KEY2** (the one that *is* unlocked — different ABL stack): [Blackberry-Key2-Research](https://github.com/stanw47/Blackberry-Key2-Research)
- **Priv** (same legacy LK lane): [Blackberry-Priv-Research](https://github.com/stanw47/Blackberry-Priv-Research)

---

## Citations & Acknowledgements

| Source | URL | Relevance |
|---|---|---|
| Qualcomm | CVE-2020-11261 / CVE-2023-33107 | KGSL IOMMU range-validation bug |
| Christopher Wade — Breaking Mobile Bootloaders | https://www.qualcomm.com/.../qpss22-christopher-wade.pdf | ABL fastboot overflow (KEY2) |
| bkerler / Loaders | https://github.com/bkerler/Loaders | firehose programmers |

---

## License

Research notes and original scripts are provided for educational purposes;
third-party code retains its own license.
