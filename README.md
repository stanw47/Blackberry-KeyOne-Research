# BlackBerry KEYone (BBB100-3) — Research

> Boot-chain enforcement, full attack-surface mapping, and a reachable Adreno
> **KGSL/IOMMU kernel vulnerability** on the BlackBerry **KEYone** (Android 7.1.1,
> MSM8953). A permanently-locked, server-authenticated Android phone.
>
> Part of the **[Blackberry-Research](https://github.com/stanw47/Blackberry-Research)**
> collection. Cross-device mechanisms live in the hub; this repo is KEYone-specific.

---

## Disclaimer

> **Research aid, not a flashing guide.** Unlocking bootloaders or flashing
> firmware can **permanently brick** the device. The KGSL PoCs here include a
> **kernel-panic DoS** — run them only on a device you own and can lose. For
> educational / defensive research. **At your own risk.**

---

## Status

| Field | Value |
|---|---|
| Device / model | BlackBerry KEYone (BBB100-3, Sprint/CDMA) |
| SoC | Qualcomm MSM8953 (Snapdragon 625), arm64-v8a |
| OS / build | Android 7.1.1, `NMF26F` / display `ABL766`, patch 2018-12-05 |
| Bootloader | **locked** — LK `aboot` + `authboot` 2.0, secure boot on |
| Root | **none** (`id` = uid 2000 shell; no `su`) |
| Access levels reached | L0 usb, L1 fastboot, L2 adb |
| Status | no software unlock; **reachable KGSL/IOMMU bug (DoS, not yet root)** |

**Current state:** The boot chain is silicon-rooted and server-authenticated; no
software-only unlock or root exists. The one genuine hole is an unpatched
KGSL/IOMMU range-validation bug reachable from an unprivileged `shell` — a
denial-of-service today, with an exploitation path under active analysis.

---

## TL;DR

- **The boot chain is silicon.** PBL (mask ROM) verifies SBL1 against fused
  QFPROM hashes; SBL1 verifies `aboot`; `aboot` verifies boot/recovery.
  Patching `aboot` is rejected by SBL1 (confirmed — it bricks until recovered).
- **`authboot`/RTAS2 gates every privileged command.** Unlocking, token
  provisioning, and protected reads require a signed, server-issued
  authorization from BlackBerry servers that are **dead**.
- **Every peripheral was mapped.** WLAN CVEs fixed; Diag/QMI/TrustZone
  SELinux-gated; Binder/ashmem UAFs neutralised by grsecurity slab isolation.
- **One real hole: Adreno KGSL IOMMU** (`kgsl_iommu_set_svm_region`). `/dev/kgsl-3d0`
  is world-writable (`0666`) and the range validation is missing — **CVE-2020-11261**
  / **CVE-2023-33107** class. Reproduced live from `shell`; currently a DoS.
- **EDL** is the only bypass, needing physical entry + a signed firehose
  programmer (a BlackBerry MSM8953 programmer was extracted from the autoloader).

---

## Key findings

*Numbered, stable — append only. Each links to detail.*

1. **Boot chain is silicon-rooted** — PBL→SBL1→aboot with fused root key;
   `flash.locked=1`, `bbss_wp_type=permanent`, `bbss_insecure=false`.
   → [`notes/23-bootchain-model-and-patch-rationale.md`](notes/23-bootchain-model-and-patch-rationale.md)
2. **`authboot`/RTAS2 command gate** — the whole permission model decoded.
   → [`notes/11-keyone-token-and-rtas2-architecture.md`](notes/11-keyone-token-and-rtas2-architecture.md),
   [`notes/16-keyone-rtas2-protocol-spec.md`](notes/16-keyone-rtas2-protocol-spec.md)
3. **`oem set-factory-mode` is RTAS-gated** — the KEY2-style factory route is closed.
   → [`notes/15-keyone-token-bypass-map.md`](notes/15-keyone-token-bypass-map.md)
4. **Reachable surface map** — WLAN, Diag/QMI, TrustZone, Binder, KGSL.
   → [`notes/21-wcnss-wlan-and-reachable-surface-map.md`](notes/21-wcnss-wlan-and-reachable-surface-map.md)
5. **KGSL/IOMMU vulnerability — CONFIRMED live** (the headline; below).
   → [`docs/KEYone-kgsl-IOMMU-vulnerability.md`](docs/KEYone-kgsl-IOMMU-vulnerability.md)
6. **TCL FOTA (`com.tcl.ota.bb`) runs as system UID** with `RECOVERY`; recovery
   still verifies against BlackBerry's otacerts (valid to 2053).
   → [`notes/tcl-fota-surface.md`](notes/tcl-fota-surface.md)
7. **Autoloader teardown** — extracted the signed MSM8953 firehose programmer +
   symbolized `aboot`. → [`notes/autoloader-teardown.md`](notes/autoloader-teardown.md)

---

## The KGSL / IOMMU vulnerability (headline)

`kgsl_iommu_set_svm_region()` validates only the **endpoints** of a requested GPU
address range against the 8 MB "global" region — it does not validate the
interior, does not check the KGSL SVM range, and has no wraparound guard. These
are **CVE-2020-11261** (exploited in the wild, CISA KEV) and **CVE-2023-33107**.

- Confirmed **verbatim** in BlackBerry's own GPL kernel source
  (`ref/bb-kernel-msm8953-ABY299/`) and reproduced **live on a retail KEYone**
  from an unprivileged `shell` (`/dev/kgsl-3d0` is `0666`).
- **Safe PoC** (`tools/kgsl_bugA_poc.c`): an out-of-SVM address is accepted where
  a patched kernel returns `-ENOMEM`.
- **Corruption/DoS PoC** (`tools/kgsl_global_overlap_poc.c`): a range whose
  endpoints are outside the global region but which spans it is accepted; the map
  overwrites the GPU's global page-table entries and **panics the kernel**.
- Not blocked by grsecurity (the primitive is IOMMU page-table aliasing, not
  slab reuse). Full chain analysis: [`notes/24–31`](notes/).

---

## How to connect

Android device: `adb` (USB `0fca:8042`), `fastboot` (`0fca:8040`). The bootloader
is `authboot`-gated — `fastboot oem device-info` returns
`authboot command permission denied`, but `fastboot getvar all` works.
Shared tooling: hub [`toolchain/`](https://github.com/stanw47/Blackberry-Research/tree/main/toolchain).

---

## Repository layout

| Path | Contents |
|---|---|
| `notes/` | KEYone session notes (numbered `01–31` + the 2026-10 audit) |
| `docs/` | [`KEYone-research-arc.md`](docs/KEYone-research-arc.md), the [KGSL public write-up](docs/KEYone-kgsl-IOMMU-public-writeup.md) + [full technical write-up](docs/KEYone-kgsl-IOMMU-vulnerability.md), [`KEYone-device-map.md`](docs/KEYone-device-map.md) |
| `tools/` | KGSL PoCs (`kgsl_bugA_poc.c`, `kgsl_global_overlap_poc.c`, …), `keyone_unlock.py`, `authboot_client.py` |
| `ref/` | BlackBerry msm8953 `ABY299` KGSL/IOMMU kernel sources |
| `recon/` | live recon (props, partitions, SELinux policy, kallsyms, security libs) + the 2026-10-02 audit |
| `devmaps/` | KEYone device maps (schema v1.0) |
| `firmware/`, `abl/`, `edl/`, `exploit/`, `kernel/` | work areas (firmware not committed) |

---

## Related repos

- **Hub:** [Blackberry-Research](https://github.com/stanw47/Blackberry-Research)
- **KEY2** (the one that *is* unlocked — different ABL stack): [Blackberry-Key2-Research](https://github.com/stanw47/Blackberry-Key2-Research)
- **Priv** (same legacy LK lane): [Blackberry-Priv-Research](https://github.com/stanw47/Blackberry-Priv-Research)

---

## References

| Source | URL | Relevance |
|---|---|---|
| CVE-2020-11261 / CVE-2023-33107 | Qualcomm | KGSL IOMMU range-validation bug |
| Christopher Wade — Breaking Mobile Bootloaders | https://www.qualcomm.com/.../qpss22-christopher-wade.pdf | ABL fastboot overflow (KEY2) |
| CVE-2021-1931 | Qualcomm | KEY2 unlock vector (not KEYone) |
| bkerler/Loaders | https://github.com/bkerler/Loaders | firehose programmers |

---

## License

Research notes and original scripts are provided for educational purposes;
third-party code retains its own license.
