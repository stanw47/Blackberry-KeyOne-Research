# KEYone — WCNSS/WLAN deep-dive + complete reachable attack-surface map

Date: 2026-10-04
Related: notes/20 (hardware inventory), notes/16 (RTAS2), notes/19 (kernel).

================================================================================
PART A — WLAN / WCNSS DRIVER (the standout reachable surface)
================================================================================
Driver module: `/system/lib/modules/pronto/pronto_wlan.ko` (6,326,836 bytes),
symlink `/system/lib/modules/wlan.ko`. Loaded (`wlan` in /proc/modules).
- Family: **Qualcomm QCA "prima"/"pronto" WLAN** = qcacld-2.0 lineage
  (source path baked in: `vendor/qcom/opensource/wlan/prima/...`).
- Host SW version string: **`3.0.11.66`**.
- HW: **WCN36xx / IRIS** (WCN3680B or WCN3660B) — version banner template
  `Host SW:%s, FW:%s, HW:%s, IRIS_HW:%s`.
- vermagic: `3.18.31-perf-gf38c8fb SMP preempt mod_unload modversions
  aarch64 REFCOUNT GRSEC` — **module itself compiled with grsec REFCOUNT**.
- Present handlers (classic vulnerable HDD surface):
  `wlan_hdd_cfg80211_testmode`, `__wlan_hdd_cfg80211_testmode`,
  `wlan_hdd_cfg80211_start_ap`, `wlan_hdd_cfg80211_change_bss`,
  `wlan_hdd_cfg80211_scan`, `wlan_hdd_setIPv6Filter`, `wlan_hdd_hostapd`,
  `wlan_hdd_wext`, `wlan_hdd_ftm`, plus full P2P/NAN/vendor-attr (QCA_WLAN_VENDOR)
  paths.
- Module params (/sys/module/wlan/parameters): `con_mode` (FTM switch),
  `country_code`, `enable_11d`, `enable_dfs_chan_scan`, `fwpath`, `ioctl_debug`.
  All root:root 0644, SELinux `sysfs` -> **shell cannot write** (verified:
  `echo 1 > con_mode` => Permission denied).

### Known CVEs matching THIS build (patch level 2018-12-05 => post-2018 open)
- **CVE-2019-10526** — "Out of bound write in WLAN driver due to NULL character
  not properly placed after SSID name". Affected list **explicitly includes
  MSM8953, QCA6174A**. Fixed March-2020 bulletin. **UNPATCHED here.**
- CVE-2018-5834 / CVE-2018-5862 — buffer overwrite in
  `__wlan_hdd_cfg80211_vendor_scan` (SCAN_SSIDS / SCAN_FREQUENCIES parsing).
  Patched 2018-06/07 -> already fixed in a 2018-12 build.
- CVE-2017-0441 / CVE-2016-8421 — Qualcomm Wi-Fi driver EoP (kernel 3.10/3.18).
  Older; likely fixed by Dec-2018.
- CVE-2020-11116/11117/11118 (WLAN HOST), CVE-2020-3667/3668/3669/3675 (WLAN
  Firmware), CVE-2020-3702 "Krook", CVE-2019-14114 (WLAN fw GTK IE overflow,
  QCA6174A listed) — all **post-Dec-2018 => nominally open**, but many target
  WLAN **firmware** (remote) or newer host code paths not clearly in 3.0.11.66.
- CVE-2019-14074 — "Heap overflow in diag command handler" (Core Services) — see
  Part C (diag is gated).

### Reachability of the WLAN driver from shell
- netdevs `wlan0` + `p2p0` exist (state DOWN/DORMANT, but ioctls live).
- A local app *can* open a NETLINK_GENERIC cfg80211/nl80211 socket and issue
  vendor commands / scan requests -> enters `wlan_hdd_cfg80211_*`. This path is
  reachable by an **unprivileged app** (requires location/wifi permissions,
  which shell/uid 2000 or an installed app can hold).
- The FTM conduit (`con_mode`) is **root/SELinux gated**, so raw test-mode is not
  directly reachable.
=> The WLAN cfg80211/nl80211 host handlers remain the **most plausible reachable
   kernel attack surface**, with a documented MSM8953-affecting OOB write
   (CVE-2019-10526) still open. (Would need a matching public/derived PoC;
   grsec REFCOUNT makes exploitation harder but the module's own build is not
   full-grsec-isolated.)

================================================================================
PART B — COMPLETE shell-reachable surface inventory (uid 2000, SELinux enforcing)
================================================================================
Groups of shell: shell, input, log, adb, sdcard_rw, sdcard_r, **devicepwd,
token_service_native_consumer, mfg_client(x2)**, net_bt_admin, net_bt, inet,
net_bw_stats, readproc.

### READABLE / USABLE by shell
- adb, /data/local/tmp, /sdcard, logcat, getprop, dumpsys (partial).
- `mfgUtil` READ commands exist but are **blocked**: "Device not running in
  production but options requested require it" (inproductionflag=false;
  clearInProductionFlag is one-way to false => already off => dead end).
- AF_PACKET (raw/protocol) sockets — but no CAP_NET_RAW; net_bt_admin group only.
- NETLINK sockets (45 open) — cfg80211/nl80211 reachable => WLAN handlers.
- Reading many /proc entries, /proc/kallsyms (names, addr=0), dmesg (restricted).

### DENIED to shell (SELinux / DAC) — the hard walls
| target | denial | gate |
|--------|--------|------|
| `/dev/socket/bbauthtool` | avc getattr denied | `bbauthtool_socket` type |
| `/dev/socket/tokenservice` | avc getattr denied | `token_service_socket` type |
| `/dev/socket/tctd`, `nims`, `pps` | DAC/SELinux | perms |
| `/dev/diag` | **EACCES (13)** when `tct-diag`/`mmi_diag` open it | needs `qcom_diag` gid (3009), shell lacks |
| `/dev/qseecom` | tee_device | root/drmrpc |
| `/dev/ion`, `/dev/adsprpc-smd` | 0664 system | root/system |
| `/sys/module/wlan/parameters/*` write | SELinux sysfs | root |
| `/dev/block/*`, `/nvram/nvuser`, `/dev/pathtrust`, `/dev/bide` | SELinux | root |
| `/sys/kernel/debug` | DAC | root |
| any `/sys` writable node | none found writable by shell | - |

### Shell-executable binaries of interest
- `mfgUtil` — manufacturing queries; production-gated (dead).
- `mmi_diag`, `tct-diag`, `diag_callback_sample` — use `libdiag.so`; both fail
  `Diag_LSM_Init: error = 13` (diag driver EACCES). Dead from shell.
- `wcnss_service`, `wcnss_filter`, `sensors.qcom`, `mm-qcamera-daemon`,
  `subsystem_ramdump`, `imsqmidaemon` — root/system daemons, not shell-runnable.

### The on-device RTAS2 daemon (NEW)
- `/dev/socket/bbauthtool` (seqpacket) — the **bbauthtool daemon runs on the
  Android side** and exposes the RTAS2 auth protocol; only the
  `bbauthtool` SELinux domain (root daemon) can connect.
- `/dev/socket/tokenservice` — token daemon; root-gated (per Priv notes).
=> RTAS2 is present at runtime, not only in the bootloader, but both sockets are
   SELinux-isolated from shell.

================================================================================
PART C — DIAG / QMI / MODEM reachability
================================================================================
- DIAG char device (241) `/dev/diag` exists, gid `qcom_diag` (3009); shell NOT a
  member -> `EACCES`. The TCL/MMI diag tools are shell-executable but cannot open
  the channel. Historical diag CVEs (CVE-2019-14074 heap overflow) require the
  diag handle = **not reachable from shell**.
- QMI via `/dev/socket/qmux_radio/*` (rild, uim, ims) — owned rild/system.
- Modem <-> AP via SMD (`/dev/smd*`) and `rmnet_*` netdevs; all system-gated.
- IPA (`/dev/ipa`, ipacm) — system.

================================================================================
PART D — Autoloader findings (WCNSS/NV/token paths)
================================================================================
The ABL766 autoloader (`aveflash.lua`) drives:
- `authboot debugtokens [--all]` -> the RTAS token load (server dead).
- `securewipe` -> destructive (notes/17).
- `flashall` with `b_flashpersist=true` (persist partition), modem (`NON-HLOS`),
  bootchain, boot/recovery/system/cache/userdata/oem.
- `IMAGE_TYPE="sfi"` (config.lua); `match_sig_tag` accepts ADBI/ABBI or MFI.
No WCNSS-specific stream: **the autoloader does NOT flash WCNSS firmware** — the
WLAN NV (`WCNSS_qcom_wlan_nv.bin`) lives on `/persist` (protected), and WCNSS
firmware comes from the system/vendor image. So there is no autoloader handle to
inject a modified WCNSS image without a signed system image (dm-verity).

================================================================================
PART E — BOTTOM LINE
================================================================================
Most-reachable surfaces, ranked:
1. **WLAN cfg80211/nl80211 host handlers** (`pronto_wlan.ko` 3.0.11.66,
   WCN36xx). App-reachable via netlink. CVE-2019-10526 (OOB write, MSM8953
   listed) still open at patch 2018-12. **Best remaining kernel LPE candidate.**
2. **AF_PACKET / netfilter / net stack** — reachable but grsec/net hardening +
   Dec-2018 patch closes most classics.
3. **`/dev/kgsl-3d0`** (0666) GPU — reachable; needs a GPU SMMU/DMA 0-day.

Everything Bootloader/RTAS2/diag/trustzone is **SELinux/DAC-gated from shell**,
and every gated socket (`bbauthtool`, `tokenservice`, `tctd`) is root-only.

**No unprivileged software path to root was found.** The realistic remaining
lead is a kernel memory-corruption bug in the **WLAN driver** (or GPU), both
reachable, versus an environment hardened by grsec/PaX + SELinux + usercopy.
