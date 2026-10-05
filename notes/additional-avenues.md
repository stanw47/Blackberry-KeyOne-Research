# KEYone additional avenues probed (2026-10-02)

After re-reading the Priv research log, I probed every transferable idea against
the KEYone. Results:

## 1. TCL FOTA / CNFota system-UID app  → documented, no unlock
- `com.tcl.ota.bb` runs as **system UID** with `RECOVERY`/`REBOOT`/
  `INSTALL_PACKAGES`. Exported `OtaProvider` guarded by `ACCESS_OTA_DATA`
  (protectionLevel=**normal**, auto-granted); receiver `ActionReceiver` reachable.
- Hidden advanced mode dial: **`fotaapp*#1221#`** (+ test-IP, local update-file
  path). Recovery install verifies against `/system/etc/security/otacerts.zip`
  = **`CN=BlackBerry Ltd`, valid to 2053**. ⇒ still needs BB private key.
- Value: possible **app-level privesc to `system`** (then `/dev/qseecom` → CVE-
  2021-1961). See `tcl-fota-surface.md`. NOT a bootloader unlock.

## 2. Factory / BBAuth / token stack  → present but DISABLED (same as Priv)
- KEYone `/system/bin` contains the identical BB factory stack:
  `bb_tokenserviced`, `bbauthtoold`, `vtnvfsd(+/_wrapper)`, `stp_server`,
  `mfg_*`, `pubmfgdata`, `reset_cause`, `selflash`.
- `/nvram/{nvuser,perm,blog,boardid,prdid}` **vtnvfs** mounts exist
  (rw for nvuser/perm/blog, `vtnvfs_*_file` SELinux, uid/gid 2900).
- `mfgUtil v1.3` (shell-accessible): read-only IDs + `--clearInProductionFlag`.
  Most commands return **"Device not running in production but options requested
  require it"**.
- **`ro.boot.inproductionflag=false`, `ro.start_stp=false`, `stp_server` NOT
  running.** The factory signing hub is off and the flag is **one-way**
  (clear-only). ⇒ NVSIG/BSIS/token-signing path **dead**, exactly as on Priv.

## 3. EDL / dload  → closed (as established)
- No software EDL command; `adb reboot edl` boots Android; no EDL cable; even
  the Priv with a real EDL path failed to enter. Confirmed out of scope.

## 4. Attack surface delta vs Priv (kernel is NEWER here)
- KEYone kernel **3.18.31** (Nov 2018) vs Priv **3.10.84**. Older exploits
  (DirtyCOW, Bad Binder class, etc.) mostly N/A or patched; no clean public
  3.18.31 LPE for this build.
- Reachable world/dev devices (shell = uid 2000):
  - `/dev/kgsl-3d0` **crw-rw-rw-** (gpu_device) — primary kernel vector.
  - `/dev/binder`, `/dev/ashmem` 0666.
  - `/dev/ion`, `/dev/adsprpc-smd` = 0664 system (shell NOT in group) — blocked.
  - `/dev/qseecom` = 0660 tee_device — **denied** (same as Priv → CVE-2021-1961
    unusable from shell).
- shell caps = 0 (bounding 0xc0) — network/socket exploits ruled out.

## Net
Every route the Priv research exhausted maps to the **same dead ends** on the
KEYone, and the KEYone adds no bootloader-side bypass. The only *new* thing is
the **system-UID TCL FOTA agent** — an app-privesc target, not an unlock. A
bootloader unlock/root on this shipped unit remains **not achievable** without
EDL, hardware ISP, or BlackBerry-signed artifacts.
