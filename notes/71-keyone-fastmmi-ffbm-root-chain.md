# 71 — KEYONE ROOT: QTI fastmmi factory-mode exploit chain (FFBM → root), live progress

Date: 2026-10-13 (session 70-71). **STATUS: chain fully reverse-engineered, exploit build in progress.**

## TL;DR — the chain

1. **FFBM factory mode is reachable** by writing `"ffbm-01"` to the `misc` partition
   (meta bypass, entry `misc`). Confirmed live: phone boots into the factory MMI
   (QTI `fastmmi` test menu), no main framework, /data = tmpfs.
   - aboot `get_ffbm` (0x8f630c84) reads misc page 0; `"ffbm-"` prefix →
     cmdline `androidboot.mode=ffbm-01` → init enters FFBM.
   - misc = LUN0 p35 (RTAS-gated for direct flash, **writable via meta bypass**).
   - revert = write zeros to misc (done, verified by parthash).
2. **The MMI (`/system/bin/mmi`, runs as ROOT, init SELinux domain) loads its test
   config from `/cache/FTM_AP/mmi.cfg`** (writable!).
   - `init_config(get_mmi_cfg_file(1))` → `/cache/FTM_AP/mmi.cfg` (source:
     `mmi_cfg.cpp: get_mmi_cfg_file` = `<mmi_ftm_ap_dir>/mmi.cfg`).
   - `is_create_mmi_cfg()` only checks: /etc/mmi/mmi.xml exists AND
     `/cache/FTM_AP/.setting` contains `checksum=<st_size+st_mtim.tv_sec of mmi.xml>`
     AND both cfg files exist → then returns FALSE (don't regenerate) → **our cfg is used**.
3. **Module configs are trusted paths**: `fork_launch_module()` builds
   `para = "lib_path:<mmi_lib64_base><config["lib_name"]>;<parameter>"`
   and `execv(get_value("mmi_agent64"), ["-m", module, "-p", para])`.
4. **The root agent `mmi_agent64` does `dlopen(path, RTLD_NOW)` with NO sanitization**
   (only NULL check + `access(R_OK)`). Source: `agent_main.cpp: load_module()`.
   - `lib_name = "../../../../cache/FTM_AP/evil"` →
     `/system/vendor/lib64/../../../../cache/FTM_AP/evil` → `/cache/FTM_AP/evil.so`
     → **dlopen as ROOT in init domain → constructor runs immediately**.
5. **Trigger**: `.autostart` file in `/cache/FTM_AP/` with content starting `54525535`
   (`is_autostart()`), OR `autorun_enable=1` in the `[MMI]` module config →
   `start_autorun()` runs all modules with `automation=1` via `module_exec_pcba()`
   → agent forks → dlopen(our lib) → root.

## Key file/partition facts (live-verified)

- `/cache` is mounted **twice**: init.rc "on init" mounts `/dev/block/mmcblk0p34`
  (`# start:BBRY_ANDROID`) and later `/dev/block/bootdevice/by-name/cache` (= GPT
  partition "cache", p55, 1GB) is mounted **over** it → effective `/cache` = p55.
  **Meta bypass entry name for /cache = `cache`.**
- misc = p35 (1MB), 56 LUN0 partitions total.
- FFBM boot generated `/cache/FTM_AP/{.setting, mmi.cfg, mmi-pcba.cfg}` (root MMI).
  The .setting holds the mmi.xml checksum → **preserve it** when staging.
- `/cache` mount options: `rw,seclabel,nosuid,nodev,relatime` — **no noexec** → dlopen OK.
- AAN355 system.img (on Ventoy) used as source for MMI binaries/configs:
  `/bin/mmi` (175KB), `/bin/mmi_agent64`, `/etc/mmi/{mmi.xml,path_config.xml,...}`.
  (AAN355 build 2017; the device runs ABL766 2018 — use the DEVICE's own
  /cache/FTM_AP + /system/etc/mmi files for the final exploit.)
- QTI fastmmi source (read for exact logic): github Sushrut1101/android_vendor_qcom_proprietary
  `commonsys/fastmmi/mmi/*` (mmi.cpp is_autostart/is_skip_pass/start_autorun,
  mmi_cfg.cpp get_mmi_cfg_file/is_create_mmi_cfg/create_mmi_cfg, module.cpp
  fork_launch_module, agent_main.cpp load_module, diag_handle.cpp FTM_AP diag cmds).

## Toolbox read channel (for /cache — run-as lacks the cache gid)

The toolbox app (`com.bbkeyone.toolbox`, priv_app, has ACCESS_CACHE_FILESYSTEM gid)
has an exported **ExecActivity**: `am start -n com.bbkeyone.toolbox/.ExecActivity
--es cmd '<shell cmd>' --es out <name>` → runs `/system/bin/sh -c <cmd>` as the app
and writes output to `/storage/emulated/0/Download/toolbox_<name>` + app external dir.
- NOTE: the cmd must not contain single quotes (breaks device-side quoting);
  use `stat -c%s`/`stat -c%Y` (no spaces).
- run-as (priv_app uid) CANNOT read /cache (0770 system:cache) — use ExecActivity.

## Exploit build plan (in progress)

1. Revert done (misc zeros). Android booted.
2. Copy out `/cache/FTM_AP/*` + `/system/etc/mmi/*` via ExecActivity (in progress —
   first attempts failed on quoting; retry with quote-free cmd).
3. Modify the pulled `mmi.cfg`: pick an `automation=1` module (e.g. SYSTEM_INFO),
   set its `lib_name=../../../../cache/FTM_AP/evil` (keep .setting + mmi-pcba.cfg
   + all other entries intact so the UI/config load succeeds).
4. Add `/cache/FTM_AP/.autostart` = `54525535`.
5. Build `evil.so` (aarch64, freestanding, no libc — clang `-target aarch64-linux-android
   -nostdlib -shared -fuse-ld=lld`, raw syscalls via `svc #0`):
   - `__attribute__((constructor))` payload: write `/cache/FTM_AP/PWNED` (with uid),
     dump `/dev/block/mmcblk0boot0` + `mmcblk0boot1` (4MB each) to
     `/cache/FTM_AP/boot0.dump` / `boot1.dump` (the AAK171 backup chain for analysis!),
     dump /proc/version + /proc/cmdline.
   - export dummy `mmi_module_info` symbol (dlsym target) — constructor runs first anyway.
6. Build a 32MB… — **NOTE: /cache = p55 = 1GB partition; build ext4 without journal
   (`mke2fs -O ^has_journal -d <dir>`) sized to partition (or smaller), flash via
   meta entry `cache`. Keep image ≤ what's needed; mke2fs -d populates directly.
7. Build ONE meta container with 2 entries: `cache` → the ext4 image (data_off/len),
   `misc` → 512B `"ffbm-01"`+zeros. Flash via `fastboot flash boot <meta>`.
8. Reboot → FFBM → MMI → is_create_mmi_cfg FALSE (checksum preserved) → loads our
   mmi.cfg → autorun (.autostart) → agent(root) → dlopen(evil.so) → ROOT payload.
9. Verify: reboot to fastboot → flash revert_misc → Android → read
   /cache/FTM_AP/PWNED + boot0.dump via ExecActivity → root proven; analyze AAK171.

## Meta container format (verified live this session)

```
+0x00  u32 magic 0xCE1AD63C
+0x4A  u16 entries_area_size (= count * 0x50)
+0x4C  entry[0]: name[NUL-padded to 0x48], u32 data_off @0x94, u32 data_len @0x98
       entry[1] @ 0x9C (stride 0x50), ...
data   at any offset (data_off from container start)
```
- Entry name is passed to cmd_flash_mmc_img(name, data+off, len) — **no permission
  check** — arbitrary partition writes.
- Bug hit + fixed: entries area size is at **0x4A** (not 0x46); name at 0x4C.
- Proven this session: wrote "ffbm-01" to misc (parthash matched SHA224 of the
  crafted page), device booted FFBM. Also earlier: rcause/hwi/boot0hwi tests.

## Open questions / next after root

- Root payload can also: read boot0 GPT + BackupBC (AAK171 backup SBL1/aboot!),
  attempt RPMB bootmode via QSEE/secapp (the real factory-mode goal!), write
  /nvram tokens, etc. Root = init domain, so full device access.
- Whether the AAK171 backup chain has a wipe-free factory path (needs its binary —
  now dumpable with root!).

## UPDATE 2026-10-13 (session 71 continued) — v1..v5 attempts, live findings

### What is PROVEN working (live)
- misc `"ffbm-01"` → FFBM + MMI menu: **works every time** (meta bypass).
- Meta container multi-entry (persist+cache+misc) writes: **work** (parthash verified).
- **Our mmi.cfg IS loaded by the MMI**: v3 renamed SYSTEM_INFO display_name to
  "ZZTEST" → MMI **crashed/hung at boot animation** (missing string lookup) —
  proof the MMI parsed OUR config. (So is_create/checksum/mount are all fine;
  /cache = the by-name/cache (p55) mount wins, and we also write p34/persist.)
- `/cache` = p55 (init.target.rc "on fs" mounts by-name/cache OVER the init.rc p34 mount);
  FFBM triggers "late-init" → the fs chain → both mounts run.
- Device MMI binary == AAN355 build except 16 bytes build-id; mmi_agent64 IDENTICAL;
  all MMI libs (libmmi.so + mmi_*.so) present on device.
- agent dlopen path has NO sanitization (agent_main.cpp load_module: NULL check +
  access(R_OK) + dlopen). libmmi parse_parameter = ';' fields + ':' kv + trim.

### What FAILS
- Payload NEVER runs: no /oem proof file, no auto-reboot, misc never cleared,
  device stays in FFBM. Confirmed via /oem read after revert.
- v4: 3 different .so builds (O2, 4K-align, O0) on 3 modules — no payload.
- v5: control (SYSTEM_INFO→mmi_sysinfo.so from /system), TOUCH→mmi_sysinfo.so copy
  in /cache, BATTERY→evil_a, CPU→evil_e (DT_NEEDED libc.so stub) — no auto-reboot.
  User saw the MMI menu; "nothing new there" (no ZZTEST obviously) — **control result
  (system_info PASS/FAIL icon) NOT yet read.**

### Remaining suspects (in order)
1. Agent fails for ALL modules (even legit lib) — then dlopen/agent is broken
   generically in FFBM. Need the control's result to know.
2. /cache dlopen blocked (SELinux execmod? noexec? — /cache mount is nosuid,nodev
   only, no noexec) — TOUCH module tests exactly this.
3. Our freestanding .so rejected by bionic (DT_NEEDED absent / missing versioned
   libc refs?) — legit mmi_sysinfo.so has NEEDED + @LIBC versioned syms; evil_e
   added DT_NEEDED libc.so.
4. Agent exec itself fails (execv mmi_agent64) — but libs all present.

### Diagnostic channels (blocked/available)
- /cache/FTM_AP/mmi.log = logcat -f (MMI + agents' logs) — **SELinux denies app read**
  (priv_app lacks cache_file read; toolbox has gid 2001(cache) but SELinux denies).
- pstore /sys/fs/pstore = denied to shell+priv_app.
- oem parthash:cache = "Partition is in blacklist". persist parthash works.
- **Todo: read the MMI's "FAILED" tab + system_info icon state via the user** (the
  control test), and consider pulling /system/bin/qcom-c_main-sh & factory scripts
  (root services) as an alternate vector.

### Files
- /tmp/opencode/exploit/{root/FTM_AP/{mmi.cfg,mmi-pcba.cfg,.setting,.autostart,evil*},cache.img,exploit_meta.img}
- /tmp/opencode/exploit/evilv.c (variant payload source, -DPWNL=<ascii>)
- device_mmi/ = pulled device MMI binaries + libs + mmi.xml + path_config.xml
- /tmp/opencode/{mmi_decomp.c,agent_decomp.c,libmmi_decomp.c}
- misc write: /tmp/opencode/ffbm_misc.img ; revert: /tmp/opencode/revert_misc.img

## UPDATE 2 (2026-10-13 late) — v6 result + state

- v6: font_size=120 marker + SYSTEM_INFO→evil_a. User: stuck at boot animation
  again (like v3 ZZTEST) → **MMI parses OUR cfg (font_size change crashes its UI)
  but exploit payload still never runs** (no /oem proof, no auto-reboot).
- Conclusion so far: config load ✓ (proven twice via visible UI crash), but
  the module-agent/dlopen path never yields our code — even the v5 control
  (legit lib from /system) result is unreadable (MMI UI not navigable by user).
- Remaining diagnostic options are exhausted on the Android side:
  mmi.log (/cache/FTM_AP/mmi.log) SELinux-denied; pstore denied; parthash cache
  blacklisted; FFBM has no USB/adb (so no live agent debugging).
- Parallel vector being explored: FFBM factory services running as root
  (tftp_server pulled, has WRQ + fts; wcnss/sensors/rmt_storage present).
- Next options: (a) deeper static trace of fork_launch_module on the DEVICE mmi
  (16-byte build-id-only diff, so AAN355 disasm is valid) to find why the agent
  produces no payload; (b) analyze tftp_server / other factory root daemons for
  a feedable input (configs, sockets, network); (c) kernel LPE (CVE-2019-2215)
  for Android root (does not unlock boot chain but gives /nvram etc.).

## UPDATE 3 — SELinux policy analysis attempt + final state (2026-10-14)

- Host lacks SELinux policy tools; `pip install setools` pulls a squatted
  audio package; GitHub setools build fails (no libsepol-dev headers, no sudo).
- Policy file: recon/keyone_selinux_policy.bin (368451 B, magic 0xF97CFF8C MLS,
  version 30). Contains types mmi_exec, mmi_data_file, cache_file, init, shell.
- file_contexts confirms: `/cache/FTM_AP(/.*)?` -> u:object_r:mmi_data_file:s0
  (NOT cache_file). `/cache/recovery`, `/cache/backup*` -> cache_file.
  `/mnt/expand/[^/]+/local/tmp(/.*)?` -> shell_data_file.
- So our staged /cache/FTM_AP/evil* is mmi_data_file. Whether mmi_exec may
  `execute` mmi_data_file is THE open question — needs setools (or libsepol-dev
  + pip build). Mount opts /cache = nosuid,nodev,barrier=1 — no noexec.
- Device state: reverted, boots normal Android, /oem clean (no payload ever ran).

### To finish the SELinux verdict (user sudo needed, one command)
- `sudo apt install setools`  (or `sudo apt install libsepol-dev` then
  pip install git+https://github.com/SELinuxProject/setools.git)
- Then: `sesearch -A -s mmi_exec -t mmi_data_file -c file -p execute policy.bin`

### Other live leads
- tftp_server (pulled, root in FFBM): QTI RFS server, strings reference
  /persist/rfs/* and "shared/server_info.txt"; TFTP RRQ/WRQ code paths.
  Network in FFBM unverified (wcnss-service starts, USB diag/adb exposes no net).
- Factory root services present: rmt_storage, sensors.qcom, wcnss_*, irsc_util,
  ptt_socket_app; qcom-c_main-sh = /system/bin/sh /init.class_main.sh (benign).
