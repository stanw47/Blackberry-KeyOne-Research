# 73 — Toolbox v3 persistent priv-app agent + MERCURY MMI Test app + FFBM tap-test findings

Date: 2026-10-14

## Toolbox self-update pipeline (PROVEN)
- `~/Documents/bb-wine/keyone/apk/` — sources (MainActivity, ExecActivity,
  TokenTestActivity, NEW AgentService, BootReceiver), keystore `tool.ks`
  (alias `tool`, store/key pass `android`), build outputs.
- Toolchain: `~/Documents/bb-wine/keyone/sdk/android-13/{aapt2,d8,zipalign,apksigner}`
  + `sdk/android-7.1.1/android.jar`.
- **d8 R8-3.3.20 NPEs on anonymous inner classes compiled by JDK 25 javac.**
  Fix: named classes (no anonymous) + `JAVA_HOME=java-17 javac -source/-target 8`.
- Build: javac -> d8 --min-api 24 -> aapt2 link -> zip add classes.dex ->
  zipalign -> apksigner (tool.ks).
- `adb install -r app-signed.apk` (v3): **Success**; dumpsys shows
  versionCode=3, flags=[SYSTEM ... UPDATED_SYSTEM_APP], privateFlags=[PRIVILEGED],
  codePath=/data/app/... with resourcePath still /oem/priv-app/BbToolbox,
  46 granted perms intact, still uid 10103 / u:r:priv_app:s0.
- => We can iterate the app by update (no /oem reflash). /oem reflash
  (oem_mod.img) remains the rescue/reinstall path.
- `pm install` via the app-shell CLI fails (INTERACT_ACROSS_USERS_FULL; then NPE
  in BB's pm) — use adb install or (future) Java PackageInstaller session API.

## AgentService (v3) — persistent priv-app shell
- BootReceiver (BOOT_COMPLETED) starts AgentService; START_STICKY.
- Loop: watches `/sdcard/.tb_cmd`; executes via `sh -c`; appends output to
  `/sdcard/.tb_out`; deletes command file. 2 s poll.
- VERIFIED live: cmd `id` -> output shows uid=10103 u:r:priv_app:s0 (BBB100-3,
  date). Start via toolbox: `am startservice -n com.bbkeyone.toolbox/.AgentService`.

## MERCURY MMI Test app (com.android.mmi) — new surface
- Installed from /system/app/MMITest (package `com.android.mmi`), domain
  `tctmmi_app` (sepolicy): ctl.start allowed (!), execmem, tctmmi_app_tmpfs
  execute, /proc/ftxxxx-debug RW (tct_mmi_proc), sensors_test_exec execute,
  keystore, tun, media_rw, sysfs_update_now RW...
- UI: "MOBILE PHONES" / "MERCURY MMI TEST SW: ABD565 SN: ... ONLINE" with
  AUTO1 / AUTO2 / MANU buttons; keyboard-driven (adb `input keyevent` triggers
  "Start?" YES/NO dialog; focus starts on NO — DPAD_LEFT then ENTER for YES).
- Log tags: MMITest.AutoTestMain ("not in keyevent mode ..."), MMITest.JRDClient.
- OAT at /system/app/MMITest/oat/arm64/MMITest.odex (dex strings include
  "ctl.start", SystemProperties, Runtime, mmiAidl, mmijni, mmi_Keyboard).
- UNEXPLORED: what its AUTO/MANU flows start (ctl.* targets) — drive via real
  screen or key events and watch `logcat` + init `starting service`.
- tctd (BB factory daemon): ctl_default_prop set, shell_exec execute, execmem,
  sys_boot cap, /cache RW, persist RW, modem_efs RW, fuse, diag — but its
  socket only writable by system_app.

## FFBM tap-test findings (v7/v8/v10)
- Config loads + labels (display_name must be a strings.xml key: "vibrator",
  "battery" work; custom labels render blank).
- Autorun on cold boot races the agent sockets: agent modules fail instantly
  (no auto-vibration), in-process modules (LCD show_rgb) run. LCD color tests
  never auto-advance => autorun stalls on them (the "red screen").
- Tapping the keyboard at the menu DOES execute modules (30 s vibrator PCBA
  test = stock module works!) but selection is stochastic; taps never
  demonstrably reached the custom "flashlight" (/cache) row => /cache dlopen
  still unproven-blocked (SELinux mmi_data_file has no execute for mmi domain).
- not yet revisited with diagnostics.

## Files
- toolbox.apk pulled: /tmp/opencode/toolbox.apk ; v3 build:
  ~/Documents/bb-wine/keyone/apk/app-signed.apk
- window_dump.xml / screenshots: /tmp/opencode/
