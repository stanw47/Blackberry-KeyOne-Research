# KEYone-specific surface: TCL FOTA / CNFota (system-UID OTA agent)

Discovered 2026-10-02. This is a surface the Priv never had — a TCL OTA app
running as **system UID** with recovery privileges. Documented for the record
and as the best remaining non-bootloader lead.

## Package
- `com.tcl.ota.bb` — `/system/priv-app/CNFota/CNFota.apk` (8.7 MB)
  versionName `7081.0672.3.276`, versionCode `618061301`, platformBuild 24.
- **`android:sharedUserId="android.uid.system"`** → runs as **system (uid 1000)**.
- SELinux domain: **`platform_app`** (seen in dmesg: `com.tcl.ota.bb`).
- Sibling: `com.blackberrymobile.aota`, `com.jrdcom.filemanager.bb`,
  `JrdFota.apk`.

## Privileged permissions held (requested & system-signed)
`RECOVERY`, `REBOOT`, `INSTALL_PACKAGES`, `DELETE_PACKAGES`,
`MOUNT_UNMOUNT_FILESYSTEMS`, `WRITE_MEDIA_STORAGE`, `ACCESS_CACHE_FILESYSTEM`,
`DELETE_CACHE_FILES`, `INTERACT_ACROSS_USERS`, `MANAGE_USERS`,
`ACCESS_KEYGUARD_SECURE_STORAGE`, `READ_LOGS`, `ACCESS_DOWNLOAD_MANAGER`, ...

## Exported (reachable) surface
| Component | Export | Guard | Notes |
|---|---|---|---|
| `com.tcl.ota.provider.OtaProvider` (`content://com.tcl.ota`) | **exported=true** | `android.permission.ACCESS_OTA_DATA` | perm is **protectionLevel=normal** → auto-granted to any app that declares it |
| `receiver.ActionReceiver` | exported | `com.tcl.ota.permission.CALL_CORE_SERVICE` | actions AUTO_CHECK/AUTO_UPDATE/NEW_VERSION/... |
| `receiver.DownloadReceiver` | exported | BOOT/WIFI actions | |
| `receiver.PackageIntentReceiver` | exported | PACKAGE_* | |
| `receiver.FotaResetReceiver` | exported | `LAUNCH_DEVICE_RESET` | |
| `activity.SystemUpdatesActivity` | exported (LAUNCHER) | none | main UI |
| `activity.AdvancedModeActivity` | **not exported** | `CALL_CORE_SERVICE` | hidden advanced mode |
| `service.FotaUpdateService` etc. | not exported | `CALL_CORE_SERVICE` | |

Live checks (adb shell, uid 2000):
- `content query --uri content://com.tcl.ota/firmware` → "No result found"
  (reachable; no access denial surfaced).
- `am broadcast -a com.tcl.ota.action.AUTO_CHECK -n .../ActionReceiver`
  → **accepted** (`result=0`).
- `am start .../AdvancedModeActivity` → `SecurityException: not exported`.

## The hidden "advanced mode" (dial code)
- Raw dex strings: **`fotaapp*#1221#`**, `*#76`, `dialog_test_enter_ip`,
  `key_tester_validated`/`KEY_TESTER_VALIDATED`, `key_test_ip`, `key_app_ip`,
  `key_test_ref`, `key_test_version`, `key_test_imei`, `update file path:`.
- ⇒ An internal **tester/advanced mode** that can set a **test server IP**
  and a **local `update file path`**. This mirrors the Priv's OTA "advanced
  mode" that was used for variant/server switching.

## The terminal gate (why this still doesn't unlock)
- `OtaProvider` is SQLite metadata only (tables app/firmware/report/state/
  unread) — no flash primitive.
- Firmware install goes through the state machine (Idle→Checking→Downloading→
  Verifying→Downloaded→Installing) using
  **`RecoverySystem.verifyPackage(update, null, null)`** and
  `/cache/recovery/last_fota.status`.
- Recovery verifies against **`/system/etc/security/otacerts.zip`** =
  single self-signed cert **`CN=BlackBerry Ltd`, valid 2018-01-02 → 2053**.
- ⇒ Producing an accepted package still requires **BlackBerry's private key**.
  Server-IP / local-path overrides change *where* a package comes from, not
  *whether it verifies*.

## Where the real opportunity is
This app is a **system-UID OTA agent with a settable server and local-file UI** —
i.e. a high-value target for an **app-level bug** (zip/path traversal, TOCTOU on
`/cache`, unsafe deserialization, exported-provider SQLi) that could yield
**code exec as `system`/`platform_app`**. That would be a privilege escalation
*within Android* (not a bootloader unlock), and from `system` one can reach
`/dev/qseecom` (tee_device) — opening the CVE-2021-1961 TrustZone route that was
dead from `shell`. Worth deep RE if a path is desired.

## Test server override endpoints found in dex
- `https://aota.tclclouds.com/api/app` (+ /appDetail /checkList /strategy /applog)
- `http://portal.fly2tech.com`, `http://54.164.122.241/aota-web/`
- push: `https://g2push-ap-south.tclclouds.com/`, `pushplatform.tclclouds.com`

## Files
- `dumps/2026-10-02/ota/CNFota.apk`, `CNFota.jar` (dex2jar), `jar_x/`,
  `otacerts/APOA.x509.pem`, `ota/` tree.
