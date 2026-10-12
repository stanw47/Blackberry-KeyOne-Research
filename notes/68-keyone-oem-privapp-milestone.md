# 68 — MILESTONE: persistent privileged system app via /oem injection (LIVE, PROVEN)

Date: 2026-10-12 (session 68)

## What was achieved

A **new, fully privileged system application** is now installed persistently on
the KEYone by injecting it into the `/oem` partition (no signature check, no
dm-verity active, survives userdata wipes since /oem is a system partition):

- Built with the downloaded build-tools r33 + platform-25 android.jar
  (`~/Documents/bb-wine/keyone/sdk`), signed with a throwaway key.
- App: `com.bbkeyone.toolbox` (`app-signed.apk`), placed at
  `/oem/priv-app/BbToolbox/BbToolbox.apk`.
- /oem image rebuilt from a faithful `tar` pull (modes preserved), uid/gid set
  to 0 and `security.selinux=u:object_r:system_file:s0` xattrs applied to every
  inode via `debugfs` (`sif`/`ea_set`). e2fsck-clean, block size 4096,
  `^metadata_csum,^64bit,^orphan_file`, size = partition (341,049,344 bytes).
- `fastboot flash oem oem_mod.img` -> OKAY; verified on device:
  `oem parthash:oem:4096` == local SHA224 of the image (exact match).
- Boot succeeded: `validate_oem` passes (ro.oem.tag=sprint kept), PROOF.txt
  marker live, all 4 original OEM apps still installed.

## Granted privileges (dumpsys, all granted=true)

INSTALL_PACKAGES, DELETE_PACKAGES, WRITE_SECURE_SETTINGS, READ_LOGS, DUMP,
PACKAGE_USAGE_STATS, CHANGE_CONFIGURATION, GET_APP_OPS_STATS, REBOOT,
MOUNT_UNMOUNT_FILESYSTEMS, ACCESS_SURFACE_FLINGER, MODIFY_PHONE_STATE,
READ_PRIVILEGED_PHONE_STATE, MANAGE_USERS, INTERACT_ACROSS_USERS,
WRITE_MEDIA_STORAGE, CHANGE_COMPONENT_ENABLED_STATE.

Runtime: `u:r:priv_app:s0`, uid 10103 — the privileged-app SELinux domain.
(Signature-level perms are correctly withheld; but signature|privileged are
all granted because /oem/priv-app is a privileged system scan dir.)

## Files / artifacts
- `~/Documents/bb-wine/keyone/apk/` — APK sources, signed APK, keystore
  (`tool.ks`, pass android).
- `~/Documents/bb-wine/keyone/` — oem.tar (pull), oem_stock.img (rescue),
  oem_mod.img (deployed), oem_paths.txt, fix scripts, parthash captures.
- Rebuild pipeline: tar pull -> extract -> add files -> mke2fs -d -> debugfs
  uid/xattr fixups -> fastboot flash oem.

## Recovery / safety
- `oem_stock.img` = identical-content rescue image (flash it any time).
- validate_oem failure mode = "device shutting down now" — keep
  `ro.oem.tag = sprint` in oem.prop.
- Fastboot is always reachable before init runs, so a bad /oem is recoverable.

## What this unlocks (next steps)
- Arbitrary compiled code can now run as a privileged system app with the
  above permissions and the priv_app SELinux domain (rebuild + reflash /oem to
  iterate).
- Direct routes: silent package installs, secure-settings control
  (accessibility hijack etc.), full dumpsys/README logs, SurfaceFlinger and
  telephony binder access — a much stronger base for LPE work on 7.1.
- Boot-chain goal (custom boot) remains walled by boot0 hardware WP +
  signatures; this is an Android-side win.
