# Session 01 — BlackBerry Security Libraries (RE)

All pulled from `/system/lib64/` (Readable as shell). Offline triage with
`tools/elf_triage.py` (LIEF + capstone). Raw output: `recon/elf_triage_seclibs.txt`.

Build note: all are **AArch64**, Android **SDK 25 (7.1.1)**, `gold 1.11`, `-z now`
(BIND_NOW/full RELRO), built 2018-11-21. They link `libqseecomimport.so` for TZ.

---

## libsecureservice.so  (38,904 bytes) — the TrustZone/secure-service shim

This is the single most valuable artifact. It exposes BlackBerry's secure-service
API over QSEE (`qseecomapi_open`, `tz_call`, `tz_app_init`, `tz_wv_app_init`).

### RPMB (directly relevant to the BB10 repo's RPMB/FS_DIRTY_ALL finding)
```
ss_rpmb_read_block
ss_rpmb_write_block
ss_rpmb_get_block_count
```

### BIDE (BlackBerry Integrity Detection Engine)
```
ss_bide_add_section
ss_bide_generate_keypair
ss_bide_generate_nonce
ss_bide_sign_data
ss_bide_storage_build_to_number
ss_bide_storage_number_to_build
ss_bide_storage_read
ss_bide_storage_update_sensor
ss_bide_storage_wipe
```

### BSIS (BlackBerry Secure Image Signing)
```
ss_bsis_gen_ecdh_bsis_priv_key
ss_bsis_gen_pub_priv_key
ss_bsis_sign_with_bsis_priv_key
ss_bsis_validate_pub_priv_key
```

### Secure execution / integrity
```
ss_verify_integrity
ss_is_oem_secured_proc
ss_is_secure_proc_bound
ss_disable_hw_access
ss_set_lk_milestone
ss_read_proc_id
ss_get_rand
ss_hmac
ss_memset_s
```

### Key / password / attestation
```
ss_attestation_verify_data
ss_password_calc_hash_with_entropy
ss_password_encrypt
ss_user_key_derive
ss_user_key_blacklist_diversifier
ss_pk_global_get_max_instances
ss_pk_global_get_user_id
ss_pk_user_enroll / delete / get_attempt_count / masterpass_export
ss_pk_user_recovery_key_create / key_extract / get_uidrs / remove_uidr
```

### DRM / HDCP2.x (widevine keybox + HDCP)
`ss_drm_wv_decrypt_keybox`, `ss_drm_hdcp2_decrypt_key`, full `ss_hdcp2x_*` suite.

### 🚩 Critical strings
```
ro.boot.binfo.bbss_insecure
"%d: Device is insecure, command not allowed"
"%d: OEM secured: %s"
"secure_service"
```
→ The library **reads `ro.boot.binfo.bbss_insecure`** and refuses secure commands
when the device is insecure. This is the Android sibling of the BB10 `bbss.insecure`
keystone from the main repo. If that byte could ever be set, this gate flips.

---

## libbidejni.so  (14,280 bytes) — BIDE JNI bridge

Java entrypoints (`com.blackberry.bide.BideKernelInterface.*`):
```
createAndSignBIDEReport
firstBootCheck
forceScan
generateP10Request
initialize
takeStartupSnapShot
```
Native behavior:
- opens **`/dev/bide`** and issues `ioctl` (`send_bide_ioctl`, `cmd=%d`)
- calls `token_service_is_token_present` (→ `libbb_tokenservice.so`)
- logs: `[BIDE NATIVE]`, `JBIDE started multiple times! Reset nonce.`,
  `First start of JBIDE.`, `Bide ioctl returned ok.`, `Error returned from bide kernel: %d`
- Binder callbacks into Java: `setKBideReport`, `setTZBideReport`, `setTZSignature`

---

## libbbauthtool.so  (14,280 bytes) — RTAS auth client

```
auth_password
auth_rtas_has_permission
auth_rtas_init
auth_rtas_sign_record
bbauthtool_cs_enter / bbauthtool_cs_exit        (critical-section helpers)
bbauthtool_event_signal / bbauthtool_event_wait
bbauthtool_sock_client_register
bbauthtool_sock_client_send
```
Uses `socket_local_client` — talks to the `bbauthtoold` daemon (uid 2911, groups 2900…).

---

## libbb_tokenservice.so  (10,120 bytes) — Token Service client

```
token_service_get_token_payload
token_service_is_token_present
```
Transport: **`/dev/socket/tokenservice`** (abstract/local socket).
Strings show strict length checks: `TokenClient: token name is too long`,
`Could not write token name to token_service: write() returned: %d, expected: %u`.

---

## libbbusb.so  (10,192 bytes) — USB state socket

```
bbusb_is_offline / bbusb_is_online
bbusb_receive / bbusb_send
bbusb_wait_for_offline / bbusb_wait_for_online
wait_for_uevent
```
Transport: **`/dev/usb_blackberry`**. This is the userspace side of the `bb` USB gadget
(loader/fastboot) seen in kallsyms.

---

## libbbry_vs.so  (63,664 bytes) — BlackBerry vendor-specific radio/QMI

Binder service `com.blackberry.ddt.IDiagnosticService` (`BpDiagnosticService`:
`open`, `send`, `send_file`, `append`, `get_guid`, `get_sysvars`, `admin`).
QMI vendor-specific (`qmi_vs_bbry_service_v01`):
```
radionv_qct_readnv_item / writenv_item
radionv_qct_read_efs_nv_item / write_efs_nv_item / read_efs_large_nv_item / efs_delete
radionv_qct_readnv_per_subs_item / writenv_per_subs_item
bbry_efs_force_sync_util
bbry_reset_modem_util / bbry_reset_modem_no_efs_sync_util
bbry_qmi_set_tuner_dacs / bbry_qmi_get_sense_ic_meas
bbry_qmi_set_enhanced_roaming_acqdb_scan
bbry_vs_qmi_set/get_power_profile
bbry_ims_qct_metrics_ims_config
```
Relevance: NV/EFS read+write primitives over QMI. The `write_efs_nv_item`/`writenv_item`
paths are modem-side, but the Binder `DiagnosticService` (`ddt_*` = "device diagnostic
tool"? `ddt_open/send/send_file/admin`) is a user-facing surface worth auditing — it can
`open(pid, path)`, `send`, and `send_file` with an fd.

---

## Consolidated trust map (userspace)

```
Java BIDEapp ──libbidejni──> /dev/bide (kernel BIDE LSM, 229:0)
                          └─> libbb_tokenservice ──> /dev/socket/tokenservice (TokenService daemon)
libsecureservice ──qseecomapi_open/tz_call──> QSEE / TrustZone (RPMB, BSIS, keys, DRM)
libbbauthtool ──socket──> bbauthtoold (uid 2911, gid 2900)  ──> RTAS auth/sign
vtnvfsd ──fuse──> /nvram/{nvuser,perm,boardid,prdid,blog} (gid 2900)
libbbusb ──> /dev/usb_blackberry ──> bb USB gadget (loader/fastboot)
libbbry_vs ──QMI──> modem NV/EFS; Binder IDiagnosticService
```

Observation: **gid 2900 links `bbauthtoold`, the `/nvram` fuse mounts, and several
daemons.** That group is the BlackBerry trusted-platform boundary and a prime focus.

## Next RE steps
1. Static-decompile `libbidejni.so` ioctl paths (`send_bide_ioctl`) to enumerate BIDE
   ioctl command numbers → map against the kernel `bide_*` symbols.
2. Enumerate `/dev/socket/tokenservice` protocol from `libbb_tokenservice.so`.
3. Audit `libbbry_vs.so` `IDiagnosticService` (ddt_*) for fd/path confusion.
4. Dump the BIDE kernel driver's sysfs (`/sys/devices/virtual/bide/bide`) as root later.
5. Compare `pathtrust_cdev_ioctl`/`bide_*` kernel code against the Priv BIDE/Pathtrust audit.
