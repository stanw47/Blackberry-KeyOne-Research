# 69 — Root-daemon & permission deep dive (avenues 1+2): all device-side walls mapped

Date: 2026-10-12 (session 69)

## Correction
`android.permission.ACCESS_SURFACE_FLINGER` (plain `signature`) was **never granted**
to the toolbox app (earlier session claim was wrong). Grant model is consistent:
only `signature|privileged` + weaker levels are granted to `/oem` priv-apps.

## Exfiltrated + decompiled (via priv_app read channel `run-as`, artifacts in
`~/Documents/bb-wine/keyone/re/` with Ghidra C dumps)

| binary | user | finding |
|---|---|---|
| `tctd` | **root** | socket `/dev/socket/tctd`; single factory command `traceability`; all `system()` calls take fixed strings; no exec/files driven by socket data. SELinux blocks shell+priv_app from its socket anyway. |
| `bkup_bc_update` | **root** | backup-bootchain updater; **exits early when `bbss_wp_type=permanent`** (our device) - dead. Otherwise would stage from `/system/vendor/backup_bootchain/*.pkg.gz` (immutable) and write BCB. |
| `pubmfgdata` | **root** | reads `/nvram/boardid/*`, `/nvram/prdid/*`, `/persist`, `/bbpersist`, `/data/config`; sets `ro.tct.*` props. All inputs unwritable by us. |
| `powerup_reason` | **root** | reads `/proc`, writes `/oempersist/minilog/powerup_reason/*`; bounded copies. |
| `vtnvfsd_wrapper` | **root** | execs `vtnvfsd` with fixed args. |
| `bb_tokenserviced` | token_service | see below - the token write service. |
| `diagnosticsd`, `smcd`, `dcmd`, `reset_cause` | misc | not yet fully analyzed. |

## The token system (fully decoded)
- `bb_tokenserviced` (user `token_service`, groups nvram+token) listens on
  `/dev/socket/tokenservice` (0660). Protocol: `[cmd byte][u32be len][payload]`.
  - `0x01` isTokenPresent(name); `0x02` **writeToken(blob)**; `0x03` cleanup.
  - Write blob = token file (54B header: 0=magic zeros, 8..47=procid,
    0x30..35=expiry "YYMMDD" ASCII; then name NUL; then payload NUL) +
    appended signature bytes. **Validation = expiry date only; NO crypto.**
  - Writes token to `/nvram/nvuser/<name>` (or `/nvram/perm/<name>` for
    hlos_signature.tkn / sw_rollback.tkn) plus sig record
    `{magic 0xAE104A54, type=2, len, sigdata}` as `.sig.<name>`.
- AIDL binder service **`TokenService` in system_server** relays to the socket!
  Transactions: 1=isTokenPresent (no perm check, works from shell!), 2=getTokenPayload
  (no perm check), **3=writeToken (requires `com.blackberry.permission.WRITE_TOKENS`)**,
  4=eraseTokens (same). Reads work from shell/app; writes denied
  ("You need Write Token permission").
- `WRITE_TOKENS` = protectionLevel **signature** (granted to **no package on the
  device**, only system). No app-level route.
- Tried the 7.1 `SystemConfig` `<assign-permission>` trick via
  `/oem/etc/permissions/00-bbtoolbox.xml` (grant WRITE_TOKENS to uid 2000/10103):
  **7.1 does not read `/oem/etc/permissions`** - no effect (verified live).
- Boot chain verification of nv tokens is ECDSA (DBGSIG) - forged tokens fail at
  boot regardless (expected).

## Permission / SELinux walls (avenue 2)
- platform.xml gid maps: ACCESS_NVRAM->nvram, ACCESS_MFG_CLIENT->mfg_client,
  ACCESS_NVRAM_PRDID->deviceid, DIAGNOSTICS_PRIV->system+shell+reset_cause+dcmd,
  DIAGNOSTIC->input+diag, ACCESS_OEMPERSIST->oempersist.
- All those perms are plain `signature` => not grantable to our app.
- `/nvram` FUSE: priv_app -> `vtnvfs_*_file` denied by SELinux (avc), independent of gids.
- Root daemon sockets (`tctd`, `tokenservice`): SELinux denies shell+priv_app
  (`{ read write }` on sock_file).
- Our app's actual granted set = the 17-20 `signature|privileged` perms
  (INSTALL_PACKAGES, WRITE_SECURE_SETTINGS, DUMP, READ_LOGS, MODIFY_PHONE_STATE,
  MANAGE_USERS, GET_TOKENS, ACCESS_BACKUP_TOKEN, ACCESS_NVRAM_PASSWORD_SERVICE,
  ACCESS_CACHE_FILESYSTEM, MANAGE_VOICE_KEYPHRASES, ...).

## Bottom line
Every reachable Android-side avenue tops out at "privileged system app"
(uid 10103, `priv_app` domain). Root needs an LPE. Most promising: kernel
LPE on **Linux 3.18.31-perf** (built 2018-11-21, gcc 4.9) - vulnerable to
CVE-2019-2215 (binder UAF) and other 3.18-era CVEs. kptr_restrict hides
kallsyms for shell (0000 addresses); KASLR assumed enabled. Kernel panics =
reboot only (recoverable); boot chain remains walled regardless (boot0 WP).
