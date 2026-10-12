# 66 — Pre-auth parser memory-corruption audit (complete) + full pre-auth command whitelist

Date: 2026-10-12 (session 66)

## Part 1 — Audit results

Full static audit of the pre-auth parser surface (ABL766, `recon/2026-10-02/re/aboot.disasm.txt`).
Verdict: **every parser is bounded; the only memory-corruption bug remains `is_sig_valid`
(stack canary wall, per-boot random, no leak found).**

| # | Target | Verdict |
|---|--------|---------|
| 1 | `usb_receive_msg.constprop.2` (0x8f638a08) | read capped 1024 into 1088 stack buf; n must be 8..548; cookie `0xbba78701`; `memcpy(dst, buf, n)` with n<=548 |
| 2 | `usb_thread` (0x8f638b58) | `new_msg(0, 548)` exact-fit; no overflow possible |
| 3 | `bbauthtool_evtq_push` (0x8f6393a8) | stores pointer only (256-entry ring); no copy |
| 4 | `get_key` (0x8f65a270) | heap exact `strlen+strlen+2` |
| 5 | handshake 0x2000 (event_thread case) | tool name at msg+27, NUL-enforced, <=15 chars |
| 6 | `password_chall_verify_v1` / `password_challenge_verify` | fixed 64, length-equality checked before memcmp |
| 7 | `cmd_oem_get_part_hash` (0x8f632ab0) | `cu_strtoll` 64-bit, nonzero check, unsigned partition-size bound (negatives/huge rejected), chunked SHA224 |
| 8 | `dbg_token_validate` (0x8f63b770) | `strnlen` within remaining, mandatory NUL, name cap 20; payload size = actual remaining (no declared-size trust) |
| 9 | `nvverify_verified_read` (0x8f657fdc) | caller size >= record size enforced; `memcpy = min(size, rec)` |
| 10 | `verify_hlos_image` tag override | `strlen <= 31` cap + exact length match |
| 11 | format strings | 1529 `_dprintf` / 49 `printf` / 70 `snprintf` / 25 `sprintf` — all format args constant; only reg-passed `_dprintf` = `exception_die` (internal constants) |
| 12 | malloc+sprintf (`get_dev_id`, `get_rec_path`) | alloc = `strlen(a)+strlen(b)+1` with `"%s%s"` — exact |
| 13 | `cmd_oem_read_protected` / `cmd_oem_read_partition` | `strstr`/`strncpy` <=64 caps, permission-gated, `mmc_read` clamped to partition bounds |
| 14 | `process_rtas_has_permission_event` (0x8f63a254) | session lookup + timeout + query; no copies |
| 15 | `get_perm_item` (0x8f637c4c) | **exact match** (strncmp + strlen equality) — no prefix/canonicalization bug |
| 16 | `fastboot_handler` command RX (0x8f62f0c8) | `memalign(64,4096)`, chunked reads, NUL at buf+len |
| 17 | `oem erase-ddr-training-*` handlers | no arguments, hardcoded targets |

### Corrections to earlier notes
- notes/44: "queues RX via `0x8f62617c`" is wrong — `0x8f62617c` is
  `arch_clean_invalidate_cache_range` (cache maintenance). The real read is a
  function pointer at `[0x8f7bc28c + 0x20]` (USB read with 64-byte chunks).
- The `-11` path in `authboot_check_permission` just retries
  `rtas2_cmd_authorization_check` once with identical args — no logic hole.

## Part 2 — Pre-auth command whitelist fully decoded

`authboot_cmd_whitelist` @ `0x8f6de194`, 38 entries x 16 B `{name_ptr, type, 0, 0, flag->LAL@12}`.
Gate chain: `fastboot_handler` -> `authboot_check_command_permission` (0x8f638168)
-> `authboot_check_permission` (0x8f637e0c) -> type switch:

- **type 0** — allowed; `flag@12==1` only logs an LAL event (add_lal_event 67).
- **type 1** — `rtas2_cmd_authorization_check(1, 0, 0)` -> allowed (calls `auth_password()` first).
- **types 2..10** — permission IDs 0x1000..0x1008 are queried via
  `auth_rtas_has_permission` (0x8f6386e8): internal socket 0x1014 ->
  `process_rtas_has_permission_event` -> `rtas_has_permission(session, id)`.
  No authenticated RTAS session => denied. (This is the "authboot command
  permission denied" we see live.)

### Allowed pre-auth (types 0/1)
```
type 0: getvar:  reboot  reboot-bootloader  continue
        oem securewipe          (flag=1, LAL-logged — DESTRUCTIVE, do not run)
        oem enable-usb-shutdown
        oem info
type 1: flash:  erase:  download:          (command level; partition-level check still applies)
        oem enable-usb-reset  oem led:  oem setled:
        oem parthash:                      (explains the working read oracle)
        oem set-product-mode               (flag=1)
        oem erase-ddr-training-primary     (flag=1)
        oem erase-ddr-training-backup      (flag=1)
```

### Denied pre-auth (permission IDs)
```
0x1000  oem getvarp:
0x1001  oem gptinfo  oem blocklist-wipe  oem format  oem test-ddr  oem bide-storage-wipe
0x1002  oem grswipe
0x1003  oem clear-anti-theft
0x1004  oem set-factory-mode               (matches live denial, notes 19/53)
0x1006  oem mmcinfo  oem ddrinfo  oem bootlog  oem read:  oem dmesg  oem mmchealth  oem clear-lal
0x1007  oem setprd:  oem bootmetrics  oem enable/disable-charger-screen  oem console
```

### Residual notes (not exploitable as-is)
- `oem set-product-mode` is type 1 (allowed) and calls `set_bootmode(1, 0)`;
  its symmetric `oem set-factory-mode` is type 6 (denied). Production-line
  asymmetry appears intentional.
- `flash:` is type 1 at command level; the gate is
  `authboot_check_partition_permission` inside `cmd_flash_mmc`
  (boot chain type 1/0x100 flashable; `persist` denied; `bbss` absent from table).
- `oem securewipe` being type 0 is a potential wipe-by-USB hazard — recorded
  for completeness only.

## Conclusion
The pre-auth parser surface is clean. The command-permission model is exact-match
and correctly gates every interesting operation behind RTAS (which requires an
ECDSA P-521 response to a device-generated ECIES-encrypted challenge).
No new memory-corruption or logic-bypass primitive was found in this pass.
