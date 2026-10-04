# KEYone — NV-Verify Branch DECODED (the smoking gun)

Date: 2026-10-02  |  `emmc_appsboot.mbn` (LK, has symbol table)

## The branch (in `boot_linux_from_mmc`, ~0x8f62acb4)

Disassembly:
```asm
0x8f62acb4:  bl   bbry_is_secure          ; 0x8f654f88
0x8f62acb8:  cmp  r0, #0
0x8f62acbc:  beq  0x8f62accc              ; secure()==0 -> "proceed anyways"
0x8f62acc0:  bl   is_mfi                  ; 0x8f655028
0x8f62acc4:  cmp  r0, #0
0x8f62acc8:  beq  0x8f62b19c              ; is_mfi()==0 -> "Failing boot"
0x8f62accc:  print "NV Signature verification failed, proceeding with boot anyways"
0x8f62acd8:  b    0x8f62a598              ; CONTINUE BOOT  <-- BYPASS
0x8f62b19c:  print "Failing boot due to NV Signature verification failure"
0x8f62b1b0:  return -1
```

Reconstructed logic:
```c
if (bbry_is_secure() == 0)          // device reports insecure
    { warn("proceeding with boot anyways"); goto continue_boot; }   // BYPASS
else if (is_mfi() == 0)
    { warn("Failing boot due to NV Signature verification failure"); return -1; }
else
    { /* MFI path */ }
```

## The two decision inputs (globals)

| Function | Addr | Reads global | Meaning |
|---|---|---|---|
| `bbry_is_secure` | 0x8f654f88 | `[0x8f7948a4]` | secure-boot flag (set from `bbss_insecure` at boot) |
| `is_mfi` | 0x8f655028 | `is_mfi_var` @ 0x8f7bebd8 | MFI (manufacturing/factory) mode |

Also present: `bbry_is_insecure` (0x8f654f48), `is_secure_boot_enable` (0x8f616394),
`set_is_mfi` (0x8f655068), `is_image_mfi` (0x8f658d08).

## What this means

There **is** a code path where NV signature verification failure still boots. It is selected
by `bbry_is_secure()==0`, i.e. the secure-boot/insecure flag. On a retail device that flag is
secure (=1), so `bbry_is_secure()` returns 0... wait — the exact polarity must be confirmed at
runtime, but the naming `bbry_is_insecure` + `bbry_is_secure` both existing and the branch
structure make the intent clear:

- The bypass branch is reachable when the device is in an **"insecure"/MFI** state.
- Retail devices take the **"Failing boot"** path on verify failure.

### Why it still matters
1. It documents the **exact function and globals** that gate NV verification leniency:
   `[0x8f7948a4]` (secure flag) and `is_mfi_var` (0x8f7bebd8).
2. `set_is_mfi` implies MFI mode can be **toggled**; if the MFI flag becomes settable from a
   reachable state, the lenient path may open.
3. It mirrors the BB10 `FS_DIRTY`/`bbss` boot-policy design exactly.

## Reachability question (next)
- How is `is_mfi_var` set? (from NV? debug token? factory partition? MFI image header?)
- How is the secure flag `[0x8f7948a4]` initialized from `bbss.insecure`/boot0?
- Can either be influenced from a writable, un-signed location (token, NV record, mfi image)?

If the MFI flag can be flipped **without** unlocking the bootloader, the device would take the
lenient boot path — a potential route to booting a modified image.

## Related symbols to trace
```
set_is_mfi (0x8f655068), is_image_mfi (0x8f658d08)
is_secure_boot_enable (0x8f616394)
bbry_is_insecure (0x8f654f48), bbry_is_secure (0x8f654f88)
nvverify_verify (0x8f657c3c), nvverify_verify_all_required_recs (0x8f657f44)
```

---

## FURTHER: how MFI mode is decided (set_is_mfi decoded)

`set_is_mfi` (0x8f655068) scans the **kernel cmdline** with `strstr` for:

```
androidboot.imagetype=mfi    -> sets is_mfi_var = 1  (MFI mode)
androidboot.imagetype=sfi    -> is_mfi_var stays 0
```

Confirmed strings: `androidboot.imagetype=mfi`, `androidboot.imagetype=sfi`, `SFI`, `MFI`, `Image type : %s`.

### The chain
1. Device boots with `ro.boot.imagetype=sfi` (secure image) -> not MFI.
2. `bbry_is_secure()` returns secure -> branch skips the lenient path.
3. `is_mfi()` returns 0 -> takes the **'Failing boot'** path on NV-verify failure.

**If `androidboot.imagetype=mfi` were present in the cmdline**, `is_mfi()` returns 1 and the
code takes the **MFI path** instead of 'Failing boot'. MFI (manufacturing) images are expected to
be unsigned/development, so the MFI path almost certainly relaxes verification.

### Where the cmdline comes from
- `get_cmdline_from_token` (0x8f63cae8) appends token-derived values to the cmdline.
- `dbg_token_get_selinux_mode`/`pathtrust_mode` use the same mechanism.
- The boot cmdline is assembled in `bbry_update_cmdline` / `bbry_set_cmdline`.

### Consequence / next step
Find whether `androidboot.imagetype` can be set from a **writable** source (token, NV,
misc/bootconfig, MFI header). If yes -> MFI mode -> lenient boot path -> potential unsigned boot.
This is now the **primary software lead**: cmdline injection of `imagetype=mfi`.

