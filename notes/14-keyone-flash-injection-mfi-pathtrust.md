# KEYone — Flash-Injection / MFI / Pathtrust / Alternate Root

Date: 2026-10-02

## 1. Can we inject during flash like the BB10 autoloader? — NO (proven)

`aveflash.lua` / `avecommon.lua` (the KEYone autoloader) reveal the security model:

### `flashImages()` (avecommon.lua:942)
Plain `fastboot flash <partition> <file>` — **no client-side crypto verification**. So the
autoloader WILL write whatever file you give it.

### `check_signature_files()` (avecommon.lua:618) + `start_write_sig_files()` (:491)
Reads `getvar security`, `hlos_signature.tkn`, `hlos_unsigned.tkn`, and flashes the 208-byte
`bootsig` / `recoverysig` **signature tokens** from `sig/`.

### The device enforces (avecommon.lua:718-737)
```
if security == enabled:
   if hlos_unsigned.tkn == disabled:
      "Error Loading Specified Image on Secure Device"
      "ERROR: Image is not signed for your device type."
      return ESIG
```
**The device refuses to boot an image not signed with its expected token.** This is the wall.
BB10 root worked because BB10's boot chain accepted the repacked OS; BlackBerry Android does not.

## 2. THE MFI FINDING (new)

```lua
-- avecommon.lua:515
function match_sig_tag(token, sigtag, hlossigtag)
    if (token == "ADBI") or (token == "ABBI") or (IMAGE_TYPE == "mfi") then return true; end
```

**`IMAGE_TYPE == "mfi"` makes the autoloader accept ANY signature tag.** `config.lua`:
```
IMAGE_TYPE="sfi"     <- ours; flip to "mfi" and the autoloader stops enforcing sig tags
```

So an **MFI autoloader** would flash a foreign/unsigned image. **BUT** the *device* must also
be in MFI mode — governed by `androidboot.imagetype=mfi` in the boot cmdline, which comes from
the **signed boot image DTB** (notes/13). MFI is a **paired** feature: autoloader + boot image.
We can produce the first (edit config.lua); we cannot produce the second without signing.

## 3. Pathtrust whitelist — present but NOT writable

- `/pathtrust_contexts` exists on rootfs -> **permission denied**; rootfs is read-only.
- Kernel has full Pathtrust LSM: `pathtrust_selctx_load`, `pathtrust_write_selinux`,
  `pathtrust_enforce`, `pathtrust_cdev_ioctl`, `pathtrust_dev_trusted`.
- BB10's Pathtrust trick needed a **writable `/proc/boot`**; Android has **no `/proc/boot`** and
  an immutable rootfs. **The BB10 root technique does not transfer.**

## 4. Alternate root paths

| Path | Viable | Notes |
|---|---|---|
| BB10-style modded autoloader | ❌ | device rejects unsigned (`hlos_unsigned.tkn:disabled`) |
| MFI autoloader (`IMAGE_TYPE="mfi"`) | ⚠️ half | needs device also in mfi mode (signed DTB) |
| Pathtrust whitelist edit | ❌ | read-only rootfs, no /proc/boot |
| Kernel LPE (3.18.31, Dec 2016) | ⚠️ maybe | old kernel, but GRSecurity/PaX + BIDE active |
| **`bbauthtool`/RTAS2 bootloader fuzz** | 🎯 best | un-hardened BB-specific parser (notes/11) |

## 5. Root-as-prerequisite conclusion

Root requires either a kernel LPE (blocked by BIDE/Pathtrust/grsec) or boot-chain compromise.
**Two live threads:**
1. **`bbauthtool` RTAS2 protocol** — largest un-hardened, BlackBerry-specific parser at
   bootloader privilege. Prime target for a KEY2-style bug.
2. **MFI pairing** — tokens reach the cmdline (`system_dbg.tkn` -> adb.mode, loglevel). If ANY
   token/mechanism can set `androidboot.imagetype=mfi` on the device, the whole chain opens.

## Files
- `firmware/keyone-abl766/ABL766 - Hn03/aveflash.lua`, `avecommon.lua`, `config.lua`
- `firmware/.../target/product/bbry_qc8953/sig/*.sig` (208-byte boot sig tokens)
- `notes/11` (RTAS2), `notes/13` (imagetype source)
