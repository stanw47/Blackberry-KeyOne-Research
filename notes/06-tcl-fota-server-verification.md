# KEYone Oreo/Frankenstein — Server-Side Verification (tcl-fw)

Date: 2026-10-02
Method: `tcl-fw` (vehoelite/tcl-fota-tool) queried **TCL's own FOTA servers** directly,
using the AES key cracked from `sugar_otu_r.dll` by Littlenine Ennea.

## Universal key (documented)

```
KEY = ascii( md5("TeleExtTest" + "t0523" + "jP7GHdmuBz").hexdigest()[:16] )
    = e26baba108b08a28
```
AES-128-ECB; used for the small partitions in the encrypted ~4 MiB FOTA header.
This is the key from Sugar's `sugar_otu_r.dll` — i.e. the "reverse-engineer Sugar" path
already exists and is public.

## Live server results — KEYone curefs

| Curef | Model | Latest build (tv) | Android | Notes |
|---|---|---|---|---|
| **PRD-63118-003** | BBB100-3 (Sprint, **this unit**) | **ABT855** | **7.1.1** | your DRD variant; latest ever published |
| PRD-63118-001 | BBB100-3 | ABP661 | 7.1.1 | the other -3 PRD (CrackBerry's Sprint patch) |
| PRD-63116-001 | BBB100-1 | **ABP819** | **8.1 Oreo** | global/unlocked US |
| PRD-63117-003 | BBB100-2 | ABT975 | 8.x | EMEA |
| PRD-63116-036 | BBB100-1 AT&T | ACG696 | 8.x | later Oreo |

**Confirmed: NO BB100-3 curef ever received an Oreo (8.x) build.** Every `-3` result is
7.1.1. This is server-side proof of the CrackBerry claim that the Sprint/CDMA `-3` was
never given Oreo.

## Device (live)

- curef: `PRD-63118-003`
- build: `ABL766`, Android 7.1.1
- `ro.boot.binfo.bbss_wp_type = permanent`
- `ro.boot.binfo.bbss_insecure = false`

## What `tcl-fw` can actually do for us

- Talks to TCL FOTA servers as the on-device updater does (no account/dongle).
- Lists a device's **complete service fileset** by curef.
- **Decrypts** the small partitions (lk/preloader/vbmeta/tee/atscatter) via the universal key.
- **Downloads** the large partitions as plaintext sparse images.
- **Verifies** signatures (public certs) — but **cannot sign**; the private key is in TCL's
  build HSM. "Nothing here bypasses verified boot."

So tcl-fw = **firmware acquisition + decryption + repack**, NOT a bootloader bypass.
It funnels into the same signed fastboot/authboot flash path.

## Meaning for the frankenstein idea

1. We CAN now pull **any variant's official firmware** (e.g. `-1` Oreo `system.img` +
   `-3` 7.1.1 `NON-HLOS`/`modemst`/`fsg`).
2. But installing the mix still hits:
   - locked bootloader + signed `bootsig`/`recoverysig`
   - permanent eMMC boot-partition WP (`bbss_wp_type=permanent`)
   - the same authboot flash path (no bypass)
3. Even if flashed, RIL<->modem mismatch + loss of `fsg`/`modemst` (IMEI/RF cal) would break radio.

## 2026 fastboot CVEs — applicability

- CVE-2026-24087 / 24091 / 24085 — memory corruption in fastboot OEM command processing,
  CWE-1286, CVSS 7.2, physical access. Same *class* as CVE-2021-1931.
- Affected CPEs are **modern SoCs** (SA8xxx, SM4xxx, QRB5165, SDX81, …). MSM8953 is EOL and
  receives no 2026 bulletins; the MSM8953 CVE feed ends Oct 2022.
- **Likely not applicable to the KeyOne** — same reason CVE-2021-1931 wasn't.

## Bottom line

- The `-3` Oreo never existed (server-confirmed).
- A cross-variant frankenstein is blocked by the signed/WP'd boot chain, not by firmware availability.
- `tcl-fw` gives us a legitimate, powerful firmware-acquisition/decrypt tool (useful regardless).
- The only real path to modern Android on the `-3` remains: **break the boot chain (hardware/EDL)
  → then port LineageOS on `msm8953/ABY299`**.
