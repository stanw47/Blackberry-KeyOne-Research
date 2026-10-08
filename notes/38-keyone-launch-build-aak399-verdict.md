# notes/38 — Launch-build verdict: AAK399 also denies unlock

Date: 2026-10-08
Package: `bbry_qc8953_autoloader_user-common-AAK399.zip` (built 2017-04-28)

## Result: the denial exists at launch

- `emmc_appsboot.mbn` size 1,922,566, sha256 `90C1813AFBEEFAE0…`
- Strings present: `oem unlock is not allowed` (`0x8f6d4594`),
  `Device is unlocked! Skipping verification...` (`0x8f6d38ac`, zero refs),
  sparse validation (`0x8f6d4a64`), `authboot flash permission denied`.
- `set_device_unlock` @ `0x8f62c194`: **instruction-identical** to AAL093's
  (`cmp r1,#0` → `bne` → print `oem unlock is not allowed`); `cmd_oem_unlock`
  passes `(0,1)` and is denied; unlock-go only proceeds when already unlocked.
- SBL1 provenance: `BOOT.BF.3.3-00206` / `OEM_IMAGE_VERSION_STRING=AAK399`
  (AAL093 = 00211, AAN355/ABL766 = 00214).
- boot.img cmdline confirms `build_number=AAK399`, `imagetype=sfi`,
  `buildvariant=user`.

## Retail-line summary (all four public builds)

| Build | Date | aboot | `oem unlock` deny |
|---|---|---|---|
| AAK399 | 2017-04-28 | 1,922,566 | **present** |
| AAL093 | 2017-05-05 | 1,925,631 | present |
| AAN355 | 2017-08-07 | 1,949,815 | present |
| ABL766 | 2018-07 | 1,952,062 | present |

**Conclusion: no public retail KEYone build ever allowed `oem unlock`.** The
community claim "unlockable before it got a patch" is not supported by any
retail firmware; it is engineering-unit or KEY2 (kibo/ABL) conflation, or
refers to pre-retail builds that are not public.

## What the first week actually changed (AAK399 → AAL093)

String-set diff shows +10 / −0 new security validation messages, all
key-material hardening:

- `bide_validate_keypair: HW access disabled`
- `bide_validate_keypair: unable to decrypt the BIDE private key`
- `bide_validate_keypair: unable to derive the key that encrypts the BIDE private key`
- `bide_validate_keypair: validation test failed`
- `validate_ecc256_pub_priv: invalid octet to point public key conversion`
- `validate_ecc256_pub_priv: invalid sign R operation`
- `validate_ecc256_pub_priv: verification failed`
- plus `failed to write to swc_process file`

So the launch aboot had weaker keypair validation; the May 3 update added
BIDE/ECC validation. The unlock gate itself never changed.

## Implications for the unlock hunt

- The `oem unlock` route is dead on every public build — no downgrade target
  exists that would enable it.
- Remaining software path = **memory corruption in aboot** (auth/key-material
  parsers, TZ milestone interface) or the engineering-state angle
  (`bbss_insecure`); the AAK399 aboot adds an extra, oldest diff baseline.
- All four aboots are preserved locally under `firmware/keyone-*/` for
  function-level diffing.
