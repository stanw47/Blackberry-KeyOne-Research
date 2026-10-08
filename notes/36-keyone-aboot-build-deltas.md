# notes/36 — aboot build deltas: AAL093 → AAN355 → ABL766

Date: 2026-10-08
Method: whole-image string-set diff (the MBN carries no symbol table — it is
not a standard ELF with section headers; only the load segments are ELF-like),
cross-checked with `tools/lk_xref.py` / `lk_disasm.py` for the unlock region.

Builds: AAL093 (first OTA, pkg 2017-05-05), AAN355 (Aug SMR, pkg 2017-08-07),
ABL766 (Sprint 7.1.1, pkg 2018-07).

## What did not change

- `oem unlock is not allowed` denial — present in all three, identical logic.
- `bbss_insecure` read/write machinery, `"Unable to update bsi bbss_insecure"`.
- `km_secure_write_protect`, `bide_generate_keypair`, `auth_key_material`,
  `km_hash failed`, `generate_and_sign_authN`, `qsee_hmac`, RTAS strings
  (`rtas2_cmd_authorization_check`, `auth_rtas_has_permission`, `bbauthtool:`).
- `"Anti-rollback protection disabled due to token presence"`.
- Sparse-header validation string (`buffer overreads … invalid sparse header`).

## Delta 1 — AAL093 → AAN355 (May → Aug 2017): TZ/QSEE key-generation wave

*+259 strings / −49 overall; +63 / −1 meaningful security strings.*

New message families (all TZ/QSEE-backed):

- `derived_key_init: qsee_kdf …`, `generate_kek_derived_key: do_crypto …`
  — KEK derivation through a QSEE KDF.
- `do_crypto: qsee_cipher_encrypt/decrypt/set_param …` — TZ cipher plumbing.
- `generate_ecc256_pub_priv` / `generate_ecc521_pub_priv` (genKey,
  point2Octet, do_prng) — **on-device ECC P-256/P-521 keypair generation**.
- `get_bsis_private_key: Hash mismatch`, `sign_with_bsis_priv` — BSIS private
  key store and signing.
- `do_hmac: qsee_hmac …` (hmac already present; error paths expanded).

Interpretation: the secure-provisioning/authbroker stack (RTAS/BSIS) matures
hard in mid-2017 — on-device keygen + wrapped-key handling appear. This is the
ancestry of the key architecture we see in ABL766.

## Delta 2 — AAN355 → ABL766 (Aug 2017 → Jul 2018): key-material validation + TZ bootstrap

*+216 / −267 overall; +11 / −62 meaningful security strings.*

Removed: the raw qsee_kdf/qsee_cipher/ECC-keygen/BSIS-key message family
(refactored or replaced by key-material plumbing).

Added:

- `"Failed to validate key material size:%d"`
- `"alg_offset validation failed after decryption:%d"`
- `"auth_key_material failed for meta_data hash method"`
- `"auth_key_material failed in %s with ret:%d"`, `"km_hash failed in %s …"`
  — wrapped/encrypted key material is now **validated after decryption**
  (size + algorithm offset).
- `bide_generate_keypair: unable to get private key` (returns, reworked).
- `Qseecom Init Done in Appsbl version is 0x%x` — QSEE bootstrap in ABL.
- `send_milestone_call_to_tz: set_tamper_fuse_cmd (HLOS_BL_MILESTONE_FUSE)
  fails!` — **boot-milestone / tamper-fuse calls to TZ** (new), matching the
  `devinfo.is_tampered` machinery.

Interpretation: no new unlock features; the 2018 work is key-material
hardening (decrypt-then-validate), TZ milestone/fuse accounting, and refactors.

## Implications for the unlock hunt

1. The unlock gate is a **constant** across the whole retail line — no build
   regressed it, none removed it. The XDA "unlockable before a patch" claim
   cannot be about AAL/AAN/ABL; only the launch AAK branch (April 2017) is
   untested.
2. The most-changed/most-complex code between builds is the **auth/key-material
   path** (RTAS/BSIS, decrypt-and-validate) — a sensible place to hunt parser
   bugs, but it consumes authenticated key blobs.
3. New TZ entry points in ABL766 (`HLOS_BL_MILESTONE_FUSE`, qseecom init)
   widen the aboot→TZ interface; worth disassembling for argument-validation
   bugs in a follow-up.

## Next

- Pull AAK399/AAK879 (April 2017) and run the same unlock-region check to close
  the launch question.
