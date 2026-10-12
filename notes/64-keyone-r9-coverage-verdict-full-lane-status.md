# notes/64 — r9-coverage verdict (closed) + full-lane status

Date: 2026-10-12. KEYone BBB100-3 ABL766. Related: notes/61 §6, 63.

## r9-coverage (signature-transfer) — CLOSED

Decoded the exact hash range in `boot_linux_from_mmc` (0x8f62a2c0–0x8f62a4a0):

```
r9 = page_size
   + round_up(kernel_size   @0x08, page)
   + round_up(ramdisk_size  @0x10, page)
   + round_up([0x28]        (= 0 in this image), page)
   + round_up(vendor_hsize  (bbry_get_vendor_hsize), page)
   + round_up(second_size   @0x18, page)
```

Measured on the shipped boot.img: `2048 + 18530304 + 2211840 + 0 + 2048 +
8265728 = 29,011,968` = **exactly the full image size**. The `second` blob
(8.26 MB gzip — the DTB collection) is inside the hash; `dt_size`@0x28 = 0;
the vendor term is the final 2048-byte page.

**Verdict: the ECDSA signature covers every byte of the boot image.** No
uncovered-byte transfer, no DTB/cmdline edits with the signature intact.
The image-verify lane is conclusively closed.

## Full-lane status (end of session)

| Lane | Status |
|---|---|
| RTAS permission lane | Behind the ECIES+ECDSA challenge — cryptographically closed |
| Challenge response (self-signed/static/replay) | Impossible (notes/62) |
| NV-SIG door (0x1016 → is_sig_valid) | Reachable pre-auth (notes/63 §8) — but canary-walled, values ECIES-encrypted, no success observable, crashes cost a manual reset |
| Image verify / r9 | Full-image ECDSA (this note) |
| Tokens | Absent, unforgeable, write path RTAS-gated |
| Fastboot parser surface | getvar long-name = host artifact (notes/47); download:0 = assertion DoS only (notes/47); parthash/getvarp/read arg parsers exercised extensively — no corruption primitive found |
| Kernel lane (KGSL etc.) | Panics on escalation (user: not viable) |
| EDL | Physically unreachable |

## Thin remaining options

1. **ECDSA verifier impl-bug sweep** via the NV-SIG door (canary-safe r/s
   values; blind — a pass has no USB observable, but crashes are detectable).
   Low odds, cheap, the only remaining pre-auth code path with a crypto bug.
2. **Canary leak hunt** — no vector found so far (parthash reads flash only;
   challenge values are encrypted).
3. Fresh static review of unexamined pre-auth parsers (notes/39 list).

---

## ADDENDUM (later same day): the bbss_insecure corner — CLOSED, with precision

Prompted by the backup-chain question ("is the backup bootloader only for
flashing?"): yes — recovery-flashing mode running an April-2017 image (AAK171).
We extracted **AAK399** (its retail sibling/proxy) and ran era diffs:

### 1. RTAS verifier stack = instruction-identical AAK399 <-> ABL766
Normalized instruction diff (only canary-global + dprintf string addresses
differ): `is_sig_valid` 120/120, `sb_ecc521_verify_sign` 178/178,
`rtas_verify_response` / `_nv_sig_` / `parse_response` / `find_challenge_item`
/ `get_key` / `sb_sha_512` / challenge builders — all logic-identical;
`husw_ECDSANoHashVerify` / `hu_ECDSANoHashVerify` byte-identical.
**No weaker crypto/parser target in the old era.** The only security-relevant
era delta = the BIDE/ECC keypair-validation functions (AAL093+) — a separate
BIDE keypair store, **not** the bbss tag path.

### 2. Partition whitelists = identical (both eras)
Full `authboot_ptn_whitelist` dumped for ABL766 and AAK399: **same entries,
same types, same flags** (phyboot* = type 3, nvuser = type 10/0x100,
debug_token/all_debug_tokens = type 7, persist = type 4, …). **`bbss` is
absent in both** -> `flash bbss` = "authboot flash permission denied" in the
backup chain too. No era downgrade for the write gate.

### 3. Hidden partitions are not addressable pre-auth (read either)
`oem parthash:bbss:…` -> `FAILED (remote: Partition doesn't exist)`; same for
phyboot*/bsis/bsi. The UTF-16 "bbss"/"hwi" names exist in both builds (the
dedicated GPT-scan literal for the hidden LUN), but the LK's *addressable*
partition table (used by parthash/flash/getvar) does not resolve them.
So: no pre-auth read of the BSI tag store either.

### 4. Net
`bbss_insecure` is a **plaintext numeric tag (≤0xFF, unsigned)**; flipping it
= instant boot bypass ("proceeding with boot anyways" / "Insecure bootchain
detected. Skipping fuse verification check"). But every pre-auth path to it
(read + write) is closed in both eras. **The data route needs EDL, root, or an
aboot code-exec primitive — nothing else.** (Matches notes/40-41 conclusions,
now era-verified.)

### 5. Tooling lesson (re-learned twice today)
Piping fastboot output through `head` kills the client mid-response (SIGPIPE)
and **wedges the device**; the **EP 0x81 drain recovers it** (no reset needed —
recovered twice today that way). Always redirect to files, never truncate
live fastboot output.
