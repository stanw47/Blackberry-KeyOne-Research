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
