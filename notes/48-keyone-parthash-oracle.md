# notes/48 — Pre-auth SHA-224 partition oracle (`oem parthash`)

Date: 2026-10-08
Discovery during RTAS-surface probing.

## The capability

```
fastboot oem parthash:<partition> <bytes>
```

- **No authentication.** The command is parsed and executed pre-auth.
- Returns `INFO<SHA-224 hex>OKAY` over the first `<bytes>` of the partition,
  starting at offset 0.
- Errors:
  - `Need partition and size in bytes` (missing args)
  - `Partition is in blacklist` → **`cache`, `userdata` are protected**
  - `Partition doesn't exist`
  - `Size must be less or equal to partition size`
- Hash implementation: SHA-224 (init @ `0x8f6ca210`, IV
  `c1059ed8 367cd507 3070dd17 f70e5939 ffc00b31 68581511 64f98fa7 befa4fa4`,
  digest length 0x1c). Handler @ `0x8f632ab0`; hex formatting via sprintf loop.
- Verification: `sha224(local file)` equals the oracle output exactly for
  multiple files (below).

## Verified device inventory (SHA-224 matches vs ABL766 package)

| Partition | Result |
|---|---|
| boot, recovery | **MATCH** local `boot.img` (identical to each other) |
| sbl1, tz, rpm, devcfg | **MATCH** local files |
| aboot (`<1952062` bytes) | **MATCH** local `emmc_appsboot.mbn` |
| aboot (full 2 MB) | differs — the partition **tail after 1,952,062 B is non-zero leftover** (not zero/0xFF pad) |
| AAK399/AAL093/AAN355 aboot prefixes | **no match** → device runs exactly the ABL766 image |
| bootsig | **MATCH** `sig/boot.img.production-sprint.sig` (sha224 `72065002…`) — only differed from the *generic* `boot.img.sig`; see notes/49 |

## What it changes for research

1. **Content fingerprinting without auth**: verify firmware identity and OTA
   state; confirm which build flash partition last (aboot probe matched only
   ABL766 among our four builds).
2. **Write-verification oracle**: any future write path (autoloader
   experiment, EDL, root) can be verified byte-exactly without raw read.
3. **Small-secret recovery**: e.g., devinfo's first 64 bytes could be
   brute-forced (few unknown flag bytes) against the oracle — a fun demo.
4. **Falsified hypothesis**: there is **no `bbss` partition** on the live
   device (`Partition doesn't exist`), nor `phyboot`. Prior note-41 inference
   (hidden factory GPT partition) is wrong; BSI storage must be elsewhere
   (candidate: `sec`, or another existing partition).
5. Not directly an unlock — information/verification only. But it is a real
   unauthenticated pre-auth interface.

## Tooling

`tools/parthash.py` — query / compare / list (raw libusb transport).

## Open items

- Locate BSI/`bbss_insecure` storage: candidates `sec`, `bbpersist`,
  `oempersist`, `oem` (name search in aboot scanned GPT for `bbss`; on this
  device that lookup fails — yet `oem info` returns WP type/insecure values,
  so the data comes from elsewhere).
- devinfo flag brute-force via oracle (optional demo).
- **Write channel FOUND (2026-10-09)** — `flash` is open for boot-chain-class
  partitions; modified `boot.img` written and oracle-verified; `persist` is the
  gated exception. See notes/49. Next: parser/exploit lanes (notes/49 §6).
