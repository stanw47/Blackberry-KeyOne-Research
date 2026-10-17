# 84 — THE COMPLETE EXPLOIT CHAIN, PROVEN LIVE (A14): pre-auth token -> is_sig_valid overflow -> panic

Date: 2026-10-16 (session 83/84) — device: KeyOne 1164118297 (now in panic loop, see §5)

## 1. RESULT
A forged vtnvfs token + hidden signature file, written pre-auth via the meta path into the
`perm` partition, causes the ABL to execute the **only memory-corruption bug in ABL766**
(`is_sig_valid`'s unbounded second memcpy) **on every boot path** (fastboot var publish and
`verify_hlos_image`), reaching the canary check -> `__stack_chk_fail` -> `_panic`.
Observed: device hung at splash; fastboot never re-enumerated; both chains inaccessible.

## 2. THE RECIPE (all offsets/semantics verified byte-exact against stock perm.img)

### 2.1 vtnvfs image (256KB, = exact perm partition size)
- Superblock (block 0): magic 0x0903fade, ver 0x00090200, name@0x30 ("perm"),
  **crc@0x5c = zlib.crc32(sb[0:92])**.
- Record slots = blocks 1..9. Record block:
  `{u64 bitmap @0x0 (bit b = inode b), u32 magic 0xf0deed0f @0x8,
    entry[b] = {u32 id, u16 block, u16 span} @0xc+b*8}`,
  **trailer @0x1FC = zlib.crc32(block[0:0x1FC])**.
  - **id = FNV-1 of the file name** (h=0x811c9dc5; per byte: h=(h*0x01000193)&0xffffffff; h^=byte).
    Verified: "bootcontrolblock" -> 0x95e7ddbf (stock), "ramdumpinfo" -> 0xbe8d59d9 (nvuser).
  - Stock slot1 = bitmap 0x2 (inode 1) -> entry[1] @0x14 = {id,13,3}.
- File = dirent block (+ inline data) + continuation blocks (span):
  - dirent: [4]=0x33 (type), **[5]=namelen**, [8]=id (== record entry id),
    [0xC]=own block (u16), [0xE]=span (u16), [0x10]=size (u32), [0x14]=0xa,
    **[0x18]=crc2 = zlib.crc32(file data)**, name @0x30 (variable length),
    **data @ 0x30+round4(namelen)** (4-ALIGNED! the #1 bug we hit),
    **crc @0x0 = zlib.crc32(dirent[4 : 4+44+round4(namelen)])** (range depends on namelen!).
  - span must satisfy: 48+round4(namelen)+size <= span*512 (1 block = 512).

### 2.2 The two files for the chain
- `/perm/hlos_signature.tkn` (name 18 chars; id=0xa7144ea9): body = token text,
  e.g. `hlos_sig\0key_name = "DBGSIG-bbb100usa"\ntag_override = "sprint"\n`
  (entries are `name = "value"` per dbg_token_find_entry_value).
- `/perm/.sig.hlos_signature.tkn` (name 23 chars; id=0xf6ca3206; hidden, leading dot):
  file = {u32 magic 0xae104a54, u32 ver=1, u32 len=len(blob)} + blob
  - blob = `{u16 L1; u16 L2; data[L1]; sig[L2]}` with L1+L2+4 == len(blob).
  - data = items, **FORMAT = {u8 len, u8 type, payload[len]}** (LENGTH FIRST — the #2 bug!):
    item5 = {0x04, 0x05, "BOOT"}; item6 = {0x40, 0x06, 64 bytes} (contents don't matter).
  - sig  = {0x30, 0x81, L2-3, 0x02, sl, 0x02, s_len, s_bytes[s_len]} with L2 = sl+7+s_len
    and (L2-3) must fit a byte => s_len <= 251.
    sl = r-length (first memcpy, dest sp+76); s_len = overflow length (second memcpy,
    dest sp+144). s_len=251 smashes canary (sp+212), saved regs (220..251) and LR (sp+248..).

### 2.3 Delivery
- Meta container (note 67): magic 0xCE1AD63C @0, u16 count*0x50 @0x4a, entry @0x4c
  {name[0x48], off@+0x48, len@+0x4c}; `fastboot flash boot <meta>` with an allowed outer
  name. Entry name "perm" -> mmc_write of the full 256KB.
- **Mount fd is cached per boot: reboot-bootloader required for a fresh mount.**

## 3. THE VERIFY CHAIN (why it fires)
`parse_hlos_signature_token` (0x8f63c438, called from fastboot_publish_hlos_sig_tkn
0x8f63c540 at fastboot init AND verify_hlos_image at boot) ->
`dbg_token_read_payload` -> `nvverify_verified_read` (0x8f657fdc) ->
`verify_rec_data` -> `get_sig_path` = "<dir>/.sig.<base>" ->
`nvverify_verify` (0x8f657c3c: sig magic/ver/len checks; rtas_init_ctx("DBGSIG");
`rtas_verify_nv_sig_response` -> `parse_response` -> `find_challenge_item`(5,6) ->
**`is_sig_valid` 0x8f658f30: memcpy#1 (sp+76, sl), memcpy#2 (sp+144, s_len) = THE BUG**
(both bounded only by blob fields) -> ECDSA -> canary check -> `_panic` (0x8f679cb4).
- requires_verification(.tkn) = TRUE always (is_image_mfi/is_dev_insecure are hardcoded 0).
- key = "DBGSIG-<device_id>", device_id = bsi("product")+bsi("variant") = "bbb100usa".

## 4. WHAT THIS UNLOCKS
Pre-auth, attacker-controlled execution of the stack-smash primitive. Remaining obstacle =
the per-boot TZ canary. With a canary leak (or the Priv's possible LCG fallback):
ROP via the saved LR (sp+248) -> LK code exec -> `set_bootmode`/`rpmb_write_record`
from LK context -> FACTORY_MODE -> unlock.

## 5. DEVICE STATE + RECOVERY NOTES (KeyOne 1164118297)
- Every boot path reads /perm/hlos_signature.tkn -> panic before USB/fastboot. Primary and
  backup chains both inaccessible (user confirmed). Not corruption: SBL1/ABL/partitions intact.
- Software recovery options are exhausted short of EDL (ruled out: no valid programmer for
  fused key hash) or service. If any fastboot prompt ever appears:
  `fastboot flash boot meta_perm_stock.img` (stock perm, hash 5978fd6a…) restores it.
- Backup-chain entry: Power+Mute (AAK171); its aboot may or may not read the token.

## 6. NEXT (Priv testbed — same code family, device still connected)
Replicate §2 on Priv (AAW068, AAC603 backup) `perm`/`nvuser` vtnvfs (256KB templates in
recon / imggen). Priv TZ may have the LCG canary fallback (deterministic!) — check first.
Then: canary leak hunt / ROP -> set_bootmode -> factory mode.

## 7. FINAL KEYONE STATE (end of session) + Priv continuity

### KeyOne 1164118297 — CONFIRMED LOST (end of session)
- State: stuck at BlackBerry / "Powered by Android" splash; LED blink pattern 101111; never
  reaches Android; **no USB enumeration at all; no power-off via any button combination**.
- Diagnosis: the ABL panics before USB/fastboot init (every path reads the token -> overflow
  -> `_panic`). Button combos (incl. backup-chain entry) are handled by the hung ABL => dead.
  Not storage corruption; the CPU just spins in the panic loop (screen on = battery drains).
- Final options (all effectively out): EDL (no valid programmer / user constraint), board-level
  force (no tools), service. If any fastboot prompt ever appears:
  `fastboot flash boot meta_perm_stock.img` (stock perm; hash 5978fd6a99b88f15...).
- **LESSON FOR ALL FUTURE TARGETS: the trigger is UNCONDITIONAL at every boot (fastboot
  publish + image verify both read /perm/hlos_signature.tkn) => the first wrong guess bricks
  the device exactly like this. On any next device: (1) verify the recovery path (backup chain
  entry + its flash gate) BEFORE triggering; (2) prefer a canary leak over a guess.**

### Priv continuity (testbed for the exploit — device alive, in fastboot)
- Priv = MSM8994, AAW068/venicena; partition map via `/sys/class/block/*/uevent` PARTNAME:
  **p22=perm (256KB — same as imggen template), p23=nvuser, p11=blog, p6=prdid, p8=boardid.**
- The full chain EXISTS in the Priv aboot (strings): `/perm/hlos_signature.tkn`, `.sig.`,
  `DBGSIG-venicena`, `hlos_signature debug token not valid...`, `scm_call for random failed !!!`.
- **Canary = likely deterministic!** `get_canary` 0xf916e3c: scm_random -> on failure `rand()`;
  `rand` 0xf971798 = LCG `seed = seed*12345 + 17`, seed global 0xfa63058, **single caller**
  (the canary fallback!) => if the 2016 TZ lacks the random service, canary = first rand() =
  **0x11**, every boot. Canary global = **0xfa81584**.
- `is_sig_valid` 0xf953e80 region: **same frame as KeyOne** (r @sp+76, s @sp+144,
  canary @sp+212, saved LR @sp+248) => the A14 payload maps 1:1.
- Command whitelist (35 entries): flash:/erase:/download: = type 1; getvar:/reboot/oem info = 0;
  oem set-product-mode = 1; oem securewipe = 0 (flag).
- **PRIV BLOCKER: type-1 flash gate = BBSECFW "devicepassword"** (0xf93e8bc -> 0xf93e730 ->
  0xf93f348; reads `devicepassword` record from nvuser; ALL type-1 commands denied on the
  primary incl. set-product-mode). Partition table (56 entries): boot/system/oem = type 0x1,
  perm/nvuser/blog = 0xa.
- **Probe image built**: /tmp/opencode/meta_priv_probe.img (token `DBGSIG-venicena` + sig blob
  with items {len,type,payload} + **s_len=69, canary byte0 = 0x11** -> tests "canary==17"
  with only 1/256 risk if TZ RNG works).
- Backup chain (AAC603, abootr.img in /tmp/opencode/priv_bc/): same whitelist + strings;
  is_sig_valid refactored (worker 0xaf250 — different frame, so only the PRIMARY takes the
  smash). Plan: boot backup (Power+Mute) -> `oem set-product-mode` gate test -> if OKAY:
  `fastboot flash boot meta_priv_probe.img` -> `fastboot reboot` -> primary boots -> canary
  test (alive = canary 17 = WIN; panic = RNG works).

## 8. THE RECOVERY PATH (EDL) — kit is ready, entry is physical

- **The BB-signed MSM8953 firehose is ON DISK**: `recon/2026-10-02/autoloader/ABL766 -
  Hn03/target/product/bbry_qc8953/qcbc/fh/prog_emmc_firehose_8953_ddr.mbn` (340KB ELF; from
  the official retail package -> signed with the retail PBL key; supports program/read/erase).
- Plus: `gpt/rawprogram0.xml` (full QFIL plan incl. perm @ start_byte_hex 0x1998b000),
  bkerler/edl tool (priv-research/edl/edl), repair image /tmp/opencode/meta_perm_stock.img.
- **Entry = hardware-only** (software dload compiled out — notes/39 + priv log §15):
  1. Teardown (iFixit/vrm24 guides; also disconnects battery = the only way to power it off).
  2. Short **eMMC CMD (or DAT0) to GND** during power-up -> flash init fails -> PBL falls
     to EDL (05c6:9008). Or short the JTAG-sense points (`pbl_sense_jtag_test_points_edl`).
  3. `edl --loader prog_emmc_firehose_8953_ddr.mbn printgpt` -> `edl w perm <stock img>` ->
     reboot -> alive (userdata untouched).
- **The KeyOne's exact TP locations are NOT publicly documented** (searched 2026-10-17:
  XDA thread 4207481 dead-end, no BBB100 TP photos; SaintPepsi/claude-on-blackberry#4 is the
  analogous open PCB-mapping task for the Priv). Research targets: repair-forum boardview
  files, CrackBerry thread, or probe the Toshiba eMMC CMD ball -> via (multimeter).
- Beyond recovery: BB-signed programmer => full eMMC R/W + peek/poke (bkerler's public
  `009720e1..._fhprg_peek.bin` MSM8953) => the HWI/vendor-CMD56 route to the actual unlock.

## Artifacts
- /tmp/opencode/meta_perm_A14.img (the trigger), meta_perm_stock.img (repair),
  perm_A12/A13/A14.img, hwi_store.bin, note 83 (full session log).
