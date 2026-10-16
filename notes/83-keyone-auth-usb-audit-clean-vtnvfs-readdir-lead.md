# 83 — Meta-path re-validation (live) + full auth/USB reply-builder audit (clean) + vtnvfs readdir namelen OOB lead

Date: 2026-10-16 (session 83)

## 1. Meta path re-validated LIVE (device 1164118297, fastboot)

- `fastboot flash boot meta_rcause2.img` (meta container, entry `rcause`, 1024 x 0xAA):
  - `oem parthash:rcause:1024` before `862d76859f62e76cb0f1642adf4899596fd7908de1672f0e1143e924`
  - after  `15c573215ff09dd1f3a11babd2e70990411ff26bbf7b135905d966b9`
  - => arbitrary closed-LUN0-partition write still works pre-auth (notes/67 stands).
- `boot0hwi` entry (our hwi_store.bin, bbss_insecure=true) re-tested:
  - flash HANGS THE CLIENT (device-side WP error; device unharmed).
  - `oem info` after: `Insecure: false`, `WP Type: permanent` — boot-LUN write still hard-blocked.
- Lesson: after a hung `fastboot flash`, the stuck client process holds the device;
  `pkill -x fastboot` (NOT `pkill -f`) recovers instantly; device is fine.

## 2. Auth/daemon USB surface — COMPLETE audit, all CLEAN

Checked every USB-facing sender and the receive path (ABL766):

| fn | verdict |
|----|---------|
| `respond_rtas_init_event` 0x8f63a080 (0x1013) | clean — `sock_send_msg` itself writes cookie `0xbba78701` @buf[0..3] + opcode @buf[4..7]; 12-byte msg fully defined |
| `process_rtas_has_permission_event` 0x8f63a254 (0x1015) | clean — 16B = cookie+opcode+status+result |
| `respond_rtas_sign_event` 0x8f63a37c (0x1017) | clean — `memset(sp+4,0,528)` first |
| `process_rtas_sign_event` 0x8f63a684 (0x1016→USB 0x2004) | clean — `memset(sp+8,0,524)` first |
| `send_rtas_challenge` 0x8f639e30 (USB 0x2004) | clean — `memset(sp,0,524)` first |
| `usb_send_msg` 0x8f638d48 | clean — local 1088B memset; writes cookie+opcode into sent buf[0..7] |
| `event_thread` 0x8f638e48: USB 0x2001 (548B), 0x2002 (32B) | clean — both memset before fill |
| `usb_receive_msg.constprop.2` 0x8f638a08 | clean — 1088B memset; n∈[8,548]; cookie check; memcpy n bytes |
| `sock_send_msg` 0x8f6392cc | writes cookie+opcode (no leak) |

Conclusion: **no uninitialized-memory leak on the auth/USB protocol surface.**
Tim's "read ABL memory" must be elsewhere (fastboot side / token path).

## 3. NEW LEAD — vtnvfs readdir: namelen > entry space (OOB write; leak gated)

Trigger chain: `oem info` (type 0, ALLOWED) → `dbg_token_fastboot_print_partition`
0x8f63bba0 → `get_dirlist` 0x8f63ba20 → `vtnvfs_readdir` 0x8f65ad54 →
`vtnvfs_readdir_drv` 0x8f65d52c. Token partitions (`perm`, `nvuser`) are
vtnvfs (magic `0xc001100c`), currently EMPTY ("None Found"), and **writable via
the meta path** (LUN0 closed partitions!).

Dirlist entry = **148 bytes**, layout (readdir_drv):
```
+0x00 u32 ptr (dir node)   +0x04 u16   +0x06/+0x07 u8 type nibbles
+0x08 u32  +0x0c u32  +0x10 u32
+0x14 name[strncpy(entry+20, src, len) + explicit NUL at entry+20+len]
```
`len = [sp+73]` = on-disk name length validated by `validate_and_copy`
0x8f65c3f8: record-size bound `44 + round4(namelen) <= 0xbf(191)`
(0x8f65c534) => **namelen can be up to ~144**, but entry name space is only
**128 bytes** (148-20) => `strncpy` + NUL write up to **16-17 bytes past the
entry**; for the last entry => past the calloc'd buffer => heap OOB (write).

Print path: `dbg_token_fastboot_print_partition` prints entry+20 with `%s`
only after `is_token_name` (0x8f63bb18): `strlen>=5`, `name[0]!='.'`,
`strncmp(name+strlen-5, "<suffix@0x8f6e012c>", 5)==0` — the suffix must land at
the END of the FULL strlen, so with OOB bytes after the name the gate fails
=> the `%s` leak on THIS path is blocked (needs OOB bytes to end in the
suffix — uncontrollable).

TODO (next session):
- audit `fastboot_publish_token_info` 0x8f63bf5c and `dbg_token_fastboot_print`
  0x8f63c15c for an UNGATED name print (getvar-published token info!);
- confirm the exact namelen cap and dir-node name allocation;
- decode the vtnvfs on-disk format (superblock 0xc001100c; see also
  blackberry-research cross-device notes) to craft a poisoned image;
- then: meta-write crafted vtnvfs to `nvuser` (or `perm`) → `oem info` → observe.

## 4. Position vs Tim ("unlock needs RPMB access")

- Insecure route (HWI store) = blocked by boot0 hardware WP on ALL standard
  write paths we hold (meta `boot0hwi`, raw `hwi:1` untested — GPT search is
  LUN0-only), and aboot has no EXT_CSD BOOT_WP switch (notes/67 §2).
- So the end state does need the RPMB boot-mode record (Tim is right about the
  destination) — but we do NOT need external "RPMB access": the memory-read
  bug → canary → `is_sig_valid` overflow → LK ROP → `set_bootmode` writes
  RPMB from LK context (where it works). Tim's 2 bugs (read + write-any-closed
  partition) fit this model: write = the meta path (ours, reproduced live),
  read = still to be located (vtnvfs lead above is our best candidate).

## 5. vtnvfs real templates found + format calibration (session 83 cont.)

- `/media/stanw47/Ventoy/tools/imggen/` = the imggen tool (main.py/imggen3.py/bb.py/
  gpt.py/mct.py) + `files/` templates: `blog.img boardid.img nvuser.img perm.img
  prdid.img` + `aboot.mbn bbss.mbn boot_gpt_secure.bin boot_gpt_insecure.bin
  stage1-3.mbn sbl1(r).mbn tz.mbn sdi.mbn user_gpt.bin`. Tool only COPIES the
  prebuilt templates into packages (no vtnvfs builder inside).
- Templates are for the **Passport balika conversion** (user), but vtnvfs format
  is the same family: on-disk magic **0x0903fade** (checked in `do_mount`
  0x8f65bea0, movw #0xfade @0x8f65befc/bf3c), in-memory magic 0xc001100c.
- KeyOne GPT sizes match templates: **perm = 512 sectors = 256KB** (gpt/rawprogram0.xml)
  -> templates are drop-in full-partition images.
- 5 vtnvfs partitions (table @0x8f7a23ac): `blog perm nvuser prdid boardid`.
  `pin` file lives in **prdid** (print_info 0x8f63239c: bbry_get_nv_fd("prdid") +
  vtnvfs_read("pin", sp, 4) -> "PIN: 0x%x"; live value 0x2c48d4c8 STABLE ->
  read succeeds; on failure it still prints [sp] uninitialized — untriggered).
- Template structure (perm.img): superblock {magic, ver 0x00090200, id, name@0x30,
  crc@0x5c}; record @0x200 (id 0x95e7ddbf, block idx u16@0x218=13, size 0x440);
  dir entry @0x1a00:
  - **crc@0x1a00 == zlib.crc32(bytes[0x1a04:0x1a40]) — CALIBRATED (standard CRC-32)**
  - fields: 0x3310 @+4 (low byte 0x10=16=name len?), id 0x95e7ddbf @+8,
    u16 13 @+0xC (block idx), u16 3 @+0xE, size 0x440 @+0x10, 0xa @+0x14,
    crc2 0xc6fe8258 @+0x18 (rule unknown), 0x5cc4fd/0x5ccc7d @+0x1C/+0x20
  - **name field @+0x30, 16 bytes, NUL-padded ("bootcontrolblock")**
- nvuser.img/prdid.img templates = empty (no CRC'd entries). nvuser.img has a
  "ramdumpinfo" region @0x1400 (struct shape differs, no CRC match by the same rule).
- Craft plan (next session):
  1. modify perm.img: extend the entry name past the 16B CRC'd field + fill
     following bytes non-NUL, recompute zlib CRC -> write to device `perm` via meta
     -> `oem info` -> observe (token listing / crash) = readdir namelen
     discriminator (strlen vs stored field);
  2. restore by re-writing the original template (or leave, tokens = none anyway);
  3. then build the targeted poisoned dirent (long name ending ".tkn", no NUL in
     block) for the OOB read/leak on the `%s` print path.

## 6. THE CHAIN — full vtnvfs control -> the only ABL memory-corruption bug (session 83 cont.)

### 6.1 LIVE-PROVEN: full vtnvfs control via meta path
- `bbry_get_nv_fd` (0x8f669ee4) resolves 5 partitions from table 0x8f7a23ac:
  `blog perm nvuser prdid boardid` (all LUN0, all meta-writable, all closed).
- **Mount fd is CACHED per boot** (`bbry_get_nv_fd` reuses `[entry+4]`) -> after writing an
  image you MUST `reboot-bootloader` for a fresh mount!
- Crafted `perm.img` (from `/media/stanw47/Ventoy/tools/imggen/files/perm.img`, 256KB =
  exact partition size) with dirent name changed to `bootcontrolb.tkn` (16B field) and
  **recomputed CRC** -> written via meta -> reboot -> `oem info` printed:
  `Debug Tokens (perm): bootcontrolb.tkn`  <= **READDIR CONTROL PROVEN LIVE.**
- vtnvfs format: on-disk magic **0x0903fade**; dirent = `{u32 crc; ...; name[16] @+0x30}`;
  **crc = zlib.crc32(bytes[entry+4 : entry+0x40])** (verified against stock image).
- `pin` file lives in **prdid**; `oem info` "PIN: 0x%x" reads it (`vtnvfs_read("pin")`).
- imggen = Passport-balika conversion toolset (user); templates reused as format source only.

### 6.2 THE TOKEN -> OVERFLOW CHAIN (all decoded, no keys needed)
Boot/fastboot reads `/perm/hlos_signature.tkn` (fastboot_publish_hlos_sig_tkn 0x8f63c540,
parse_hlos_signature_token 0x8f63c438; entries `key_name`/`tag_override`):
```
dbg_token_read_payload 0x8f63bfa0
  -> nvverify_verified_read 0x8f657fdc      @ requires_verification(basename)?
       non-.tkn & not in 9-table -> NO VERIFY (raw read!)
       .tkn -> verify_rec_data 0x8f657e20
         -> get_sig_path: "<dir>/<base>.sig." (fmt "%s/%s%s" + ".sig.")
         -> nvverify_verify 0x8f657c3c
              sig file: {u32 magic 0xae104a54; u32 ver<=2; u32 len=sig_size-12; blob...}
              rtas_init_ctx(key: DBGSIG for .tkn / NVSIG else)
              -> rtas_verify_nv_sig_response 0x8f659e24
                   parse_response -> find_challenge_item(5=name,6=hash)
                   -> is_sig_valid 0x8f658f30
```
**`is_sig_valid` = the ONLY memory-corruption bug in ABL766 (note 66), and it is fully ours:**
- 1st memcpy: `memcpy(sp+76, blob+5, sl)` (sl = blob byte 4, bounded by len check)
- **2nd memcpy: `memcpy(sp+144, blob+sl+7, L2)` where `L2 = r9-sl-7`, r9 = u16 from blob
  header => up to 65528 bytes -> unbounded stack smash (frame is 220B).**
- Fires BEFORE the ECDSA result matters -> forged sig blob still triggers the overflow.
- Canary @ [sp+212]; saved regs/LR after. Canary wall = the only blocker.

### 6.3 Geography (KeyOne ABL766)
- `kmain`: heap_init -> get_canary (0x8f6161c8) -> stores canary global **[0x8f7c2ed0]**;
  thread_create(name, entry 0x8f627948, arg 0, flags 16, **stack 8192**).
- heap_init: heap = **[0x8f7c3dc0 .. 0x8fd00000]** (5.5MB, right after image end).
- Initial SP literal @0x8f600118 = **0x8f7b2184** (boot stack inside image region).
- Canary global (0x8f7c2ed0) is 0xF0 BELOW heap base -> upward overflow from heap
  stacks/8KB main stack cannot reach it; boot stack (0x8f7b2184) reach max ~0x8f7c0xxx
  (L2 max 65528) -> misses by ~0x2ed0. => global-overwrite bypass NOT possible directly.
- BUT: overflow (65KB) from the 8KB heap main-thread stack lands in **the heap above**
  (other thread stacks / FS objects / buffers) -> potential cross-thread corruption /
  small targeted overflow (L2 ~80 reaches canary slot + saved LR in is_sig_valid's own
  frame) -> ROP *if* the canary is known.

### 6.4 Side findings
- `requires_verification` table 0x8f79491c (9 entries): `bsn macaddressbt macaddresswlan
  subvariant pin imei imei_2 meid inproductionflag` (flags 1,1,1,1,1,1,0,0,0).
- **`bypass_subvariant_verification` (0x8f657390): file "subvariant" is read UNVERIFIED
  on bbb100usa + (pcb<=6 OR pcb 7/8 + subvariant=="sprint") = OUR DEVICE => we control
  the `subvariant` record via the vtnvfs (no signature!).**
- Token value prints (tag override / pk name) require the verified token -> not a leak.
- Non-.tkn files not in the table = raw unverified reads (no leak by itself).

### 6.5 NEXT (queued)
1. LIVE overflow test: craft `/perm/hlos_signature.tkn` + `.sig.` blob with huge L2
   (e.g., r9=0xFFFF, sl=0) -> meta-write perm -> reboot -> `oem info`/getvar ->
   expect crash/hang = overflow proven in-session (same boot as a leak, no reboot
   needed between leak+exploit).
2. Canary: (a) find a .bss/stack leak (payload buffer 0x8f7bdfcc -> canary 0x8f7c2ed0
   = 0x4F04 away, zero-wall), (b) Tim's read bug, (c) small-L2 ROP once canary known.
3. Then: ROP in fastboot ABL -> `set_bootmode`/`rpmb_write_record` from LK context ->
   FACTORY_MODE -> unlock. Restore perm = rewrite stock template.

## 7. vtnvfs file layout hypothesis (for building multi-file images)

Stock perm.img analysis (all offsets confirmed by CRC calibration):
```
superblock  block 0  0x0000 : {magic 0x0903fade, ver 0x00090200, id, name@0x30, crc@0x5c}
record      block 1  0x0200 : {u32 2, 0, magic 0xf0deed0f, 0, 0, id 0x95e7ddbf,
                               u16 block=13, u16 nblocks=3, ...}
dirent      block 13 0x1a00 : {crc, len=0x10 @+4, id 0x95e7ddbf @+8, u16 13 @+0xC,
                               u16 3 @+0xE, size 0x440 @+0x10, 0xa @+0x14,
                               crc2 @+0x18, 0x5cc4fd @+0x1C, 0x5ccc7d @+0x20,
                               name[16] @+0x30 (variable len = byte@+4)}
```
- Hypothesis: file = record (block 1+n) + dirent (block 13+chunk) + **inline data after
  the name**, spanning `nblocks` blocks; "bootcontrolblock" = 0x440 bytes -> 3 blocks
  (13,14,15); block 14/15 = zero data (BCB = zeros).
- To add files: next free record block (2 = 0x400), next free dirent block (16 = 0x2000),
  new unique id linking record<->dirent, data inline after name, CRC =
  zlib.crc32(entry+4 .. entry+0x40) (name > 16 bytes extends past +0x40; update len byte).
- Name len byte = dirent+4 (0x10 for "bootcontrolblock"); names up to ~144 supported.

## 8. Crafting attempts live + mount internals (session 83 cont.)

### Live test matrix (device 1164118297, perm partition)
| build | layout | result |
|-------|--------|--------|
| var1 | name field +0x40 filler 'A' (no NUL) | write OK, listing unchanged (mount cache! then no effect) |
| var2 | name="bootcontrolb.tkn" (16B) | **LISTED** after reboot-bootloader -> readdir control proven |
| A2 | rec@2/3 (0x400/0x600), files@16/17, crc2=data crc | **"Partition Read Error"** (walk rejected) |
| C | rec@16->file@17, rec@18->file@19, crc2=data crc | parses OK but entries NOT listed |
| C2 | same + crc2 patched | parses OK, still not listed |

### Mount internals (do_mount 0x8f65bea0)
- reads block 0 (512B), checks `u16 [0] == 0xfade`, **CRC: `zlib.crc32(superblock[0:92]) == u32 @+0x5c`** (stock
  sb crc 0x7e0af6e4 verified intact in our builds - mount CRC passes).
- copies 96B of superblock into fs object; fields: `[+4] u16 = 0x200` (total blocks!), `[+6] u16 = 9`
  (reserved/data start?), `[+3] u8` shift; computes bitmap word count from (total-reserved).
- **block bitmap**: `vtnvfs_set_bits` 0x8f65a838 / get_bits; mount `blk_read` + `inode_blk_cmd` 0x8f65b940.
  => FS tracks ALLOCATED blocks in a bitmap; our added files' blocks are NOT marked allocated, which
  explains "parses but not listed" (readdir iterates allocated nodes only / statfs count wrong).
- record walk appears sequential: rec@1 -> file@13 (span 3) -> next rec@16 ... ; records in 2..12
  area rejected (A2) => do NOT place records in the low record area; chain after files.
- Listing special-case: entry name == **"hlos_signature.tkn"** (string @0x8f6dfdbc) triggers
  `parse_hlos_signature_token` -> token read -> verify -> **sig -> is_sig_valid -> OVERFLOW** in the
  SAME `oem info` call. Prints: "Key Name: %s" / "Sig Tag Override: %s" (0x8f6dfde8/df f8).
- `crc2` @dirent+0x18 = `zlib.crc32(file data)` (verified: stock zeros(0x440) -> 0xc6fe8258).
- `get_sig_path` = `"%s/%s%s"` with dirname + **".sig." prefix + basename** => sig file =
  **".sig.hlos_signature.tkn"** (hidden from token listing, leading dot).

### NEXT (bitmap step)
1. Read `vtnvfs_set_bits`/`get_bits` (0x8f65a838/…) + superblock struct to learn bitmap location+format
   (fields [+4]=total blocks 512, [+6]=9 reserved, [+8..] root inode?).
2. Mark our blocks allocated in the bitmap (records 2/3 + files 16/17) OR find the correct record
   area, then rebuild -> entries must appear in `Debug Tokens (perm)`.
3. Once listed, the listing itself triggers the read -> overflow (crash expected with s_len=251,
   canary+saved regs+LR range sp+144..sp+395).

## Artifacts
- `/tmp/opencode/meta_test.img`, `/tmp/opencode/meta_rcause2.img`,
  `/tmp/opencode/hwi_store.bin`, `/tmp/opencode/meta_flash.log`
- disasm anchors: 0x8f63a080, 0x8f63a254, 0x8f63a37c, 0x8f63a684, 0x8f639e30,
  0x8f638d48, 0x8f638e48, 0x8f638a08, 0x8f6392cc, 0x8f63bba0, 0x8f63ba20,
  0x8f63bb18, 0x8f65d52c, 0x8f65c3f8, 0x8f65c534, 0x8f63bf5c, 0x8f63c15c
