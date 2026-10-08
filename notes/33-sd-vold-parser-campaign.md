# notes/33 — microSD / vold root-parser campaign (Passport Dirty-COW chain, transplanted)

Date: 2026-10-08. Device: KEYone BBB100-3, ABL766 (Android 7.1.1).

## The idea (from the Passport work, sessions 25/26)

On the Passport prototype (Android 5.1, kernel 3.4) the win was:

**Dirty COW → page-cache-patch `/system/bin/fsck_msdos` → eject/reinsert microSD
→ vold executes the checker as root → resident daemon + `/sdcard` channel.**

Two halves: (a) a write primitive, (b) the **root-exec trigger** — vold running
a filesystem checker on untrusted removable media. This note is the attempt to
transplant it to the KEYone, all flavors, per the "exhaust options" directive.

## Half (a): the primitive is dead on ABL766

Dirty COW (CVE-2016-5195) was fixed in 2016; this kernel is 3.18.31 built
2018-11-21 (patch level 2018-12-05), and the Priv (3.10.84, 2017) already had
it blocked. `/proc/self/mem`, `process_vm_writev` are also restricted. No
shell-level page-cache write exists today; if the KGSL chain yields kernel R/W,
this route revives trivially (or skip straight to creds).

## Half (b): the trigger is fully alive — and richer than expected

Vold (root) runs these **against attacker-controlled media** on insert
(LineageOS cm-14.1 `system/vold` sources, matching BB 7.1.1):

| Parser | Invocation | Context | Input |
|---|---|---|---|
| `blkid` | metadata probe (`ReadMetadataUntrusted`) | root/untrusted | any superblock |
| `fsck_msdos` | `-p -f <dev>` | `fsck_untrusted` | FAT12/16/32 |
| `fsck.exfat` | `<dev>` (no args) | `fsck_untrusted` | exFAT |
| `mount.exfat` | FUSE mount helper | root | exFAT (full parse) |
| kernel `vfat` / exfat (`Texfat_*`) | `mount(2)` | kernel | FAT/exFAT on mount |

Binaries extracted from the ABL766 `system.img` (sparse → 7-Zip 26 chains
sparse→ext4; no 4 GB conversion needed):

```
fsck_msdos a14b6d46824151936f972674ebd407f345ed008d22792ec6fec96d58c61a15dd
blkid      27c6883cdc7dd79c998265537da69ecb747a50303e4ba2e3e9ef4733537b7eec
fsck.exfat 7a96f568e5780443e12c51ac3de0b6994abf00ad89af6813ab510031d041b902
vold       845f5c27c580b2719d4b924273b171ab674b6fa97361998e998979bd35e4834d
```

All aarch64, dynamically linked (linker64), **FORTIFY'd** (`__strcpy_chk`,
`__read_chk`, `__snprintf_chk`) with stack canaries. fsck_msdos/fsck.exfat
built with clang 3.8 (2016) — 7.1-era code in a 2018 build.

## The on-device fuzzing trick

SELinux blocks shell from *reading* `/system/bin/*` — **but not from executing
a pushed copy**: `adb push fsck_msdos /data/local/tmp/` + `chmod 755` runs
fine (prints usage). That turns the phone into the fuzzing ground for its own
root-exec'd parsers (no qemu-user on Windows; WSL absent).

Tooling: `tools/fat_seed.py` (minimal valid FAT16, >4085 clusters), and
`tools/sd_fuzz.py` (structured mutator → push batch → device loop with the
exact vold args `-p -f`, crash = rc ≥ 128, pulls crashing images).

## Results so far

- 576 mutants with `-n`, 768 with the real vold invocation `-p -f`
  (**1,344 total**) → **0 crashes** (≈5.3 img/s end-to-end).
- The FAT checker validates aggressively and FORTIFYs everything; no
  low-hanging fruit in FAT12/16 BPB/FAT/dir/LFN mutation space.

## Update — full campaign results (same session)

| Parser | Invocation (vold) | Mutants | Crashes |
|---|---|---|---|
| `fsck_msdos` | `-p -f` (preen+force) | 1,344 | 0 |
| `blkid` (libblkid) | `-c /dev/null -s TYPE -s UUID -s LABEL`, plus `-p` | 4,608 | 0 |
| `fsck.exfat` (relan 1.2.3) | `<dev>` | 512 | 0 |
| `e2fsck` (e2fsprogs 1.42.9) | `-y` | — | path GATED |

New tooling: `tools/blkid_fuzz.py`, `tools/exfat_seed.py` (ports relan mkexfatfs;
needs `mkfs/uctc.c` from a relan/exfat clone), `tools/exfat_fuzz.py`,
`tools/sparse2raw.py` (Android sparse → raw), `tools/ext4_quota_poc.py`.

Seed work:
- exFAT seed built from the relan mkfs layout (VBR checksum, bitmap, upcase
  table, root dir) — `fsck.exfat` reports **No errors found**, then shrugged off
  512 semantic mutants (with checksum recompute so boot-sector changes mount).
- ext4 seeds: `bbpersist.img` sparse (20 MB raw) is the small one; the others
  are 256 MB–9.5 GB logical. `e2fsck -fn` clean on it.

**e2fsck quota path: dead.** The binary references `libext2_quota.so`
(`quota_compare_and_update`, `quota_write_inode`, …) and has e2fsck/quota.c
messages, but its feature table rejects the ext4 `quota` feature:

```
/data/local/tmp/poc.ext4 has unsupported feature(s): quota
e2fsck: Get a newer version of e2fsck!
```

Crafted CVE-2019-5094-style images (RO_COMPAT_QUOTA + quota inodes 3/4 with a
qtree leading to `get_bit(bitmap, 0x40000000)`) never reach `report_tree` —
e2fsck exits before parsing. The quota code is only reachable via
mke2fs/tune2fs, which are not on this device and never run on untrusted media.
**CVE-2019-5094 is not reachable through vold on Android 7.1.1/ABL766.**

## Flavor queue (not yet done)

1. **Grammar-aware FAT12/FAT32** seeds (FAT32 = >65k clusters, 32 MB — sparse
   or trimmed; FAT12 = small-card path).
2. **`blkid`** — random/superblock-structured inputs (no valid seed needed);
   libblkid probes many filesystems as root.
3. **`fsck.exfat` + `mount.exfat`** (relan/exfat 1.2.x, 2016) — need a minimal
   exFAT seed; different, smaller codebase than fsck_msdos.
4. **Kernel `vfat`/`Texfat` mount path** — not shell-reachable; requires vold
   to mount a crafted card (physical insert), but it is the only route here
   that lands *in kernel*.
5. **Source-diff** fsck_msdos 7.1 vs 8.1/9 for fixes after the clang-3.8 build
   (mirrors were uncooperative; binary is ground truth anyway).

## Files

- `tools/fat_seed.py`, `tools/sd_fuzz.py`
- `artifacts/keyone-system/bin/{fsck_msdos,blkid,fsck.exfat,vold}` (extracted)
- `artifacts/sd-fuzz*` (mutant batches, pruned)
