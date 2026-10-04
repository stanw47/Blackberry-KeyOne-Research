# KEYone — RTAS2 wire framing, live-probe result, and kernel root survey

Date: 2026-10-04
Related: notes/16, 17, 18.

## Part 1 — RTAS2 wire framing (reconstructed statically)

Message codes in the LK authboot region (0x8f6392cc..0x8f63a700), passed as
`r0` to `sock_send_msg` (`0x8f6392cc`):

| code | direction | handler |
|------|-----------|---------|
| `0x1013` | device→PC | `respond_rtas_init_event` (0x8f63a0a8) |
| `0x1015` | device→PC | `process_rtas_has_permission_event` reply (0x8f63a2ec) |
| `0x1017` | device→PC | `respond_rtas_sign_event` (0x8f63a3d4) |
| `0x2004` | device→PC | challenge (`send_rtas_challenge` region, 0x8f639ee4) |
| `0x2005` | PC→device | **challenge response** — must equal 0x2005 (0x8f63a480) |

Auth-gate tool message: cookie `0xbba78701` (`movw ip,#0x8701 / movt ip,#0xbba7`),
request size `0x1014`.
`auth_rtas_has_permission` (0x8f6386e8) builds a 0x2c-byte struct:
```
sp+0x00 = 0xbba78701        ; cookie
sp+0x04 = 0x1014 (size)
sp+0x18 = r6 (cmd string ptr)  ... then send via 0x8f639ba0
```

PC-side (pcauthtool.exe) structs: `msg_header_t{cookie,msg_size,version,code}`,
`msg_dev_rtas_chal_pc_t{rtas_chal,rtas_chal_len}`,
`msg_pc_rtas_chal_dev_t{rtas_resp,rtas_resp_len}`.

### Capture attempt (BLOCKED)
- USBPcap is installed (`C:\Program Files\USBPcap\USBPcapCMD.exe`) and Wireshark
  present; device on bus 3 -> `\\.\USBPcap3`.
- USBPcapCMD requires **administrator elevation** to open the driver; the shell
  is non-elevated -> no pcap produced. **No live capture obtained.**
- Would need: run the capture elevated (e.g. `Start-Process -Verb RunAs` with a
  UAC prompt) while running `authboot getvarp bsn` / `debugtokens`.

## Part 2 — live probe of the RTAS2 truncation candidate (NEGATIVE)

Tested via the fastboot path (0x0FCA:8040 iface 0) with `tools/fastboot_libusb.py`:

```
oem getvarp:bsn / :procid / :../../etc / :<256 A> / :bsn:extra  -> FAILauthboot command permission denied
oem set-factory-mode                                            -> FAILauthboot command permission denied
oem enable-usb-reset / oem led:off                              -> OKAY  (ungated)
```

- The RTAS **string whitelist denies before any message parser runs**. So
  `process_rtas_chal_response` (the 16-bit `uxth` truncation candidate from
  notes/18) is **unreachable from an unauthenticated fastboot session**.
- Callers of `rtas2_cmd_authorization_check` (`0x8f637d04`) all pass
  `r0=1 (handle), r1=1 (cmd_id), r2=0x1000/0x1006/0x1007/0x1008`; the (0,0)
  trivial-allow branch is never used in the live paths. Authorization fails at
  `auth_rtas_has_permission` (device returns not-granted; server dead).
- `oem securewipe` bypasses the gate only because its handler never calls it
  (notes/17) — not because of the (0,0) branch.

Verdict: the RTAS2 parser bug, if real, is **behind the auth wall**. To reach it
we would need to first establish an RTAS session (dead server) — a hard blocker.

## Part 3 — kernel root surface (MSM8953, 3.18.31)

```
uname: 3.18.31-perf-gf38c8fb #1 SMP PREEMPT Wed Nov 21 2018 aarch64
Android 7.1.1, SDK 25, security patch 2018-12-05, build ABL766
SELinux Enforcing, shell uid 2000, kptr_restrict=3
```

World-writable devices (same layout as Priv):
```
crw-rw-rw- /dev/ashmem      (10,56)
crw-rw-rw- /dev/binder      (10,57)
crw-rw-rw- /dev/kgsl-3d0    (240,0)  system:system
crw-rw-r-- /dev/ion         (10,94)  system   (not shell-accessible)
crw-rw-r-- /dev/adsprpc-smd          system
SELinux-denied to shell: /dev/qseecom, /dev/diag
```

### DECISIVE: GRSECURITY/PAX is PRESENT
`kallsyms` contains full grsecurity/PaX symbol set:
```
grsec_enable_harden_ptrace   grsec_enable_tpe / _tpe_all / _tpe_invert
grsec_enable_socket_all/_client/_server   grsec_enable_brute   grsec_enable_blackhole
grsec_enable_audit_ptrace    grsec_fops   grsec_lock   grsec_enable_harden_ipc
grsec_enable_dmesg, _forkfail, _link, _symlinkown, _signal, _mount, _chroot_*
pax_report_fault   pax_report_insns   pax_report_refcount_overflow   pax_set_initial_flags
```
(`/proc/sys/kernel/grsecurity` not visible to shell, but the code is compiled in.)

**Implication:** the KEYone shares the same hardening class that defeated every
public Priv exploit (per-receiver slab/freelist isolation killed the binder UAF;
harden-ptrace killed DirtyCOW/ptrace; grsec socket restrictions kill the AF_PACKET
family; TPE/module restrictions block kernel-module tricks). This makes
**CVE-2019-2215 (binder UAF), CVE-2020-0041, DirtyCOW, QuadRooter, and the
AF_PACKET/IGMP families strong-REJECTED/likely-blocked**, exactly as on the Priv.

### Also present (attack-surface functions, from kallsyms)
```
binder_ioctl, binder_ioctl_write_read, binder_transaction, binder_release,
  binder_thread_read, binder_transaction_buffer_release
ashmem_ioctl, ashmem_mmap, ashmem_pin/unpin
ion_alloc, ion_free, ion_ioctl
kgsl_ioctl_gpumem_alloc(_id), kgsl_sharedmem_free (+_compat variants)
__check_object_size (HARDENED_USERCOPY present), __stack_chk_fail (stack canary)
```

### Honest verdict
- Kernel patch level **2018-12-05** leaves post-2018 CVEs nominally open, BUT the
  grsec/PaX + HARDENED_USERCOPY + SELinux-enforcing + kptr_restrict=3 combination
  is a **hostile exploitation environment** with no public working chain for this
  exact config.
- The realistic remaining kernel leads mirror the Priv:
  - **KGSL/Adreno 506** (world-writable /dev/kgsl-3d0) — SMMU/GPU-DMA class
    0-days (Lasimeri-style) are the only known survivors of grsec; require a
    kernel-write primitive that hasn't been publicly demonstrated for 3.18/MSM8953.
  - **TrustZone / QSEE** (CVE-2021-1961 class) — gated behind /dev/qseecom which
    shell cannot open (SELinux tee_device) => circular without prior root.
  - **downgrade** to a pre-grsec build — but like the Priv, the retired OS
    versions may not boot this hardware revision.

## Bottom line

All three lines converge on the same wall documented for the Priv:
1. Bootloader/RTAS2: parsers hardened + auth gate unreachable (dead server).
2. securewipe: un-injectable.
3. Kernel: grsec/PaX + user-copy hardening + SELinux; no public chain.

No software-only unlock/root path has been found for the KEYone (BBB100-3
ABL766), consistent with the broader BlackBerry family.
