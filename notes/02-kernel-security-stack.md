# Session 01 — Addendum: Kernel Symbol & Security Stack Analysis

Source: `/proc/kallsyms` (167,987 symbols, names intact, **addresses zeroed** / `kptr_restrict`)
Saved raw output: `recon/bb_recon2.txt` (filtered view). Full symbol dump not yet captured cleanly;
re-capture later with a device-side script that greps batched patterns.

## Security stack confirmed present in the KEYone kernel (3.18.31)

### PathTrust LSM (BlackBerry)
```
pathtrust_init, pathtrust_setup, pathtrust_fs_init, pathtrust_dev_init, pathtrust_nl_init
pathtrust_add_dev, pathtrust_dev_trusted
pathtrust_lsm_audit, pathtrust_audit_pre_callback, pathtrust_audit_post_callback
pathtrust_kernel_fw_from_file, pathtrust_kernel_module_from_file
pathtrust_sb_kern_mount, pathtrust_sb_mount
pathtrust_mmap_file, pathtrust_bprm_set_creds
pathtrust_write_selinux, pathtrust_read_enforce, pathtrust_cdev_ioctl, pathtrust_selctx_load
pathtrust_hooks, pathtrust_pathnode_list, pathtrust_enforce, pathtrust_cdev_fops,
pathtrust_selctx_list, pathtrust_selctx_list_mutex, pathtrust_ctx_loaded, pathtrust_dir
pathtrust_enforce_file, pathtrust_selinux_file, pathtrust_enforce_file_ops, pathtrust_selinux_file_ops
netlink_pathtrust_data
```
- Device node context in SELinux: `/dev/bide` → `u:object_r:bide_device:s0`
- Rootfs file `/pathtrust_contexts` (tcontext `u:object_r:rootfs:s0`)
- `pathtrust_cdev_fops` implies a **pathtrust char device** too (analogous to BIDE).

### BIDE (BlackBerry Integrity Detection Engine)
```
bide_perm_search, bide_perm_insert, bide_perm_drop, bide_perm_remove, bide_exit
xml_jbide_hash_msg, JBIDE_HASH_TAG
bide_device                  (the /dev/bide char device, major 229)
com.blackberry.bide          (userspace process, uid 8000)
```
- `xml_jbide_hash_msg` / `JBIDE_HASH_TAG` = the **Java-BIDE measurement/hash** path.
- `libbidejni.so` is the JNI bridge.

### grsecurity / PaX
- `/proc/<pid>/status` → `PaX: PemRs`
- `grsec_lock`, `grsecurity_init`, `grsec_fops`
- Exposed writable toggles (data/B symbols):
  `grsec_enable_chroot_*` (chdir, chmod, chroot, mount, mknod, nice, pivot, caps, sysctl, rename, execlog, findtask, unix, shmat, fchdir, double),
  `grsec_enable_tpe`, `grsec_enable_tpe_all`, `grsec_enable_tpe_invert`, `grsec_tpe_gid`,
  `grsec_enable_dmesg`, `grsec_enable_ptrace_readexec`, `grsec_enable_harden_ptrace`,
  `grsec_enable_harden_ipc`, `grsec_enable_execlog`, `grsec_enable_forkfail`,
  `grsec_enable_rofs`, `grsec_enable_link`, `grsec_enable_brute`,
  `grsec_enable_socket_server/client/all`, etc.
- `pax_report_insns`, `pax_check_flags`, `pax_get_path`, `pax_report_fault`,
  `pax_report_refcount_overflow`, `pax_set_initial_flags`, `pax_list_*`

### BlackBerry USB gadget (loader/fastboot)
```
bb_function_bind_config, bb_function_init/cleanup/bind/unbind,
bb_function_enable/disable/set_alt, bb_open/release/read/write,
bb_complete_in, bb_complete_out, bb_request_new, bb_fops, bb_shortname,
bb_device, bb_interface_desc, bb_string_defs, fs_bb_descs, hs_bb_descs, ss_bb_descs
```
- This is the gadget that presents the BlackBerry loader interface (the `0FCA:8001/8014/8040/...` PIDs).

## SELinux denials observed while probing (useful map of the walls)
- `shell` → `bbauthtoold_exec` : `getattr` denied (can't even stat the binary)
- `shell` → `bide_device` : `getattr` denied
- `shell` → `kernel_securityfs` : `read dir` denied
- `adbd` → `security_file` : `search` denied (the `/data/security` dir)
- `shell` → `rootfs` (`/pathtrust_contexts`) : `getattr` denied

These confirm the enforcement is real and fine-grained; shell has essentially no
reach into the security daemons or their device nodes.

## Implications for the research plan

1. **The KEYone kernel is a near-sibling of the Priv kernel** (BIDE + Pathtrust +
   grsecurity/PaX). Any audit tooling or findings from the Priv work transfer directly.
2. Two char devices worth RE: `/dev/bide` (229:0) and the pathtrust device
   (`pathtrust_cdev_fops`). Both are classic LSM attack surface.
3. `bbauthtoold` + `TokenService` + `libbbauthtool.so` + `libsecureservice.so` are the
   userspace trusted-computing stack — RE these next.
4. `/nvram/nvuser` is writable via `vtnvfsd` (uid/gid 2900); `bbauthtoold` runs as uid 2911
   in group 2900 → the trust boundary between them is the interesting edge (matches the
   Priv `nvuser` token idea).
5. Kernel symbol names are available (addresses hidden). Once we have a rooted/tethered
   environment, `/proc/kallsyms` gives us the symbol table for exploitation; until then,
   the published kernel source branch (`msm8953/ABY299`, nearest to ABL766) gives offsets.

## Next

- Pull and RE `vtnvfsd`, `bb_tokenserviced`, `libsecureservice.so`, `libbbauthtool.so`.
- Capture a clean full `kallsyms` text dump for offline symbol mapping.
- Acquire BBB100-3 firmware → `aboot`/`abl` extraction.
