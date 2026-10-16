# 77 — CVE-2019-2215 KEYone: P0 iovec technique blocked by DEBUG_LIST; panic root-caused

Date: 2026-10-14 (continued 4)

## WHAT WAS PROVEN THIS SESSION
1. `binder_poll` in our 3.18.31 has the FIXED logic (proc->wait in first branch);
   the magic state (transaction_stack != NULL, todo empty, BR_OK, !NEED_RETURN)
   is required and WORKS. Trigger = BC_ENTER_LOOPER + sync BC_TRANSACTION to
   handle 0 with read consuming tcomplete (read_consumed == 8), then epoll_ctl ADD
   IMMEDIATELY (no syscalls/markers between!).
2. `binder_free_thread` has NO POLLFREE fix (disasm-verified: rb_erase,
   binder_send_failed_reply, binder_release_work, kfree — no wake) => UAF real.
3. READV RECLAIM WORKS: readv() on a pipe with 25 iovecs (>UIO_FASTIOV=8)
   kmallocs 400B (kmalloc-512) and reclaims the freed binder_thread chunk.
   PROVEN by spin oracle: iovec[4].iov_len = 1 -> chunk+0x48 = 1 -> epoll DEL
   -> remove_wait_queue spin_lock -> hard lockup -> PANIC (readv array WAS at
   the chunk). Note iovec[4].iov_len low 32 bits = the wait head lock at +0x48;
   keep it 0 in real runs.
4. Kernel copy_to_user uses NORMAL stp/str (UAO alternative patched to NOP,
   no STTR) => kernel-address copies DO work at copy time (no access_ok
   recheck in copy_to_iter_iovec, __copy_to_user raw). The technique is not
   blocked by uaccess; notes/75's "P0 dead" conclusion was wrong.
5. CONFIG_DEBUG_LIST IS ENABLED on this kernel. `__list_del_entry` calls
   `__list_del_entry_debug` (0xffffffc00034fac0) which prints via printk:
   - "list_del corruption, %p->next is LIST_POISON1 (%p)" (LIST_POISON1 =
     0xffff00000000ff01, POISON2 = 0xffff00000000ff02)
   - returns 0 on corruption; caller skips __list_del.
   The checks compare *(B+0x50)==entry and *(B+0x58)==entry where
   entry = &pwq->wait.task_list (the eppoll_entry address, unknown).
   The iovec-array reclaim's copy_from_user OVERWRITES B+0x50/B+0x58 with our
   iovec[5] values => validation always fails => (observed) panic.
   NOTE: the printk paths in __list_del_entry_debug appear to fall through a
   suspicious word 0xe7f001f2 after the printk BL — suspected trap/invalid
   instruction => oops => panic (panic_on_oops=1 confirmed). The DEBUG_LIST
   "warn" path here is NOT the standard warn_slowpath (no panic_on_warn in
   3.18) yet every corruption path observed ends in panic. Treat ANY
   validation failure as fatal.
6. panic_on_oops = 1, panic = 5 (reboot delay). panic_on_warn does not exist
   in this kernel (3.18). A normal WARNING (netif_rx_internal) occurred and
   the device survived => plain WARNs are harmless.
7. device-side infra: ExecActivity output file = /sdcard/Android/data/
   com.bbkeyone.toolbox/files/<out> (readable by adb shell). Use it instead
   of logcat. ALWAYS `am force-stop` before `am start` (onCreate only).
   WATCHDOG RESETS ZERO OUT RECENTLY PUSHED FILES: /data/local/tmp binaries
   and app-dir copies come back 0 bytes after an unclean reboot => re-push
   and verify md5 before EVERY run.

## WHY THE EXPLOIT STILL MISSES
- The P0 write primitive needs iovec[5] corrupted to {B+0x50, B+0x50} by the
  unlink. The unlink only runs if the DEBUG_LIST validation passes, i.e. the
  head fields at B+0x50/B+0x58 must still contain `entry` (the pwq task_list
  address) at DEL time.
- The iovec-array reclaim destroys exactly those fields (its copy overwrites
  0x50 with our iov[5] values). => validation fails => fatal.
- A reclaim that PRESERVES 0x50..0x5F (e.g. unix-dgram skb with payload
  length <= 0x50 - delta) lets the validation pass and the unlink run (self
  writes B+0x50 into B+0x50/B+0x58), but then the chunk bytes are unreadable
  (skb recv only returns payload) and the follow-up readv import would
  overwrite the self-writes anyway. => need a way to learn B (chunk address)
  or entry (pwq address) before the corruption.

## OPEN IDEAS FOR NEXT SESSION
- Leak `entry`: the __list_del_entry_debug printk message contains it, but
  the path is suspected fatal; if the panic leaves the log in ramoops console
  (8KB) the line might be captured (grep the pstore window for
  "list_del corruption" immediately after a crash).
- Alternative readable reclaims that don't overwrite 0x50: consider
  skb with short payload + reading via a second socket op; or an object with
  a user-visible read path that starts at offset 0x50.
- Alternative write primitive: use the wake path with a fake wait entry in
  user memory (kernel reads user memory fine — UAO not implemented, no PAN).
  The reply-wake is blocked by binder_free_thread nulling t->from; the nested
  transaction path is blocked the same way. Look for any other wake source of
  &thread->wait (binder_send_failed_reply target_thread = t->from only).
- If `entry` becomes known (stable per boot, pwq_cache LIFO): set user
  iov[5] = {entry, entry} in the readv reclaim; validation passes; unlink
  writes {B+0x50, B+0x50} into iovec[5]; readv staged writes (chunk1 80B to
  B+0x50 rewrites iovecs 6..9 with targets; second write 4096B so no
  pipe_write merge; pipe size F_SETPIPE_SZ 4096 so stage 2 blocks) -> write
  8 bytes to selinux_enforcing (0xffffffc001473030, +4 selinux_enabled) and
  modprobe_path (0xffffffc0016065c0) -> execve bad-binfmt trigger ->
  request_module -> /data/local/tmp/x runs as root. All addresses verified
  (init_uts_ns bytes at 0xffffffc001448bb8 = kref 2 + "Linux").

## STATIC ADDRESSES (no KASLR, base 0xffffffc000080000)
selinux_enforcing 0xffffffc001473030 (enabled at +4)
modprobe_path 0xffffffc0016065c0
__list_del_entry_debug 0xffffffc00034fac0; __list_del_entry 0xffffffc00034fb60
ep_remove 0xffffffc0001e4950; remove_wait_queue 0xffffffc0000e3e88
binder_free_thread 0xffffffc000939fbc; ep_poll_callback 0xffffffc0001e4ee0
__copy_to_user 0xffffffc000336540 (normal stp/str!)

## FILES
/tmp/opencode/lpe/: exploit2215.c (full exploit), oracle_reclaim.c (spin
oracle, iov[4].len=1), oracleB/C, leak2215.c (leak attempt), selfsvc.c.
/tmp/opencode/kern/vmlinux.elf + disas via capstone (objdump can't decode).
