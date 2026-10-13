# 74 — CVE-2019-2215 LPE on KEYone 3.18.31: trigger works, reclaim open

Date: 2026-10-14

## Kernel facts (from boot.img -> vmlinux via vmlinux-to-elf)
- 3.18.31-perf-gf38c8fb, built 2018-11-21. Kernel image extracted to
  /tmp/opencode/kern/vmlinux.elf (link base 0xffffffc000080000).
- No KASLR strings ("Kernel Offset" absent) => static addresses usable.
- Symbols: commit_creds 0xffffffc0000c013c; prepare_kernel_cred 0xffffffc0000c052c;
  selinux_enforcing 0xffffffc001473030; init_cred 0xffffffc001451b50;
  binder_get_thread 0xffffffc00093a4f8; binder_poll 0xffffffc00093e54c;
  binder_thread_read 0xffffffc00093e868; binder_release 0xffffffc00093a19c;
  binder_free_thread 0xffffffc000939fbc; ep_remove 0xffffffc0001e4950.
- binder_get_thread: kzalloc via kmalloc_caches[9] => kmalloc-512; size=0x128
  (mov x2,#0x128; flags 0x80d0 = GFP_KERNEL|ZERO). wait_queue_head at +0x48
  (add x0,x19,#0x48; init_waitqueue_head). proc @+0, pid @+0x20.
- task_struct: pid @0x398, cred @0xa30 (from sys_getuid), uid @cred+4.
  thread_info: task ptr @thread_info+0x10 (3.18 in-stack thread_info).
- binder_ioctl: BINDER_THREAD_EXIT = 0x40046208 CONFIRMED (cmp w22,#0x40046208
  -> b.eq 0x942930 -> binder_free_thread(proc,thread) at 0x94295c). Same
  constant as 4.4 POC. BINDER_WRITE_READ = 0xc0306201.
- /proc/kallsyms zeroed (kptr_restrict=3); no /proc/config.gz; /proc/slabinfo
  MISSING; /sys/kernel/slab/ exists (SLUB). priv_app cannot read
  kmalloc-512/objects (read failed).

## Tooling that works (Android foothold)
- Toolbox priv-app agent (notes/73): write /sdcard/.tb_cmd -> runs as uid
  10103 u:r:priv_app:s0 (Groups: cache, devicepwd, media_rw, sdcard_rw, log,
  audio), output /sdcard/.tb_out. Exec from /sdcard blocks SELinux exec; place
  binaries in /data/data/com.bbkeyone.toolbox/<name> (app_data_file) and run.
- Freestanding aarch64 (clang -target aarch64-linux-android -nostdlib -static
  -fuse-ld=lld -Wl,-e,_start) with syscall harness works. ARM64 syscall notes:
  epoll_create1=20, epoll_ctl=21, fork=clone(220, SIGCHLD), mmap=222 (6 args,
  x0=addr!), wait4=260, setsockopt=55, sched_setaffinity=122, F_SETFL=4,
  O_NONBLOCK=0x800, F_SETPIPE_SZ=1031. SysV IPC (msgget/msgsnd/msgrcv) =
  ENOSYS. add_key/keyctl = EACCES (SELinux). SystemProperties via app only.

## UAF mechanics (CVE-2019-2215)
- Setup: open /dev/binder; epoll_create1; epoll_ctl(ADD, binder_fd, EPOLLIN)
  => binder_poll registers current thread's binder_thread->wait (B+0x48) with
  the epoll's eppoll_entry (pwq->whead = B+0x48).
- BINDER_THREAD_EXIT ioctl frees B (verified disasm). PWQ dangles.
- epoll_ctl(DEL) (from forked child works; fds inherited) -> ep_remove ->
  ep_unregister_pollwait -> remove_wait_queue(B+0x48, &pwq->wait) ->
  spin_lock(B+0x48) then list_del: writes (B+0x50) to [B+0x50] and (B+0x58).
  => self-write of heap ptr into the reclaimed object; spinlock at B+0x48 reads
  low32 of first 4 bytes of the object -> can be used as reclaim ORACLE
  (nonzero => child spins => reclaim proven).
- wait_queue_head layout (arm64 3.18): lock @+0 (4B), task_list.next @+8,
  prev @+16. For our reclaimed iovec array (entry i at 16*i):
  lock = low32(iovec[4].iov_len); next = iovec[5].iov_base; prev = iovec[5].iov_len.

## Status of reclaim attempts (ALL MISSED so far)
1. writev import_iovec reclaim (kmalloc(464) => kmalloc-512): 300-attempt loop
   with per-attempt: ADD, fork child(sleep30ms, DEL, drain), THREAD_EXIT,
   writev pipe with crafted iovec (lock=1 oracle). writev blocks on full pipe
   (0x1000 filler) and unblocks after child drain => UAF timing OK. NEVER a
   spin (lock never read nonzero) => import never lands in B.
2. skb spray: unix dgram socketpair, payload 192 and 96 (kmalloc-512 sizing
   assumed via SKB_DATA_ALIGN(len + shinfo)), pre-spray 278 (queue limit
   truesize ~208KB), THREAD_EXIT, drain 16, post-spray 8, child DEL. Never a
   spin; drained 270, corrupted=0. Nonblocking sends needed (O_NONBLOCK) or
   the 400-send pre-spray blocks.
3. CPU affinity (sched_setaffinity cpu0) added: same result.
4. msg_msg (SysV) not available; keyctl EACCES.

=> Conclusion so far: either the freed chunk is not making it to the
kmalloc-512 freelist we allocate from, or something consumes it between free
and our allocs. Next-session experiments (in order):
- read /sys/kernel/slab/kmalloc-512/{objects,slabs,cpu_slabs,partial} AS THE
  APP via agent (maybe as u0_a103 with cat directly works; our exec read used
  syscall openat - the -1 likely = EACCES; try agent cat).
- bisect skb payload sizes (32/48/64/96/128/160/192) with the spin oracle -
  find which size class actually hits (the shinfo size on this kernel may make
  all our payloads land in kmalloc-1024).
- writev retry loop BUT with iovec import _and_ a pre-free grooming: alloc many
  kmalloc-512 (iovec imports) BEFORE the free so B is allocated on the current
  cpu slab; free; then ONE writev.
- verify the reclaim target by freeing MANY binder_threads at once (N binder fds
  => N threads via ADD each? careful: ADD uses current thread; instead N
  parallel... simpler: loop THREAD_EXIT? one thread only). Alternative: create
  many binder_threads by spawning many short threads each doing ADD? B per
  thread is per-thread; each thread's B can be freed by that thread.
- alternative reclaims: sendmmsg (batch), SOCK_SEQPACKET, timerfd/CVE-2019-2025
  style ashmem UAF as fallback.
- consider the 'epoll-item' primitive variant: add SECOND epoll on same binder
  fd (two pwqs) - changes list_del next/prev to point at a second kernel object.

## Arms that were also prepared
- exploit containers + meta flash pipeline (notes 70-71): FFBM via misc
  'ffbm-01' meta (flash boot exploit_meta.img, parthash verify; revert =
  flash boot /tmp/opencode/revert_misc.img; misc-zeros sha224(512B) =
  4026dd4dbeb4d8a951dfd9a592897f46203ebe2d99c4a8837aa3afc9).
- poc.c (freestanding port) in /tmp/opencode/lpe/; leakloop{,2,3}.c;
  socktest{,2..10}.c all on host.
