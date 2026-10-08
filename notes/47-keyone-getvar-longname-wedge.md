# notes/47 — Long `getvar` names wedge the bootloader (DoS-class candidate)

Date: 2026-10-08
Pre-auth fastboot probing against ABL766 (live BBB100-3).

## Observation summary

Sending `getvar` with a long name wedges the fastboot interface: the device
still enumerates (`fastboot devices` OK) but every command write times out
(`AdbWriteEndpointSync failed ... 121`); only a physical reset recovers.
Same signature as the `oem gptinfo` wedge (notes/42).

### Reliable data points (correction, third pass)

Success criterion must be `Finished` present **and** `FAILED` absent — several
earlier "OK" reads were truncated-echo misreads.

| Command line | Result |
|---|---|
| `getvar` + 200-char name (207 B) | **OK** (`Finished`, fast) |
| `getvar` + 1000-char name (1,007 B) | echo only → wedge |
| `getvar` + 1500-char name (1,507 B) | echo only → wedge |
| `getvar` + 2041-char name (2,048 B) | echo only → wedge |
| `getvar` + 4000-char name (4,007 B) | echo only → wedge |

→ Boundary lies in **(207, 1,007]** — much smaller than the 0x800 line limit;
consistent with a small fixed buffer (e.g. 0x100/0x200/0x400) in the getvar
name path or the 64-byte-chunk reassembly.

Recovery note (confirmed by operator): the on-device bootloader menu remains
usable; selecting "continue boot" restarts the OS and fastboot works normally
again on the next entry — no hardware reset needed.

### Bisect plan (one probe per fresh fastboot entry)

Success = response contains `Finished` and not `FAILED`.
Order: 400 → (as needed) 600, 300, 500, 700 → pin the exact byte.

### Earlier data (method-corrected)

| Command line | Result |
|---|---|
| `getvar` + 200-char name | responded; device alive |
| `getvar` + 1000-char name (1,007 B) | responded; device alive |
| `getvar` + 2041-char name (2,048 B) | **device wedged** (writes time out; adb empty) |

(Kept for history; superseded by the corrected table above.)

Method note: a second batch attempted 2048 / 8007 / `oem`-long probes with a
liveness check that matched the *echoed command* (`getvar:version` in stderr)
rather than the response — producing false "ALIVE" results. Post-batch the
device was wedged. Those 8,000-char / `oem` results are **unreliable**.

## Static analysis — fastboot command loop

`fastboot_command_loop` (`0x8f62f138`+):

- `memalign(0x40, 0x1000)` → **4 KB heap command buffer**.
- Per iteration: `memset(buf, 0, 0x40)`, receive via transport vtable
  `[r7+0x20]` (= `0x8f62eb0c`) with `r1 = 0x40`, NUL-terminate at the returned
  length, print `"fastboot: %s"`, then dispatch:
  - special-case `getvar:partition-type` (21-byte strncmp),
  - `authboot_check_command_permission` route,
  - command-table lookup; unknown → `FAIL`.
- Reads are **64 bytes at a time** — long commands span multiple reads and
  must be reassembled (or are truncated/desynced).

## Static analysis — length check and handler

- The only explicit maximum found: `"Command line length is %d, maximum is
  %d"` (`0x8f63b5e8` region) computing **max = 0x800 (2,048 bytes)**.
- `cmd_getvar` (`0x8f62f6bc`) is bounded — values copied into a 0x40-byte
  stack buffer with strlcpy/strlcat-style calls; no unbounded name copy.

## Hypotheses

1. **Receive/dispatch-layer overflow or desync**: if the raw USB transfer
   writes the full host command into a bounded buffer before the 0x800 check
   is applied, a >2 KB command corrupts/hangs the path — the CVE-2018-5854
   class ("stack-based buffer overflow in fastboot", no auth required).
2. **Pure transport deadlock (DoS)**: multi-chunk reassembly desync leaves the
   device waiting for a transfer that never completes.

Distinguishing test requires the reliable-liveness protocol below.

## Next session protocol (one probe per fresh boot)

Reliable liveness: response must contain `OKAY` or `(bootloader)`
(`$out -match 'OKAY|bootloader'`), never the echo.

1. name len 1500 (total 1,507) → expect alive (bisect floor)
2. name len 2041 (total 2,048) → boundary case
3. if wedge: 2000 (total 2,007), then bisect to the exact byte
4. far-beyond test: 8 KB command, watch for different failure mode
   (auto-reset vs deadlock vs no-recovery)
5. command-agnostic test: long `oem` argument, long unknown command
6. If corruption-like behaviour: shape payload toward the mapped patch
   targets (deny branch `0x8f62c1c8`, insecure global `0x8f7948a4`).

## Device state

Wedged in fastboot; physical reset required (hold Power ~15 s).

## Update (fourth pass) - boundaries and host-side hypothesis

- Strict full-output criterion (Finished present, FAILED absent):
  - getvar + 400-char name (407 B): **OK**
  - getvar + 593-char name (600 B): **OK**
- Boundary now known to be **(600, 1500]** (1500 wedged strictly; 1000 untested strictly).
- After the two successes, astboot reboot timed out and the device remained
  in fastboot, unresponsive to commands (still enumerating).
- **New hypothesis: host-side USB bulk-pipe stall** (Windows/QUSB driver),
  not a device hang. Decisive test in progress: unplug/replug the USB cable
  while the phone stays in fastboot; if commands resume immediately, prior
  "wedge" conclusions must be re-examined as host artifacts.

## Update (fifth pass) - host pipe vs device: replug recovery + libusb

- **Replug test**: after a stalled session, unplug/replug of the USB cable
  (phone stays in fastboot) restores command processing instantly. So the
  host-side pipe/endpoint state is a component of the failure.
- However, fresh-pipe **first-shot 1500-char getvar still fails**
  deterministically (host write times out mid-command; follow-up wedged).
  So the trigger is real and reproducible from a clean state.
- libusb with explicit backend (C:\bb10mt\libusb-1.0.dll) enumerates and
  opens the fastboot interface (0FCA:8040, ifaces 0/1 vendor-specific), but
  while stalled the bulk write also times out -> endpoint not consuming until
  re-enumeration.
- Tool 	ools/fb_longcmd_probe.py added: compares **chunked (64 B paced)**
  vs **single-write** long commands after a replug, with liveness checks.

## Next

Run fb_longcmd_probe.py after a replug:
- if chunked survives and single wedges -> host/driver transfer-size issue
  (no device bug);
- if both wedge -> device-side receive handling of long commands.

## Update (sixth pass) - DEVICE-SIDE STALL CONFIRMED

Raw libusb (bypassing Google fastboot entirely, explicit backend):

- sanity getvar:version -> OKAY0.5 (clean)
- **chunked** 1500-char getvar sent as **paced 64-byte writes** -> **STALL**
  mid-stream (ep_out.write timeout), endpoint unresponsive afterwards.
- Conclusion: **not** a host transfer-size artifact. The bootloader
  **stops consuming the OUT endpoint partway through long commands** and the
  endpoint stays stalled until USB re-enumeration (replug). Physical device
  remains healthy (menu works; reboot clears nothing; replug clears the
  endpoint).
- Tool now reports how many bytes were accepted before the stall
  (b_longcmd_probe.py), enabling an exact boundary measurement.

## Next

Replug, then run b_longcmd_probe.py --chars 2000 --chunk 1 (or 64) to read
the accepted-byte count at stall. Candidates: 512/1024/2048 buffer boundary.
If the stall byte count is a round buffer size, the endpoint/receive buffer
is the culprit and the boundary count becomes the exploitation constraint.

## Update (seventh pass) - protocol correction; chunked result was OUR bug

Key insight: **one USB bulk OUT transfer = one complete fastboot command**.
The "stall after 64 bytes" in the chunked test was protocol misuse on our
side: the device took the first 64-byte transfer as a complete (truncated)
command and began sending its reply; because the host was not reading IN
while continuing to write, the device blocked and our second write timed out.

Consequences:
- Chunked testing is invalid; the boundary must be measured with **single
  transfers of increasing size** (what Google fastboot does).
- The genuine remaining candidate is the single-transfer boundary:
  600B OK (Google), 1000B untested-strictly, 1500B fails on a fresh pipe.
- b_longcmd_probe.py rewritten: single-transfer mode with optional second
  size, liveness checks, and clear stall reporting.

## FINAL VERDICT (eighth pass) - NO DEVICE-SIDE LENGTH BUG

Raw libusb single-transfer results (each followed by liveness, all OKAY):

| Command | Result |
|---|---|
| getvar:version | OKAY0.5 |
| getvar 1025 B / 1507 B | OKAY |
| getvar 4007 / 4096 / 4107 / 8199 / 16391 / 65543 B | OKAY |
| getvar 1,048,583 B (1 MB) | OKAY |
| oem + 4089-char arg | FAILunknown command (clean rejection) |

The device handles arbitrarily large single-transfer commands; no stall, no
state change. Conclusion: **the entire "long getvar wedge" was a Google
fastboot client artifact** (its write/read management), not an aboot bug.
No memory-corruption primitive here. Thread closed.

Lessons recorded:
- LK treats **one bulk OUT transfer as one command**; chunked writes are
  invalid fastboot (each chunk = a new command) and cause host-side stalls.
- Prefer the raw libusb harness (	ools/fb_longcmd_probe.py,
  astboot_libusb.py) with explicit backend path for probing; Google
  fastboot's error semantics (echo on stderr, 121 timeouts) misled earlier
  analysis.
- The harness itself is retained as a useful base for future fuzzing
  (download sizes, oem handlers, RTAS capture).

## RTAS-era probe note: download:0 behavior (new lead?)

Raw harness: download:0 -> device replies DATA00000000 (parser fine), then the
endpoint stops consuming (write 10060). Two candidate explanations:

1. Protocol requirement: after DATA, the device expects a data-phase transfer;
   for size 0 that would be a zero-length packet (ZLP). Our client sent none.
2. Device-side hang on download:0 (a legal-looking command) - would be a
   pre-auth hang primitive.

Decisive test (after replug): download:0 -> DATA -> send ZLP (ep_out.write(b''))
-> liveness. If liveness OK, it is protocol; if stalled, download:0 is a hang.

Also queued: download:16 with a proper 16-byte data phase, and the
FAIL-path sizes (0x20000001/0xffffffff) which need no data phase.

## authboot_client.py status

Read: it is a capture/replay framework (scan/sniff/frame/send) with a
working-hypothesis frame layout (cookie/size/version/code, events
HANDSHAKE..DISCONNECTED). Next step for RTAS fuzzing: capture a real exchange
(trigger an RTAS-gated command over the raw harness and record all IN/OUT
traffic), then fuzz the parsed fields.

## download:0 aftermath - USB malfunction + LED (2026-10-08)

After the download:0 probe (DATA00000000, endpoint stopped consuming):

- Windows reports a **malfunctioning USB device** for the KEYone.
- The phone shows a **white blinking LED**.
- ZLP / download:16 follow-up could not run (device no longer enumerates as
  fastboot; no 0FCA devices at all until reset).

Assessment: download:0 (and/or the follow-on state) puts the device into a
USB-corrupted state requiring physical reset - a **device-side crash-class
candidate**, not a mere host artifact. Rules until understood:

1. Do not probe download: with data-phase edge cases again without a
   staged recovery (device reset + known-good autoloader).
2. On recovery, verify nothing persistent changed:
   oem info (Insecure flag, WP type, versions), getvar all diff.
3. If the device boots normally, classify as non-persistent (RAM) state.
4. If it does not boot: bootloader menu -> fastboot; official ABL766
   autoloader restore; EDL only as last resort (test points required).

## download-path campaign - FINAL (2026-10-08)

Results (raw harness, protocol-correct single transfers):

| Probe | Result |
|---|---|
| getvar:version sanity | OKAY0.5 |
| download:0 | DATA00000000 -> then endpoint dead, USB malfunction on host, white LED (assertion halt) |
| download:16 + 16B data | DATA00000016 -> data sent -> device consumes writes but never replies again |
| flash:boot after that | no reply (session cannot be completed without auth) |
| oversize sizes (20000001/ffffffff/7fffffff) | never reached (device already silent) |

Root cause for download:0 (static): the fastboot rx wrapper  x8f62eb0c
has an explicit assert/panic path for size == 0 (file/line constants at
 x8f62ec14); cmd_download does not reject zero size before calling it.
=> pre-auth assertion-halt (DoS), not memory corruption.

Post-crash verification: nothing persistent changed (Insecure: false,
WP Type: permanent, all 26 getvars identical modulo battery voltage).

Conclusions:
- The flash/download path is NOT a usable pre-auth fuzzing surface: a
  download session can only be finished by an auth-gated lash: command,
  so every attempt strands the device (reset required).
- One clean pre-auth DoS: download:0 -> assertion halt. Documented; no
  further probing of this path.

Next surface (queued): capture a live RTAS/authbroker exchange with the raw
harness (trigger via a gated command) and fuzz the parsed message fields.
