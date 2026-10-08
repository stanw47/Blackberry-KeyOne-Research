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
