# notes/59 — authboot/RTAS wire protocol REVERSED + live unauthenticated session

Date: 2026-10-11. Device: KEYone BBB100-3 ABL766, bootloader mode.

## Breakthrough

The bootloader's authbroker (RTAS2) protocol is now decoded and reachable from
the host **without credentials** (device has no password set), over the auth
USB interface — the earlier "auth wall" was only the fastboot command
whitelist. We can now drive/fuzz the pre-auth parsers directly.

## Wire format (from pcauthtool.exe RE)

`pcauthtool.exe` ships a COFF symbol table (8437 syms) + the cookie constant.
Frame = **`{cookie:u32 LE = 0xbba78701, code:u32 LE, payload...}`**, sent as ONE
bulk transfer (size includes the 8-byte header).

| code | dir | meaning | size |
|---|---|---|---|
| 0x2000 | PC->DEV | handshake (0x00010003, "Linux", 0x78) | 28 |
| 0x2001 | DEV->PC | handshake info dump | 548 (0x224) |
| 0x2002 | DEV->PC | password prompt (skipped, no password) | - |
| 0x2003 | PC->DEV | password response | 72 (0x48) |
| 0x2004 | DEV->PC | RTAS challenge | - |
| 0x2005 | PC->DEV | RTAS challenge response | 528 (0x210) |
| 0x1010 | PC->DEV | session/state machine request | ? |
| 0x1014 | PC->DEV | "has permission" response (cmd string) | 0x1014 |
| 0x1015 | DEV->PC | has-permission reply | 16 |

Device auth interface: **0FCA:8040 interface 1** (class 0xff/0x02/0xff),
ep 0x82 IN / 0x02 OUT. Fastboot = interface 0 (ep 0x81/0x01).

## Live handshake dump (0x2001, 548 B) — key fields

- serial/BSN `1164118297`
- primary BC `ABL766`, `primary_bc_ver` = 0x10001
- backup BC `AAK171` (`msm_nChipVerAAK171`)
- model `bbb100`, product `bbb100usa`, secure flag `false`

## Device-side dispatcher (ABL766, `0x8f638e44`)

Receives messages (cookie validated against 0xbba78701) and switches on
`[msg+4]`:
- `0x1010` -> 0x8f638f98 (session/state machine driver; 0x8f63d120 state query)
- `0x1014` -> **`process_rtas_has_permission_event` 0x8f63a254** (needs an
  active RTAS session; calls `rtas_has_permission` with our [msg+0x28])
- `0x2000` -> 0x8f639094 (handshake parser; prints our string field at
  msg+0xc, NUL-bounds it at msg+0x1b; sends 0x2001 reply)
- `0x2003` -> 0x8f639028 (`auth_password` path; 0x40-bounded copy)
- `0x2005` -> **`process_rtas_chal_response` 0x8f63a450 with NO state check**
  (the notes/18 16-bit truncation candidate is directly reachable)

## Live test results

- `0x2000` handshake -> immediate `0x2001` 548-byte reply (session alive).
- `0x2005` truncation candidate (len_a=0xFFFE, len_b=1 -> uxth passes as 3):
  clean rejection, no crash, device alive (matches notes/18 verdict).
- `0x2005` oversized (2040 B, > dispatcher's 0x760 stack buffer): handled
  cleanly, no crash. Receive path bounds/queues safely.
- `0x2003` zeroed password reply: no reply (expected).
- `0x1010` zero payload: no reply (needs specific payload).
- 0x1014 direct: needs an active session (signature-gated challenge flow).

## Tools

- `tools/auth_flow.py` — handshake / flow / chal / big / raw sender+receiver
  (pyusb, explicit libusb backend `C:\bb10mt\libusb-1.0.dll`).
- `tools/auth_capture.py` — trigger + capture framework.

## Next (fuzz targets, all pre-auth)

1. 0x2005 verifier deep-fuzz: both paths (normal + nv_sig), TLV parser
   (0x8f6598a4), length/count fields, nested records.
2. 0x2003 password parser (`auth_password` 0x8f638450): size fields, the
   no-password path, possible session-state bypass.
3. 0x1010/0x1014 session machine: reverse the state driver (0x8f63d120,
   0x8f638990) to create a session; test whether a failed permission can be
   flipped.
4. Auth USB receive path: larger transfers (8-64 KB) to map buffer limits.
5. If any parser yields code exec in aboot -> set_bootmode(1,0) (FACTORY) or
   authboot bypass -> the bootloader win.
