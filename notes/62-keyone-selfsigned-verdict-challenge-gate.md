# notes/62 — Self-signed RTAS credentials: verdict + corrected oracle statuses + the challenge gate

Date: 2026-10-12. Device: KEYone BBB100-3 ABL766, bootloader mode. Related:
notes/16 (RTAS2 spec), 59 (authboot wire live), 61 (readout/tooling), 53/aboot-re-authboot.

## 1. Goal

Test whether a **self-made P-521 keypair** can pass the authboot challenge
(0x2004/0x2005) — i.e., whether the device validates a BB-issued client cert
or only proof-of-possession of whatever key the PC presents.

## 2. Static decode of the full no-password auth chain (ABL766)

`rtas2_cmd_authorization_check` (0x8f637d04): all callers pass `(r0=1, r1=1, code)`
→ `auth_password()`; if it returns 0 → `r1!=0` → **tool lane**:
`auth_rtas_init` + `auth_rtas_has_permission`.

Reply checks (device-side, reply buffer at 0x8f7bd8dc; all little-endian u32
after the cookie; message = {cookie, code, fields...}):

| Device sends | Oracle must reply | Checks |
|---|---|---|
| `0x1010` (session query) | `0x1011` (12 B) | `[4]==0x1011`, `[8]==1` → proceed |
| `0x1012` (init, 40 B w/ tool name) | `0x1013` (12 B) | `[4]==0x1013`, `[8]==0` → proceed |
| `0x1014` (has-perm, 44 B, code @+0x28) | `0x1015` (16 B) | `[4]==0x1015`, `[8]==0` (status), `[12]==1` (allowed) |

**The old oracle (auth_oracle.py) used 1/1/1 — wrong on two of three.**
Corrected oracle: `tools/oracle_full.py` (temp) — statuses 1 / 0 / 0+1.

## 3. But the challenge comes FIRST — the session gate

Live (fresh session, corrected oracle on the auth interface):

- `oem set-factory-mode` → device sends **0x2004 (524 B)** immediately after the
  0x2000/0x2001 handshake — **before any 0x1010/0x1012/0x1014**.
- `oem getvarp:bsn` → identical 0x2004 (fresh challenge data).
- Payload: cookie, code, TLV-ish fields, ASCII **`AUTHBOOT-bbb100usa`**
  (the channel), then ~500 B fresh challenge data.

So the tool-trusted lane sits **behind** the 0x2004/0x2005 session
establishment (lib_init path).

## 4. The 0x2005 verification — self-signed is cryptographically dead

`process_rtas_chal_response` (0x8f63a450) → `rtas_verify_response` (0x8f659bc8):

- response = `{cookie, 0x2005, 0, len_a:u16, len_b:u16, TLV items}`,
  `len_a+len_b+4 <= 512`;
- TLV items checked: **type 1 = PIN** (4 B) == `get_pin()`, **type 3 = BSN**
  (4 B) == `get_bsn()`, **type 2 = challenge echo** == ctx+24 / u16[ctx+6],
  type 4 = 18 B copied to ctx+0x2e (session material);
- then `is_sig_valid` (0x8f658f30): parses `SEQUENCE{INTEGER r, INTEGER s}`
  from the signature blob, `SHA-512(blob)` and `sb_ecc521_verify_sign(...)`
  with **`[ctx+0x40] = get_key(tool_name)` — the device's built-in per-channel
  key** (AUTHBOOT-bbb100usa, blob @0x8f6e2878). **No key from the response is
  used anywhere.**

**Verdict: a self-made keypair cannot pass. The official `rtas.bin`/PKCS12
must contain BlackBerry's issued private key for the channel.** The two
unchecked memcpys in `is_sig_valid` remain the only signature-side bug
(canary-walled, notes/60).

## 5. Live mechanics worth keeping

- **Garbage 0x2005 responder:** sending a well-formed 0x2005 with zero payload
  makes the device deny fast and clean: `FAILED (remote: authboot command
  permission denied)` in ~0.1 s — no hang, no wedge. (Use for future fuzzing.)
- **Recovery:** pending FAIL responses flush via **EP 0x81 drain** (again live);
  device healthy immediately after.
- Key table (0x8f794988) has two channel classes: **`AUTHBOOT-*`** and
  **`DBGSIG-*`** per product/variant (bbb100cn/emea/japan/usa, bbd100*);
  DBGSIG = debug-signature channel — open question which flows use it
  (debug-token related?).

## 6. Consequences / next

- The authboot challenge gate is cryptographic → the remaining authboot-side
  path is the **pre-auth parser surface**: `parse_response` (0x8f6598a4),
  `rtas_verify_response` item handling, `is_sig_valid` overflow (canary),
  plus the notes/59 fuzz list.
- Everything else unchanged: image verify = ECDSA (notes/61), factory mode =
  set_bootmode via code exec, KGSL kernel path (panics).
