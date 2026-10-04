# KEYone — RTAS2 LK internals: length-handling audit (candidate bug)

Date: 2026-10-03
Related: notes/16 (RTAS2 protocol spec), notes/17 (securewipe negative).
Source: `emmc_appsboot.mbn` (ABL766) — LK, full symbol table.

## Full RTAS2 LK function map (addresses)

Handshake / session:
- `bbauthtool_sock_client_send`     0x8f639ba0  (indirect via `sock_daemon_recv_handler` ptr @0x8f7bdf78)
- `bbauthtool_sock_client_register` 0x8f639bf0
- `bbauthtool_sock_daemon_send`     0x8f639c30
- `bbauthtool_sock_daemon_register` 0x8f639c80
- `sock_send_msg`                   0x8f6392cc
- `bbauthtool_get_handshake_info`   0x8f63953c
- `bbauthtool_cs_enter/exit`        0x8f6397c4 / 0x8f639840
- `bbauthtool_event_wait/signal`    0x8f6398a0 / 0x8f63991c

RTAS event state machine:
- `process_rtas_init_event`         0x8f63a0f8
- `process_rtas_has_permission_event` 0x8f63a254
- `respond_rtas_sign_event`         0x8f63a37c
- `process_rtas_chal_response`      0x8f63a450   <-- candidate (below)
- `respond_rtas_init_event`         0x8f63a080
- `send_rtas_challenge`             0x8f639e30
- `get_active_rtas_session`         0x8f639d7c

RTAS crypto / verify:
- `rtas_init_ctx`                   0x8f659958
- `rtas_dispose_ctx`                0x8f659a18
- `rtas_create_challenge`           0x8f659a84
- `rtas_create_nv_sig_challenge`    0x8f659b08
- `rtas_verify_response`            0x8f659bc8
- `rtas_verify_nv_sig_response`     0x8f659e24
- `rtas_has_permission`             0x8f659f78
- `rtas_authboot_key_exists`        0x8f659fcc
- TLV/record parser                 0x8f6598a4   <-- safe (see below)

Authorization gate:
- `rtas2_cmd_authorization_check`   0x8f637d04
- `auth_password`                   0x8f638450
- `auth_rtas_init`                  0x8f63857c
- `auth_rtas_has_permission`        0x8f6386e8  (sends cmd string to device; cookie 0xbba78701, size 0x1014)

Token path (see notes/15):
- `dbg_token_validate` 0x8f63b770 · `dbg_token_read_payload` 0x8f63bfa0 ·
  `dbg_token_insert` 0x8f63c05c · `dbg_token_get_hlos_tag_override` 0x8f63c5fc ·
  `dbg_token_is_unsigned_hlos_allowed` 0x8f63c694 · `nvsign_write_rec_and_sign` 0x8f657a04

## Candidate bug: 16-bit length truncation in `process_rtas_chal_response`

`process_rtas_chal_response(r0=ctx, r1=msg)` @ 0x8f63a450:

```asm
8f63a478  beq  invalid_arg                   ; ctx/msg null -> "Invalid argument"
8f63a47c  ldr  r1, [r1, #4]                  ; msg->field4
8f63a480  movw r3, #0x2005
8f63a484  ldr  r2, [r6, #8]                  ; msg->field8
8f63a488  cmp  r1, r3 ; 8f63a48c beq ok      ; require field4 == 0x2005
8f63a4cc  cmp  r2, #0 ; 8f63a4d0 bne err     ; require field8 == 0
8f63a4d4  ldrh r7, [r6, #0xc]                ; len_a = u16 @ msg+0xc
8f63a4d8  ldrh r3, [r6, #0xe]                ; len_b = u16 @ msg+0xe
8f63a4dc  add  r7, r7, r3                    ; r7 = len_a + len_b   (32-bit)
8f63a4e0  add  r7, r7, #4
8f63a4e4  uxth r7, r7                        ; *** TRUNCATE to 16 bits ***
8f63a4e8  cmp  r7, #0x200
8f63a4ec  bhi  resp_len_too_large            ; reject > 512
...
8f63a5e4  mov  r2, r7                        ; length = truncated r7
8f63a5e8  mov  r1, r6
8f63a5ec  bl   0x8f659e24                   ; rtas_verify_nv_sig_response(buf, len)
    (or the alternate arm: 8f63a620 r1=r6+0xc; r2=r7; bl 0x8f659bc8 rtas_verify_response)
```

`len_a + len_b + 4` is computed in 32 bits then **truncated to 16 bits with `uxth`**
before the `<= 0x200` check. If `len_a + len_b + 4 > 0xFFFF`, the value wraps to a
small number, passing the check while the two 16-bit fields are large.

### Why this is only a *candidate*
- Both downstream verifiers (`rtas_verify_nv_sig_response` 0x8f659e24,
  `rtas_verify_response` 0x8f659bc8) re-parse the payload with the **safe**
  record parser `0x8f6598a4`, which does:
  ```asm
  8f6598f8  ldrh r3, [r4]        ; len_a (zero-extended 32-bit)
  8f6598fc  ldrh r2, [r4, #2]    ; len_b
  8f659900  add  r2, r3, r2      ; NO uxth -> 32-bit sum
  8f659904  add  r2, r2, #4
  8f659908  cmp  r2, r7          ; 32-bit compare vs real buffer len
  8f65990c  bne  out_of_range
  ```
  The parser requires `len_a + len_b + 4 == exact total length` in 32-bit, so a
  wrapped outer value would cause the parser to reject unless the real length also
  matches. The `uxth` in the outer function is therefore probably just a
  pre-filter; the true guard is the parser.
- Verdict: **likely NOT exploitable as-is**, but the asymmetry (`uxth` truncate in
  the caller vs 32-bit compare in the parser) is worth a dynamic probe.

## What IS confirmed

- `respond_rtas_sign_event` @0x8f63a37c **bounds sign data to 0x200**
  (`cmp r3,#0x200; bhi` -> "resp_len too large"). Good.
- `rtas_verify_nv_sig_response` requires len>3 and zero-inits a 12-byte out-struct
  before parsing. Good hygiene.
- The device consumes a **signed tool string** (`cmd_string_check` -> cookie
  0xbba78701, size 0x1014) to authorize each fastboot command; the gate is a
  per-boot cached session (`bbauthtool_rtas_init_done` @0x8f7bd8b0).

## Next experiment (dynamic)

Use `tools/authboot_client.py` on the **auth interface** (0x0FCA:80xx MI_01,
ep 0x82/0x02) or via the fastboot `oem getvarp:*` path to drive the RTAS2
handshake, then send a crafted `process_rtas_chal_response` message:
- `msg+4 = 0x2005`, `msg+8 = 0`
- `len_a = 0xFFFE`, `len_b = 0x0001`  -> sum+4 = 0x10003 -> uxth = 0x0003 (passes!)
- observe whether the parser rejects (expected) or the copy over-reads.

This is non-destructive: it only exercises the challenge-response handler; a
crash reboots the bootloader (recoverable, as before).

## Note on dead strings

`"Invalid sock message size: %u"` @0x8f6de454 is **not referenced by any
movw/movt pair** in the image -> dead code, consistent with the Priv corpus
(many BB diagnostics compiled out).
