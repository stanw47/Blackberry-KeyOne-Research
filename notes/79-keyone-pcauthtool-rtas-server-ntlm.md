# notes/79 — pcauthtool / RTAS server protocol fully mapped (NTLM) + factory-mode verdict

Date: 2026-10-16. Device: KEYone BBB100-3 ABL766, bootloader mode, serial 1164118297.

## 1. Toolset (all local, not stripped, debug_info)

`recon/2026-10-02/autoloader/ABL766 - Hn03/host/linux-x86/bin/`:
- `authboot` — fastboot clone; RTAS-protected cmds `getvarp [bsn|pin|procid|authbootlog]`,
  `oem set-factory-mode`, `debugtokens`, `flash debug_token`, `erase debug_token`,
  `erase all_debug_tokens`, `-q <token server URL>`, `-x <token_file.zip>`.
  **No `sb_*` crypto, no `BBAuth*`, no libusb, no pcauthtool refs.** `do_send_signature @ 0x4c420`
  is Android AVB `.sig` flashing, not RTAS. `signature must be 256 bytes` = RSA-2048 debug-token lane.
- `pcauthtool` — the RTAS credential agent / libusb daemon. Claims the device auth interface
  (`0FCA:8040` intf1), waits for connection, handles handshake + challenge.
- `fastboot`, `adb`. Windows copies: `~/bb-wine/{authboot,pcauthtool}.exe` (PE32).

## 2. pcauthtool internals (symbols)

- `main @ 0x2b90`; `login @ 0x5640`; `read_response @ 0x6810`; `BBAuthVerifyCred @ 0x6780`;
  `BBAuthDecryptRtasBlob @ 0x5390` / `BBAuthDecryptRtasBlob2 @ 0x53f0`;
  `store_encrypted_rtas_credentials @ 0x4320`; `get_rtas_cred_from_file @ 0x4620`;
  `get_rtas_cred_from_stdin @ 0x4000`; `delete_rtas_credentials @ 0x4110`;
  `invalidate_rtas_credentials @ 0x41f0`; `get_rtas_cred_path @ 0x5200`; `get_random @ 0x5290`.
- Crypto lib (dormant): `sb_ecc521_sign @ 0x7a10` + `sb_ecc521_verify_sign @ 0x7ef0` are called
  ONLY from self-test `sb_verify_ecc521_pub_priv_keys @ 0x7870` (0x79b5/0x79e1);
  `sb_gen_ecc521_pub_priv_keys @ 0x74e0` has no callers. Also `sb_sha_512 @ 0x7220`,
  `sb_sha_256 @ 0x6f60`, `sb_sha_1 @ 0x6eb0`, `sb_enc_aes @ 0x6ad0`, `sb_dec_aes @ 0x6e40`,
  `sb_ecc521_gen_ecdh @ 0x8810`, `sb_ecc521_kdf @ 0x8b20`, `sb_ecc521_ies_kdf_xor_encrypt @ 0x8de0`,
  `sb_ecc256_verify_sign @ 0x8290`, `sb_pre_initialize @ 0x6940`, `sb_initialize_global_context @ 0x69a0`.
- Globals: `rtas_server @ 0x75008`, `rtas_username @ 0x754c8`, `rtas_password @ 0x754cc`.
- Default server string `rtasinsidebb.rim.net` at file offset `0x4e394`; port `0x1f40` = **8000**
  (`login()` does `gethostbyname` + `connect`).
- `store_encrypted_rtas_credentials` AES+HMAC-encrypts `{user,pass,server}` to `<env>/rtas.bin`.
- Usage: `-s` store, `-d` delete, `-u <rtas_user>`, `-r <rtas_pass>`, `-b` bypass RTAS credential
  check at launch, `-p <device_pass>`, `-v`, `-l <log_dir>`. `-b` still prompts for username unless
  `-u/-r` given. Source: `vendor/bbry/security/firmware/bbauthtool/src/pc/pcauthtool.c`.

## 3. RTAS server protocol (rtasinsidebb.rim.net:8000) — NTLM

`login()` = custom length-prefixed framing over TCP, then **NTLMv1** auth. `read_response` struct:
`{u32 total; u16 field4; u16 type; u16 code; u16 payload_len; void*payload; void*extra}`.
Wire: 8-byte header `{u32 total, u16 field4, u16 type}`; if `type==0x10` read 4 more bytes
`{u16 code, u16 payload_len}` + payload + extra(`total-12-payload_len`); else extra = `total-12`
bytes starting at byte 8.

Live capture (fake server on 127.0.0.1:8000, patched binary `pcauthtool_fake`):
1. server → hello `0c000000 0000 1000 0100 0000` (type 0x10, code 1).
2. client → `0c000000 0010 0100 0200 0a00` = `{total=12, 0x11000, 0xa0002}` (start).
3. server → hello-ok (same as hello).
4. client → `30000000 0010 0400` + 40-byte **NTLMSSP NEGOTIATE** (`4e544c4d53535000 01000000 b78208e2 ...`).
5. server → NTLM CHALLENGE (type 2): `3c000000 0000 0400` + `NTLMSSP\0 02000000 ...` (48-byte body).
6. client → 182-byte **NTLM AUTHENTICATE** (type 3): `NTLMSSP\0 03000000 ...` with
   user `testuser`, workstation `Name`, LM/NT responses (NTLMv1: MD4(pass) + DES + MD5).
7. server → (placeholder) → client then forwards the **device challenge**:
   `b3000000 0010 0800` + 171-byte challenge (see §4). Client expects a type-8 response
   (`BBAuthDecryptRtasBlob2` checks `type==8`, `total-8 > arg0x58`); our placeholder → `Decryption failed - code: 0`.

⇒ The RTAS server gate is **Windows-domain NTLM auth with `RIMNET\user` + password**
(confirms notes/65). The server's post-auth reply is an encrypted/signed blob that pcauthtool
decrypts and relays to the device.

## 4. Device RTAS challenge (captured live, 171 bytes)

`ab 00 01 01 12 00 10 00 02 00 81 00 05 00 01 00 84 00 05 00 01 00 00 00`
`"AUTHBOOT-bbb100usa"` `02 00` `<128-byte nonce>`.
- Contains the tool name `AUTHBOOT-bbb100usa` (matches key-table entry `0x8f6e2b34`) + a fresh
  nonce (anti-replay; new nonce each attempt). Device sends this to pcauthtool (0x2004), which
  forwards it to the server; the server signs it; pcauthtool returns the signed blob (0x2005).

## 5. Device-side verification (ABL766) — why this is closed

- `parse_response @ 0x8f6598a4` splits 0x2005 into `{len_a, len_b, data_a, data_b}`; `data_a` =
  all TLV items (PIN, BSN, challenge echo, **type-4 permission bitmap**), `data_b` = ASN.1 signature.
- `is_sig_valid @ 0x8f658f30` hashes `data_a` and verifies `data_b` with `get_key(tool_name)` at
  `ctx+0x40` (built-in public key). Only after valid does `rtas_verify_response @ 0x8f659bc8`
  copy type-4 into `ctx+0x2e` (the bitmap `has_permission @ 0x8f65a140` reads).
- Key table `0x8f794988` (55×20B) is public-only. `sb_ecc521_verify_sign @ 0x8f66d648`.
- ⇒ **The permission bitmap is inside the signed payload; the signature is produced by the RTAS
  server with RIM's ECC-521 private key (AUTHBOOT-bbb100usa).** pcauthtool does NOT sign
  (`sb_ecc521_sign` is self-test-only); it relays. A fake server can complete NTLM but cannot
  produce the signature.

## 6. VERDICT

- `pcauthtool -b` only skips the **local** credential check; the device still waits for the RTAS
  answer (getvarp went from ~0.1s to 8–15s) and returns `(No information available)` without a
  valid server response.
- **Factory mode via pcauthtool/fake server is not achievable**: the device verifies the response
  against RIM's public key; the private key is in RIM's HSM/server (unobtainable). This confirms
  notes/62 and notes/65. The only remaining path is a pre-auth memory-corruption bypass in the ABL
  (canary-walled per notes/60, 78).

## 7. Artifacts

- `/tmp/opencode/pcauthtool_fake` (patched server string → 127.0.0.1), `/tmp/opencode/server3.py`
  (fake NTLM server), `/tmp/opencode/srv3.log`, `/tmp/opencode/pca5.log`.
- Live device handshake (pcauthtool log): BSN 1164118297, ABL766, AAK171, bbb100usa,
  `Device Insecure: false`, Processor ID `000100004C000000A6F528E8...`.
