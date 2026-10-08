# KEYone — `oem securewipe` injection analysis (negative) + RTAS2 gate decode

Date: 2026-10-03
Related: notes/15 (token bypass map), notes/16 (RTAS2 protocol spec).
Prior corpus cross-ref: stanw47/Blackberry-Research `notes/priv-research-log.txt`
(sections 3, 13, 17) and `docs/AUTOLOADER_GUIDE.md` (BootROM wipe warning).

## Question

Can `oem securewipe` (which we confirmed runs **without** RTAS authorization and
executes a destructive wipe) be **injected into** to reach arbitrary write/exec?

## Answer: NO. It parses nothing.

`cmd_oem_secure_wipe` @ `0x8f633350` (160 bytes), disassembled:

```asm
cmd_oem_secure_wipe:
  print("Attempting secure wipe...\n")     ; 0x8f6dbca0
  r0 = 4                                    ; HARDCODED constant
  set_pending_wipe(4)                       ; 0x8f6742fc, mode 4 = USER wipe
  r5 = ret
  if r5 != 0: print("Failed to set wipe for all required FS and NV partitions") ; 0x8f6dbc1c
  else:
      print("Device is set in USER wipe mode.")              ; 0x8f6dbcbc
      print("It will reboot after wipe is complete")         ; 0x8f6dbc78
  return r5
```

- The incoming fastboot command string is **never read** (no `strstr`, no
  `sscanf`, no length/name field).
- The wipe mode is the literal `4`; `set_pending_wipe` only compares against
  fixed constants `4` / `8` / `2`.
- **Zero attacker-controlled bytes flow anywhere.** Not injectable.

### The two live-tested classes of `oem` command

| class | examples | RTAS gate | injectable? |
|-------|----------|-----------|-------------|
| argument-free | `securewipe`, `bide-storage-wipe`, `set-factory-mode` | **often MISSING** (securewipe ran un-gated) | **no** |
| argument-taking | `getvarp:%s`, `read:%s`, `flash:debug_token`, `erase:%s` | **present** (`rtas2_cmd_authorization_check`) | yes → but gated |

This exactly matches the Priv corpus: only `%s`-taking commands feed the authboot
parser; argument-free commands are un-injectable (they just set flags).
`securewipe` is **mis-authorized, not exploitable**.

## RTAS2 authorization gate decode

`rtas2_cmd_authorization_check(handle r0, cmd_id r1, cmd_string r2)`
@ `0x8f637d04` (264 bytes):

```asm
rtas2_cmd_authorization_check:
  if handle != 0: get_perm()                 ; 0x8f638450 -> auth_rtas_has_permission
  if handle == 0 && cmd_id == 0: return 0     ; trivial-allow branch
  if !cached_flag[0x8f7bd8b0]:                ; per-boot session cache
      bbauthtool_perm_open("AUTHBOOT")        ; 0x8f63857c
        -> auth_password / auth_rtas_init / auth_rtas_has_permission
      cached_flag = 1 on success
  r = cmd_string_check(cmd_string)            ; 0x8f6386e8
  if r in {-2, -0x3e}: cache=0; return -0xa   ; reopen needed
  if r == 1: return 0 (allowed)
  else: print("rtas2_cmd_authorization_check failed: %d", r); return -1
```

Supporting strings (resolved): `"AUTHBOOT"`, `"auth_password failed: %d\n"`,
`"auth_rtas_init failed: %d\n"`, `"auth_rtas_has_permission failed: %d\n"`.

Key state globals (LK data):
- `0x8f7bd8b0` — cached "authorized this boot" byte
- `0x8f7bd8b4` / `0x8f7bd8b8` / `0x8f7bd8d8` — authboot session struct fields

`cmd_string_check` (`0x8f6386e8`) opens an authboot connection and **sends the
command string to the device** via the `0x8f639ba0` send path (cookie
`0xbba78701`, size `0x1014` in the request struct) — i.e. the device-side
`bbauthtool` parser is what ultimately authorizes each command. This is the
surface mapped in notes/16.

## `bbauthtool_secure_wipe` (the authorized twin)

`0x8f639cc0` calls `set_pending_wipe(4)` too — same action — but prints
`"bbauthtool: INITIATING SECURE WIPE!"` and honorably reports
`"bbauthtool: set_pending_wipe failed: %d"`. It is the RTAS-authorized variant.
`cmd_oem_secure_wipe` skips the auth check and does the same destructive act.

## Consequence for the exploit plan

- **Do not pursue securewipe** — no input surface.
- The only injectable fastboot surface is the **argument-taking** set, all behind
  `rtas2_cmd_authorization_check` → `cmd_string_check` → device `bbauthtool`
  parser. That device parser (RTAS2 `msg_*` handlers, notes/16) is the target.
- `securewipe` is best treated as a **hazard to avoid**, not a vector.

## Incident note

Testing `oem securewipe` (2026-10-02) erased `boot`+`recovery` on the KEYone.
Fully restored via ABL766 autoloader `flashall.bat` (bootchain, boot, recovery,
system, modem, dsp, oem, userdata, cache all OKAY). Device healthy afterward.

**Recurred 2026-10-09** (run again without re-reading this note): wiped the
boot/recovery **signature records** ("No Signature found") and set the userdata
wipe pending. Restored in-place with `flash bootsig` + `flash recoverysig`
(production-sprint tokens); see notes/49 §0. The sig-wipe is the immediate,
restorable damage; the userdata wipe fires on next boot.
