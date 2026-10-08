# notes/39 — Deep attack-surface map + creative avenues (KEYone unlock)

Date: 2026-10-08
Context: retail unlock denial proven across all four public aboots
(notes/35–38). Software unlock now means finding a *primitive*, or abusing
state/data. This note maps every avenue we know, including brute-force
realities and what the community has already tried.

## 0. Our structural advantage

Four signed aboot baselines preserved (AAK399 Apr-2017 → AAL093 → AAN355 →
ABL766 Jul-2018) plus the full boot chain. This enables **function-level diff
archaeology**: every security fix between builds = a bug that existed in the
older build. We also have raw USB tooling (`tools/keyone_unlock.py`,
`fastboot_libusb.py`), the signed EDL peek programmer, symbolized
disassembly (`lk_xref.py`, `lk_disasm.py`, `kallsyms3.py`), and the KEY2
playbook (kibo) as a template.

## 1. The AAK→AAL lead (fresh 2017 validation code)

- AAL093 (first OTA, 7 days after launch) added: `bide_validate_keypair:*`
  (HW access disabled / decrypt failure / key-derivation failure / validation
  test failed) and `validate_ecc256_pub_priv:*` (input parameter, octet→point
  conversion, sign-R operation, verification failed), plus
  `failed to write to swc_process file`.
- Those messages live in a **quoted message table** (no movw/movt xrefs) —
  locate via the string pointer table; the consumer functions are the new
  validation routines.
- The launch build has **no such validation**: AAK399 is the older, weaker
  key-material validation target. New code written in early 2017 is also the
  least battle-tested code in the 2018 build.

## 2. Non-corruption path: the `bbss_insecure` engineering state

Strings in every build:
- `Insecure bootchain detected. Skipping fuse verification check`
- `Ignoring auth failure on insecure device`
- `Unable to update bsi bbss_insecure`
- `Anti-rollback protection disabled due to token presence`

If the insecure flag is data-backed (BSI/BBSS record in a plain partition),
then **writing that flag** — via root, EDL, or a logic bug — could make the
boot chain skip verification without any memory corruption. This is the
single highest-leverage hypothesis and should be resolved next:
1. disassemble the users of both strings (find gating conditions),
2. determine the storage: BBSS/BSI partition vs RPMB,
3. if plain storage: test EDL/root writes (staged, reversible).

## 3. Parsers and gates (memory-corruption candidates)

- Fastboot/auth token parser: `"device subv and sig tag lengths do not match
  %d != %d"` @ `0x8f653e54` region — appears bounded (strlen, cap 0x1F,
  size+1 copy), but the surrounding token field parsing needs a full audit.
- Token-name builder @ `0x8f63b98c`: `strlen(a)+strlen(b)+3` then alloc/copy
  — check integer-overflow and length semantics.
- Permission system: `authboot_cmd_whitelist` / `authboot_ptn_whitelist` /
  `get_perm_item` @ `0x8f637c4c` — audit for **logic bypasses**: prefix
  matching (`strncmp` lengths), canonicalization mismatch between the name
  looked up and the name dispatched, type-switch edge cases, the `-11`
  retry path. A logic bug here = unlock with zero memory corruption.
- Fastboot protocol **pre-auth** surfaces: `download:` size handling (before
  any auth), `getvar`/`getvarp` formatting (format-string/overflow class,
  the KEY2 bug family), `oem read:`/`oem parthash:` argument parsing.
- USB stack (pre-auth, host-controlled): EP0 control transfers, descriptor
  handling, configuration changes — fuzzable with libusb from the PC.
- SBL1 (never dissected): vtnvfs version-record reader
  (`boot_rollback_version.c`), GPT/DSM parsers, DDR data. Runs before image
  verification.

## 4. EDL via software (no test points)

- Test `adb reboot edl` / `fastboot oem edl` (KEYone was enumerating via ADB).
- With the BlackBerry-signed MSM8953 **peek** programmer: read devinfo/BBSS/
  vtnvfs, EXT_CSD (write-protect answer), rollback state — decisive data.
- If the loader exposes any write/program path: staging ground for BBSS-flag
  experiments. Also: fuzz the firehose XML parser (runs with full memory
  access; read-only commands make failure cheap).
- EDL does not beat PBL signature checks for the boot chain itself.

## 5. Brute force — honest assessment

| Target | Verdict |
|---|---|
| `oem unlock` code | No such code exists (hard deny) — nothing to brute force |
| ECDSA P-521 signatures | Infeasible |
| ARB fuses | Immutable |
| **RTAS/bbauthtool password challenge** | **Worth testing**: capture a `flash:` handshake with USBPcap, audit `password_challenge_verify_*` for offline-crackable verifier or timing channel; factory/service defaults may be low-entropy |
| Hidden `oem` subcommands | Enumerate the full dispatch table; brute-force **read-only** names for undocumented state queries (cheap, nobody has documented the surface) |

## 6. Downgrade strategy (KEY2/kibo model)

1. Hunt bugs in **AAK399** (oldest; weakest validation).
2. If a bug is fixed in AAL/AAN/ABL, downgrading to AAK restores it
   (autoloader downgrade; ARB analysis in notes/37 says soft-brick risk only,
   community downgrades work, our unit never took Oreo).
3. Exploit AAK aboot over USB → patch the deny branch in RAM or set
   insecure state → unlock/flash during that boot; persistence semantics
   (dead verify-skip consumer in retail) remain the open question.

## 7. What the community has tried (and why it failed)

- Stock reload (Sugar QCT / Mobile Upgrade Q / autoloaders) — by design.
- TWRP — runs only on engineering units (`authboot command permission denied`
  on retail).
- FRP/debloat/SIM-unlock tools — unrelated to bootloader.
- Downgrades — work, but every retail build denies unlock.
- Fastboot `oem` exploration — RTAS-gated, denied.
- EDL — needs test points; no full BlackBerry 8953 programmer public.
- Result: KEYone remains uncracked publicly; no one has published
  function-level aboot RE (our advantage).

## 8. Prioritized experiments

1. **Resolve `bbss_insecure` storage/gating** (static; decisive).
2. **Permission-checker + token parser audit** (static; days).
3. **Fastboot pre-auth probes** (dynamic, safe-first): getvar edge cases,
   malformed `download:` sizes, malformed tokens, EP0 fuzz.
4. **AAL→AAK function diff** (map exactly what was added; hunt bugs in the
   AAK baseline).
5. **EDL-via-software** + peek dump (devinfo/BBSS/EXT_CSD), then firehose
   parser fuzz.
6. RTAS password-challenge capture + offline-crack feasibility.

Risk ladder: static (safe) → read-only USB probes → malformed-but-non-flash
fuzzing (aboot crashes reboot) → downgrade flash (recoverable w/ autoloader +
EDL plan) → EDL writes (last resort, staged).
