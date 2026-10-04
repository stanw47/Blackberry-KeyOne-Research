# KEYone (BBB100-3) — Complete Hardware Inventory & Attack-Surface Map

Date: 2026-10-04
Device: BlackBerry KEYone BBB100-3 (Sprint), s/n 1164118297, PCB-61876-001-1
SoC: Qualcomm MSM8953 (Snapdragon 625), 14 nm, 8x Cortex-A53 @2.0 GHz
Sources: live `/proc`, `/sys`, dmesg, kallsyms (167987 syms), MSM8953 device
spec (80-P2472-1), reference-platform schematic (PM8953+PMI8952+WTR3925+WCN36xx).

Legend for **Has FW** = contains its own processor/firmware (attack-relevant).
**Reachable** = can shell (uid 2000, SELinux enforcing) touch it directly.

================================================================================
1. SoC — QUALCOMM MSM8953 ("Snapdragon 625")
================================================================================
- CPU: 8x ARM Cortex-A53 (part 0xd03, r0p4), 4+4 clusters, ARMv8-A aarch64.
- GPU: Adreno 506 @ 650 MHz  -> /dev/kgsl-3d0 (0666), kgsl driver, a506_zap
  TrustZone shader, kgsl-iommu (gfx3d_secure). **Has FW (zap)**.
- Modem: integrated in MSM8953 (LTE Cat7/Cat13, DSDS). **Has FW (modem.mbn)**.
- ADSP: Hexagon DSP v56 (LPASS) -> /dev/adsprpc-smd, fastrpc. **Has FW**.
  ramdump_adsp, ramdump_modem in /proc/misc.
- Video: Venus VPU -> /dev/video* (venus.mdt/b00-b04). **Has FW**.
- Camera: VFE / CSI / CPAS -> cpp_firmware (fw). **Has FW**.
- Display: MDSS/DPU (MIPI DSI), Adreno display. Rotator (/dev/mdss_rotator).
- Audio: LPASS + SLIMbus -> WCD codec path, avtimer (/dev/avtimer).
- Crypto: QCE (Qualcomm Crypto Engine) /dev/misc 63 "qce"; HW random
  /dev/hw_random + msm_rng (/dev/misc msm_rng, char 256).
- TEE: TrustZone/QSECOM -> /dev/qseecom (SELinux tee_device, shell DENIED),
  keymaster/gatekeeper (gatekeeper.msm8953.so seen in BIDE log). **Has TZ fw**.
- RPM: Cortex-M3 power manager (RPM) + MPM.
- ISP: Hexagon (cpp_firmware). GNSS: Gen8C (WCNSS/independent).
- Security HW: SMMU/IOMMU (iommu-ctx nodes), TrustZone, QFuses (jtagfuse
  @a601c, a601c.fuse), QFPROM/feature fuses (bbss WP type permanent).
  Boot ROM (PBL) + SBL1 have fused root keys (RSA) — the true root of trust.
- JTAG/Debug: `619d000.jtagmm`, `619e000.etm`, `61bd000.etm`, CTI/ETM/TMC/FUNNEL
  coresight blocks present (6013000/6018000/... cti, 6027000.tmc, 6100000.funnel).
  => hardware debug infrastructure exists on-die.

================================================================================
2. PMIC / POWER (Qualcomm PM8953 + PMI8952 + SMB1351)
================================================================================
Controller ICs:
- **PM8953** — primary PMIC (SPMI). RPM-controlled rails; PON/reset; RTC;
  thermal; MPP/GPIO. qpnp_rtc @ /sys/class/rtc/rtc0. **Has FW (RPM img)**.
- **PMI8952** — secondary PMIC / charger (I2C). `pmi_chg` class present.
  Internal: battery charger, fuel gauge (FG ADC), USB input, WLED boost
  (display backlight), flash/torch LED driver.
- **SMB1351** (I2C 2-001d "smb1351-charger") — parallel QuickCharge 3.0
  switch-mode charger. **Has FW (not user-updatable)**.
- **qpnp_pon** — power-on/reset input device (input0).
Power-supply nodes (/sys/class/power_supply): battery, bms, bcl (battery
current limit), fg_adc (fuel-gauge ADC), usb, usb-parallel.
Interfaces: SPMI (x2 to MSM8953), I2C, GPIO. Attack: SPMI/I2C bus, charger
QFV/firmware, USB-PD/QC negotiation. Reachable: partially (healthd).

================================================================================
3. STORAGE / MEMORY
================================================================================
- **eMMC 5.1** — Samsung `RX1BMB`, manfid 0x15 (Samsung), OEMID 0x0100,
  serial 0x9464c43c, date 02/2017. 32 GB (BBB100-3). boots: /dev/mmcblk0,
  boot0/boot1, RPMB. **Has FW (eMMC controller)**; RPMB protected via TrustZone.
- **LPDDR3 SDRAM** — non-PoP, 32-bit, up to 933 MHz, 3 GB (BBB100-3). No fw.
- **microSDXC** — shared SIM tray. /dev/mmcblk1, sdhci 7864900/7824900.
- Storage media present: eMMC boot0/boot1 (bootchain), RPMB (BBSS/BIDE),
  GPT user area (56 partitions, see recon/keyone_partitions.txt).
Attack: RPMB (write, cmd), eMMC EXT_CSD write-protect (permanent on boot0),
vendor CMD56 (Toshiba/Samsung vendor cmds), Boot Partition WP.

================================================================================
4. CONNECTIVITY — WCNSS (Wi-Fi / Bluetooth / FM) + NFC + GNSS
================================================================================
- **WCN3680B / WCN3660B** (MSM8953 companion; "WCNSS") — 802.11 a/b/g/n/ac
  1x1, Bluetooth 4.2, FM. Driver: `wlan` kernel module (O), /dev/wcnss_wlan
  (misc 61), wcnss_ctrl (misc 62). **Has FW (WCNSS_fw, wcnss.b*)**.
  remoteproc subsys "wcnss"; wcnss_service, wcnss_filter binaries.
- **NFC: NXP PN548** (PN5xx) — driver `nq-nci` @ I2C 5-0028; /dev/nq-nci
  (misc 64); firmware `libpn548ad_fw.so`. Also `alipay.mbn` (China variant).
  **Has FW + Secure Element (eSE / UICC)**. Attack: NCI prot., eSE, HCE.
- **GNSS: Gen8C** — GPS/GLONASS/BeiDou/Galileo; part of WCNSS/GNSS path.
- **NFC/ESD:** `nq-nci` present; SE likely.

================================================================================
5. RF FRONT-END / MODEM CHAIN
================================================================================
- **WTR3925** (or WTR2965/WTR4905) — RF transceiver (RFIC), MIPI RFFE.
- **RFFE** front-end modules (QFE, PAs) — driven via MIPI RFFE bus.
- Modem inside MSM8953. Modem partition NON-HLOS-usa.bin (98 MB).
- RF cal data: rfcal/rfbackup partitions (gated). IMEI/MEID: `/oem`.
Attack: modem/common processor (relatively privileged), RFFE, QMI, DIAG.

================================================================================
6. AUDIO
================================================================================
- **WCD9335/WCD9326** (PM8953 SLIMbus codec) OR external codec — msm8953-snd-
  card-bbb100 (ALSA card0), Headset Jack + Button Jack input devices.
- **WSA881x** smart speaker amps — `wsa881x-i2c-codec` @ I2C 2-000e/0f/44/45
  (4 instances). Class-D digital amps with DSP. **Has FW (WSA ramping)**.
- **TFA98xx** (NXP speaker boost) possibly — check; not directly seen.
- Interfaces: SLIMbus, I2S, PDM, SoundWire (SWR). Attack: DSP audio img.

================================================================================
7. DISPLAY / TOUCH / HAPTICS / INDICATORS
================================================================================
- Display: 4.5" 1080x1620 IPS LCD, MIPI DSI panel; backlight via PMI8952 WLED
  and leds fan5702/ktd2026. `mdss_fb`, mdss_mdp, mdss_dsi_pll.
- Touch: **Synaptics DSX** (`synaptics_dsx_i2c` @ I2C 6-0020, RMI4, reset flow)
  + **FocalTech fts** (`fts_input_device_B`, ft_rw_iic_drv char 210) — the
  KEYone uses Synaptics ClearPad; FTS is the "B" secondary/pad.
  **Synaptics has FW (touch controller ROM/flash)**. Attack: fw update path.
- Keypad: **STMPE** (`stmpe-keypad` @ I2C 8-0040) — physical QWERTY matrix +
  `stmpe_inject_key` (seen in dmesg). `hammerhead`/matrix keypad.
- Haptics: **msm_hweffects** (misc 66) — timed-output / vibration motor driver.
- LEDs: `leds-fan5702` (I2C 2-0036 / 8-0036) — RGB notification LED +
  keyboard backlight; `leds-ktd2026` (I2C 8-0030) — RGB LED. LED drivers.
- Hall sensor: `/sys/class/hall`, input "hall" (flip/lid). Mag switch.
- Flash/torch: PMI8952 flash LED driver (led:flash/torch, torch-light0/1).

================================================================================
8. CAMERAS
================================================================================
- Rear: **Sony IMX378** 12 MP f/2.0 (1/2.3", 1.55µm, PDAF). I2C + CSI.
- Front: **OmniVision OV8856** 8 MP f/2.2. I2C + CSI.
- Actuator (VCM AF), EEPROM (OTP calibration), flash (dual-LED).
- `msm_actuator`, `msm_eeprom`, `msm_camera_flash`, `msm_csi`, vfe, csid.
- Both sensors have OTP/calibration + firmware. Attack: camera fw/ISP.

================================================================================
9. SENSORS (Qualcomm SSC — Sensors Low Power Island / ADSP)
================================================================================
- /dev/sensors (char 230); class `ssc`; sensors.qcom daemon; SSC on ADSP.
- Sensors present (KEYone): accelerometer, gyroscope, magnetometer/compass,
  proximity, ambient light — all likely via the **ADSP/SSC** (6-axis IMU
  typically **Bosch BMI160** + magnetometer **AKM AK0991x** or **ST**).
  (Priv used similar; exact part not exposed to shell — SSC hides I2C.)
- Fingerprint: **FPC1020** (`soc:fpc1020`, via `hbtp_vm` LDISC,
  /dev/hbtp_input, hbtp class) — front-mounted, in spacebar. **Has FW + TEE**.
- HRM/baro: none on KEYone.
Attack: SSC/ADSP firmware, sensor HAL, fingerprint TA (TrustZone).

================================================================================
10. USB / CHARGING / ACCESSORY
================================================================================
- USB Type-C 3.1 w/ OTG. dwc3 controller, /dev/usb*, android_usb.
- USB functions/misc: mtp_usb, usb_accessory, usb_blackberry (custom BB
  function — the auth/fastboot channel!), android_rndis_qc, android_mbim,
  ccid_bulk/ccid_ctrl (smart-card class), dpl_ctrl.
- Charger: PMI8952 + SMB1351, QC3.0, 18W. HVdcp3 seen in healthd.
- Type-C: dual_role_usb, typec phy, usb_bridge (msm_usb_bridge).
Attack: **usb_blackberry** function = the RTAS2/authboot channel (notes/16);
USB descriptor/class confusion; fastboot protocol.

================================================================================
11. TRUST / SECURITY ELEMENTS
================================================================================
- TrustZone (QSEE) — /dev/qseecom, widevine TA, gatekeeper, keymaster,
  a506_zap, cmnlib64 (mdt/b00-b05). **Has FW, BB-signed** (from prior corpus).
- **BSIS/BIDE** — /dev/bide (char 229), libbidejni; RPMB-backed boot integrity
  at boot. Pathtrust — /dev/pathtrust (char 228), grsecurity-based exec ctrl.
- RPMB — in eMMC, TrustZone-only. Stores boot state, BIDE db.
- Optional secure element for NFC (eSE) via PN548.
- bsSIL / selinux: enforcing, token_service_native_consumer group.

================================================================================
12. DEBUG / MANUFACTURING INTERFACES ON-DIE
================================================================================
- Coresight: ETM/ETB/ETM/TMC/FUNNEL/CTI blocks (many .cti, .etm, .tmc nodes).
- JTAG: jtagmm, jtagfuse (fuse sense), 619d000.jtagmm.
- QFPROM/fuse: a601c.fuse, a601c.jtagfuse (secure-boot fuses).
- DIAG: /dev/diag (char 241), DIAG_CNTL — QCDM diagnostic channel (SELinux/
  group-gated: shell has mfg_client group but diag needs qcom_diag gid).
- UIO: /sys/class/uio (userspace I/O drivers possible).
- SMD/pkt: smdpkt, smd (char 243/242/244) — shared-memory IPC to remoteprocs.
- Subsystems (remoteproc): modem, adsp, wcnss, venus, a506_zap
  (/sys/bus/msm_subsys/devices), each crash-dumpable (ramdump_*).

================================================================================
13. ATTACK-SURFACE RANKING (hardware-rooted)
================================================================================
| # | Component | Has FW | Interface | Reachable | CVE/lead class |
|---|-----------|--------|-----------|-----------|----------------|
| 1 | WCNSS (WCN36xx) | yes | wlan module, wcnss_ctrl | module loaded | QC WLAN QCA6174/WCN CVE family (many) |
| 2 | Adreno 506 KGSL | yes | /dev/kgsl-3d0 (0666) | **yes** | GPU SMMU/DMA 0-days (survive grsec) |
| 3 | NFC PN548 | yes | /dev/nq-nci, I2C | partial | NFC NCI stack CVEs; eSE |
| 4 | TrustZone/Widevine | yes | /dev/qseecom | NO (SELinux) | CVE-2021-1961 class (needs root first) |
| 5 | Modem/ADSP | yes | smdpkt, fastrpc | partial | remote processor LPE |
| 6 | Sensors SSC/ADSP | yes | /dev/sensors, ssc | partial | sensor fw |
| 7 | Synaptics/FocalTech | yes | I2C 6/210 | NO | touch fw update |
| 8 | Fingerprint FPC | yes | hbtp, TEE | NO | FPC TA |
| 9 | eMMC | yes | mmcblk | NO | RPMB/EXT_CSD |
| 10 | USB `usb_blackberry` | - | USB | **yes** | RTAS2 authboot (notes/16) |

### The KEY hardware insight
**WCNSS (Wi-Fi/BT radio)** is the standout: it is a separate ARM processor
running its own firmware, its kernel module `wlan` is **loaded and reachable**,
and Qualcomm WLAN has a *long* history of memory-corruption CVEs (QCA6174 /
WCN36xx / prima driver: CVE-2019-... stack overflows, buffer overflows in the
prima/HDD cfg80211 handlers). Unlike the bootloader/KGSL, the WLAN driver is a
large, historically-buggy, **reachable** attack surface. And crucially, from the
WLAN firmware/driver one can often reach the ADSP/remoteproc via SMD, and
potentially the modem — bypassing the grsec-hardened app processor.

### Second insight
`/dev/kgsl-3d0` (Adreno 506) remains world-writable, and GPU-DMA/SMMU
0-days are the one class that has historically survived grsec/PaX.
