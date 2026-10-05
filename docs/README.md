# Documentation Index

Write-ups and guides for the BlackBerry KEYone (BBB100-3) and KEY2 (BBF100-6)
research.

## Published articles

- [KEYone — Adreno KGSL IOMMU vulnerability (public write-up)](KEYone-kgsl-IOMMU-public-writeup.md)
  — the reachable, unpatched kernel bug (CVE-2020-11261 / CVE-2023-33107 class),
  with proof-of-concept results and reproduction steps.
- [KEYone — complete research arc](KEYone-research-arc.md)
  — boot-chain enforcement, the full attack-surface map, the kernel finding, and
  why it is a DoS rather than root.

## Technical deep-dives

- [KEYone — kgsl IOMMU vulnerability (full technical write-up)](KEYone-kgsl-IOMMU-vulnerability.md)
  — source analysis, the safe and corruption PoCs, the global-region-overlap
  primitive (§14), and the io-pgtable guard impact scoping (§15).

## Device guides

- [KEY2 — LineageOS install guide](KEY2-LineageOS-Guide.md)
  — unlock via CVE-2021-1931 and flashing LineageOS 22.2.

## Device mapping

- [devmap — standardized device mapping standard](devmap/STANDARD.md)
  — one schema for every device, OS, and access level (USB → fastboot → ADB →
  root → QNX → EDL); maps live in [`../devmaps/`](../devmaps/) and compare with
  `py tools/devmap.py diff a.json b.json`.

## Session notes

The chronological research trail lives in [`../notes/`](../notes/): device recon,
security-stack mapping, bootloader analysis, the RTAS2 protocol, hardware
inventory, the reachable-surface map, and the KGSL investigation (notes 20–31).
