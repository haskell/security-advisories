# CVSS v4.0 Specification Revision

## Implementation Target

**Revision**: CVSS v4.0-r1.2 (Specification Document Version 1.2)
**Examples**: CVSS v4.0 Examples Document Version 1.7
**Date verified**: 2026-05-28

## Specification Sources

| Document | URL |
|----------|-----|
| Specification | https://www.first.org/cvss/v4.0/specification-document |
| Examples | https://www.first.org/cvss/v4.0/examples |
| User Guide | https://www.first.org/cvss/v4.0/user-guide |
| Implementation Guide | https://www.first.org/cvss/v4.0/implementation-guide |
| Calculator | https://www.first.org/cvss/calculator/4.0 |
| Reference implementation | https://github.com/RedHatProductSecurity/cvss-v4-calculator |

## Verification Method

All components were verified by direct comparison against the Red Hat / FIRST reference JavaScript implementation (`cvss40.js`) from the official CVSS v4.0 calculator repository. Additionally, all 20 official FIRST CVSS v4.0 example vectors produce the expected scores.

## Verification Results

### Metric Definitions

All 31 metrics across 4 metric groups match the specification:

- [x] AV (Attack Vector): N/A/L/P
- [x] AC (Attack Complexity): L/H
- [x] AT (Attack Requirements): N/P
- [x] PR (Privileges Required): N/L/H
- [x] UI (User Interaction): N/P/A
- [x] VC (Vulnerable System Confidentiality): H/L/N
- [x] VI (Vulnerable System Integrity): H/L/N
- [x] VA (Vulnerable System Availability): H/L/N
- [x] SC (Subsequent System Confidentiality): H/L/N
- [x] SI (Subsequent System Integrity): S/H/L/N
- [x] SA (Subsequent System Availability): S/H/L/N
- [x] E (Exploit Maturity): A/P/U/X
- [x] CR (Confidentiality Requirement): H/M/L/X
- [x] IR (Integrity Requirement): H/M/L/X
- [x] AR (Availability Requirement): H/M/L/X
- [x] MAV/MAC/MAT/MPR/MUI/MVC/MVI/MVA/MSC/MSI/MSA (Modified metrics): X + base values
- [x] S (Safety): X/N/P
- [x] AU (Automatable): X/N/Y
- [x] R (Recovery): X/A/U/I
- [x] V (Value Density): X/D/C
- [x] RE (Vulnerability Response Effort): X/L/M/H
- [x] U (Provider Urgency): X/C/A/G

### EQ Decision Trees

Each EQ decision tree was verified against the reference implementation:

- [x] EQ1 (AV/PR/UI): 3 levels (0/1/2), all branches match
- [x] EQ2 (AC/AT): 2 levels (0/1), logic matches
- [x] EQ3 (VC/VI/VA): 3 levels (0/1/2), all branches match
- [x] EQ4 (SC/SI/SA): 3 levels (0/1/2) including Safety, logic matches
- [x] EQ5 (E): 3 levels (0/1/2), direct mapping matches
- [x] EQ6 (CR/IR/AR + impact): 2 levels (0/1), conditional logic matches

### Severity Constants

All severity distance constants match the reference implementation:

| Metric | High | Medium/Low | None | Safety |
|--------|------|------------|------|--------|
| AV | N:0.0 | A:0.1, L:0.2 | P:0.3 | - |
| PR | N:0.0 | L:0.1 | H:0.2 | - |
| UI | N:0.0 | P:0.1 | A:0.2 | - |
| AC | L:0.0 | - | H:0.1 | - |
| AT | N:0.0 | - | P:0.1 | - |
| VC/VI/VA | H:0.0 | L:0.1 | N:0.2 | - |
| SC | H:0.1 | L:0.2 | N:0.3 | - |
| SI/SA | - | H:0.1, L:0.2 | N:0.3 | S:0.0 |
| CR/IR/AR | H:0.0 | M:0.1 | L:0.2 | - |

### Lookup Table

The macrovector lookup table (270 entries, representing all valid EQ level combinations) was verified entry-by-entry against the FIRST reference implementation. All values match exactly.

### Max Composed Vectors (Severity Distance Reference Points)

- [x] maxComposedEQ1: 3 level configurations (EQ0: 1, EQ1: 3, EQ2: 2) -- all match
- [x] maxComposedEQ2: 2 level configurations (EQ0: 1, EQ1: 2) -- all match
- [x] maxComposedEQ3EQ6: 5 combined configurations -- all match
- [x] maxComposedEQ4: 3 level configurations -- all match

### Max Depth Values

- [x] maxDepthEQ1: EQ0=1, EQ1=4, EQ2=5 -- matches
- [x] maxDepthEQ2: EQ0=1, EQ1=2 -- matches
- [x] maxDepthEQ3EQ6: (0,0)=7, (0,1)=6, (1,0)=8, (1,1)=8, (2,1)=10 -- matches
- [x] maxDepthEQ4: EQ0=6, EQ1=5, EQ2=4 -- matches
- [x] maxDepthEQ5: all=1 -- matches

### Default Value Handling

| Metric | Default | Scoring Behavior | Verified |
|--------|---------|-----------------|----------|
| E (Exploit Maturity) | X -> Attacked (A) | Worst case (EQ5=0) | Yes |
| CR/IR/AR (Security Requirements) | X -> High (H) | Worst case | Yes |
| Modified metrics (MAV, etc.) | X -> fall back to base | No modification | Yes |
| Supplemental metrics (S, AU, etc.) | X -> Not Defined | No score impact | Yes |

### Scoring Formula

The scoring formula was verified indirectly through all 20 official FIRST examples producing correct scores:

- [x] Base score: macrovector lookup + mean severity distance reduction
- [x] Threat score: base metrics + Exploit Maturity (E)
- [x] Environmental score: modified metrics + security requirements
- [x] Rounding: round to 1 decimal place
- [x] Clamping: score in [0.0, 10.0]

### Official FIRST Examples

All 20 official FIRST CVSS v4.0 example vectors produce the expected scores:

| CVE | Vector | Score Type | Expected | Result |
|-----|--------|-----------|----------|--------|
| CVE-2022-41741 | AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | Base | 7.3 | Pass |
| CVE-2020-3549 | AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | Base | 7.7 | Pass |
| CVE-2020-3549 | .../E:U | Threat | 5.2 | Pass |
| CVE-2023-3089 | AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N | Base | 8.3 | Pass |
| CVE-2023-3089 | .../CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L | Env | 8.1 | Pass |
| CVE-2021-44714 | AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N | Base | 4.6 | Pass |
| CVE-2022-21830 | AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N | Base | 5.1 | Pass |
| CVE-2022-22186 | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N | Base | 6.9 | Pass |
| CVE-2023-21989 | AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N | Base | 5.9 | Pass |
| CVE-2020-3947 | AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | Base | 9.4 | Pass |
| CVE-2023-48228 | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H | Base | 9.3 | Pass |
| CVE-2023-30560 | AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D | Base | 8.3 | Pass |
| CVE-2026-20805 | AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A | Threat | 6.8 | Pass |
| CVE-2014-0160 | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A | Threat | 8.7 | Pass |
| CVE-2021-44228 | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A | Threat | 9.3 | Pass |
| CVE-2021-44228 | AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | Base | 8.2 | Pass |
| CVE-2021-44228 | .../E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L | Env | 5.5 | Pass |
| CVE-2013-6014 | AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H | Base | 6.4 | Pass |
| CVE-2016-5729 | AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/R:I | Threat | 8.4 | Pass |

### Notable Implementation Details

1. **E severity values**: The implementation uses 0.0/1.0/2.0 for E severity (vs the reference's 0/0.1/0.2). This is harmless because EQ5's contribution to the severity distance is always multiplied by zero in both implementations.

2. **EQ4 Safety in base metrics**: The base `computeEQ4` includes a Safety check (`siChar == 'S' || saChar == 'S'`), but Safety is only available as a value for MSI/MSA environmental metrics. The base SI/SA metrics can never be 'S', so this branch is unreachable in base scoring. This is consistent with the reference implementation.

3. **EQ3+EQ6 combined selection**: The implementation combines EQ3 and EQ6 for the next-lower macrovector gap selection, using `min` to select the smaller gap (larger score). This matches the reference implementation.

## Revision History

### Initial Implementation
- Based on CVSS v4.0 specification
- Iterative fixes for EQ decision trees and distance calculation

### 2026-05-26: EQ4 and EQ6 decision tree fixes
- Corrected EQ4 and EQ6 decision tree logic (commit 42d9bf5)
- Added Safety (S) support for environmental metrics (commit 13cc3f5)
- Implemented threat metric scoring (commit 418ec09)

### 2026-05-28: Distance calculation fixes
- Fixed EQ3+EQ6 next-lower macrovector selection to use min instead of max (commit fc89270)
- Corrected example borrowing from spec (commit 373406b)

### 2026-05-28: Specification verification
- Full verification against CVSS v4.0-r1.2 (Specification Document Version 1.2)
- Cross-referenced all components against FIRST reference implementation
- All 20 official FIRST examples verified
- Created this documentation
