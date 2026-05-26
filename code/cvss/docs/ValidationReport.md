# CVSS Score Validation Report

**Date:** 2026-05-26
**Source:** FIRST official example documents
**Implementation:** Haskell `cvss` library v0.2.0.1

## Executive Summary

Cross-validation against official FIRST CVSS examples revealed **35 scoring discrepancies** across CVSS v2.0, v3.1, and v4.0. CVSS v3.0 passed all 18 tests.

- **CVSS v2.0:** 14 failures (significant temporal/environmental bugs suspected)
- **CVSS v3.0:** 0 failures (18/18 passed)
- **CVSS v3.1:** 1 failure (17/18 passed, rating discrepancy)
- **CVSS v4.0:** 20 failures (15/20 failed, base scoring issues suspected)

## Detailed Results

### CVSS v2.0: 14 Failures

#### Temporal Score Issues (6 failures)

| CVE | Vector | FIRST Expected | Implementation | Issue |
|-----|--------|----------------|----------------|-------|
| CVE-2002-0392 | `AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C` | Base: 7.8, Temporal: 6.4 | Gets base 7.8 | Not testing temporal score correctly |
| CVE-2002-0392 | `AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C` | 6.4 (temporal) | Gets 6.4 but expects 7.8 (base) | Test expects wrong metric |
| CVE-2003-0818 | `AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C` | Base: 10.0, Temporal: 8.3 | Gets base 10.0 | Same pattern |
| CVE-2003-0818 | `AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C` | 8.3 (temporal) | Gets 8.3 but expects 10.0 (base) | Same pattern |
| CVE-2003-0062 | `AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C` | Base: 6.2, Temporal: 4.9 | Gets base 6.2 | Same pattern |
| CVE-2003-0062 | `AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C` | 4.9 (temporal) | Gets 4.9 but expects 6.2 (base) | Same pattern |

**Analysis:** Test pattern issue - temporal vectors should call `cvss20TemporalScore` but tests are using `cvssScore` which returns base score.

#### Environmental Score Issues (8 failures)

| CVE | Vector | FIRST Expected | Implementation | Issue |
|-----|--------|----------------|----------------|-------|
| CVE-2002-0392 | `.../E:ND/RL:ND/RC:ND/CDP:N/TD:H/CR:H/IR:H/AR:H` | Base: 7.8, Env: 9.2 | Gets 10.0 | TD:H with AR:H should give 9.2 |
| CVE-2002-0392 | `.../CDP:N/TD:H/CR:L/IR:L/AR:L` | Base: 7.8, Env: 4.6 | Gets 5.4 | TD:H with AR:L should give 4.6 |
| CVE-2002-0392 | `.../CDP:N/TD:N` | Base: 7.8, Env: 0.0 | Gets 0.0 | ✅ Correct |
| CVE-2003-0818 | `.../CDP:N/TD:H/CR:H/IR:H/AR:H` | Base: 10.0, Env: 9.0 | Gets 10.0 | TD:H with AR:H should give 9.0 |
| CVE-2003-0818 | `.../CDP:N/TD:H/CR:L/IR:L/AR:L` | Base: 10.0, Env: 6.4 | Gets 8.1 | TD:H with AR:L should give 6.4 |
| CVE-2003-0818 | `.../CDP:N/TD:N` | Base: 10.0, Env: 0.0 | Gets 0.0 | ✅ Correct |
| CVE-2003-0062 | `.../CDP:N/TD:H/CR:M/IR:M/AR:M` | Base: 6.2, Env: 7.5 | Gets 5.8 (rated Medium) | Rating and score mismatch |
| CVE-2003-0062 | `.../CDP:N/TD:H/CR:L/IR:L/AR:L` | Base: 6.2, Env: 5.6 | Gets 4.3 | TD:H with AR:L should give 5.6 |

**Analysis:** TD:N correctly gives 0.0. TD:H scores don't match FIRST values - suggests environmental score formula bug.

### CVSS v3.0: 0 Failures ✅

All 18 official v3.0 examples passed. Scores and ratings match exactly.

### CVSS v3.1: 1 Failure

| CVE | Vector | FIRST Expected | Implementation | Issue |
|-----|--------|----------------|----------------|-------|
| CVE-2019-7551 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H` | High, 9.0 | Critical, 9.0 | Rating boundary: 9.0 should be Critical |

**Analysis:** This is likely correct - v3.1 spec defines Critical as >=9.0, so 9.0 should be Critical. FIRST documentation may have error.

### CVSS v4.0: 20 Failures

#### Base Score Discrepancies (15 failures)

| CVE | Vector | FIRST Expected | Implementation | Issue |
|-----|--------|----------------|----------------|-------|
| CVE-2022-41741 | `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | High, 7.3 | Critical, 9.1 | Major score difference |
| CVE-2020-3549 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | High, 7.7 | Critical, 9.6 | Major score difference |
| CVE-2023-3089 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N` | High, 8.3 | High, 8.4 | Minor difference |
| CVE-2023-3089 (env) | `CVSS:4.0/.../CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L` | High, 8.3 | High, 8.4 | Minor difference |
| CVE-2021-44714 | `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` | Medium, 4.6 | Medium, 6.6 | Significant difference |
| CVE-2022-21830 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` | Medium, 5.1 | High, 7.2 | Significant difference |
| CVE-2023-21989 | `CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N` | Medium, 5.9 | Medium, 6.1 | Minor difference |
| CVE-2020-3947 | `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` | Critical, 9.4 | Critical, 9.7 | Minor difference |
| CVE-2023-30560 | `CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D` | High, 8.3 | Medium, 6.5 | Major difference with safety metrics |
| CVE-2014-0160 (threat) | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A` | High, 7.3 | High, 8.4 | Significant difference |
| CVE-2014-0160 (base) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A` | High, 7.5 | High, 8.8 | Significant difference |
| CVE-2021-44228 (base) | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | High, 8.2 | Critical, 9.2 | Major difference |
| CVE-2021-44228 (env) | `CVSS:4.0/.../E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L` | High, 5.5 | High, 8.2 | Major difference |
| CVE-2013-6014 | `CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H` | Medium, 6.4 | Medium, 6.9 | Minor difference |
| CVE-2016-5729 | `CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/R:I` | High, 8.4 | Critical, 9.5 | Major difference |

#### Threat Score Discrepancies (3 failures)

| CVE | Vector | FIRST Expected | Implementation | Issue |
|-----|--------|----------------|----------------|-------|
| CVE-2020-3549 | `CVSS:4.0/.../E:U` | High, 7.7 | High, 7.9 | Minor difference |
| CVE-2021-44228 | `CVSS:4.0/.../E:A` | Critical, 9.3 | Critical, 9.3 | ✅ Correct |
| CVE-2026-20805 | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A` | High, 6.8 | High, 8.8 | Major difference |

#### Environmental Score Discrepancies (2 failures)

| CVE | Vector | FIRST Expected | Implementation | Issue |
|-----|--------|----------------|----------------|-------|
| CVE-2021-44228 | `CVSS:4.0/.../E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L` | High, 5.5 | High, 8.2 | Major difference |
| CVE-2023-48228 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H` | Critical, 9.3 | Critical, 9.3 | ✅ Correct |

**Analysis:**
- 3 tests passed (CVE-2021-44228 threat, CVE-2023-48228, CVE-2022-22186)
- Many v4.0 base scores differ significantly from FIRST values
- UI:A scores are especially off (4.6→6.6, 5.1→7.2)
- Safety metrics (S:P/V:D) significantly reduce score (8.3→6.5)
- Macrovector lookup table or EQ calculation may have bugs

## Root Cause Analysis

### v2.0 Issues
1. **Test pattern bug:** Temporal vectors call `cvssScore` (base) instead of `cvss20TemporalScore`
2. **Environmental score formula bug:** TD:H scores don't match FIRST values
3. **Potential AR multiplier issue:** High/Low AR give different-than-expected results

### v3.1 Issues
1. **Rating boundary:** 9.0 correctly rated as Critical (>=9.0), FIRST docs may have typo

### v4.0 Issues
1. **Major base scoring discrepancies:** 15/20 tests failed
2. **UI:A handling:** Scores significantly higher than expected
3. **Safety metrics:** S:P/V:D reduce score more than expected
4. **Macrovector/EQ calculation:** Potential bugs in lookup table or EQ computation
5. **Test data verification needed:** Confirm FIRST v4.0 scores are correct (spec may have errors)

## Recommendations

### High Priority
1. **Fix v2.0 environmental score formula** - Investigate TD:H scoring logic
2. **Investigate v4.0 macrovector calculation** - Verify EQ levels and lookup table
3. **Check v4.0 UI:A implementation** - Why scores are higher than FIRST
4. **Verify FIRST v4.0 example scores** - Some may be spec errors

### Medium Priority
1. **Fix v2.0 test temporal pattern** - Use `cvss20TemporalScore` for temporal vectors
2. **Add v4.0 environmental score examples** - Test with modified metrics
3. **Investigate v4.0 safety metrics** - S:P/V:D scoring logic

### Low Priority
1. **Verify v3.1 rating boundary** - FIRST 9.0 High may be a documentation error
2. **Add more v4.0 test vectors** - Follow-up bead will handle this

## Test Data Coverage

- **CVSS v2.0:** 15 vectors (base, temporal, environmental variants)
- **CVSS v3.0:** 18 vectors (all base examples)
- **CVSS v3.1:** 18 vectors (all base examples)
- **CVSS v4.0:** 20 vectors (mix of base, threat, environmental)

## Conclusion

The cross-validation successfully revealed significant scoring discrepancies, particularly in CVSS v2.0 (temporal/environmental) and CVSS v4.0 (base scoring). CVSS v3.0 performed perfectly, and v3.1 has only a minor boundary discrepancy.

**These findings warrant immediate investigation and fixes to ensure mathematical correctness of the CVSS implementation.**

## Follow-up Actions

1. Create bead for v2.0 temporal/environmental scoring bugs (blocks `security-advisories-0ju`)
2. Create bead for v4.0 base scoring investigation
3. Create bead for v4.0 UI:A and safety metrics investigation
4. Follow-up bead `security-advisories-y93` will add more v4.0 test vectors