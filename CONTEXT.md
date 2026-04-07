# CONTEXT — EDI Compare Library
_Read this before making any changes. Last updated: 2026-03-28._

## What This Is
Standalone Python library extracted from edi-file-compare.
Published to GitHub as a reusable package for X12 5010 EDI comparison.

## Location
`~/projects/edi-compare-lib/`

## Key Files
| File | Purpose |
|---|---|
| `edi_compare_lib.py` | Main library — 70KB, full X12 comparison engine |
| `test_edi_compare_lib.py` | Test suite |
| `example.py` | Usage examples |
| `README.md` | API documentation |

## GitHub
`https://github.com/techautomator414/edi-x12-compare-lib` — v1.4.2

## Canonical Location
The **canonical copy** of `edi_compare_lib.py` lives in:
`~/projects/shared/lib/edi_compare_lib.py`

Changes must be made to the shared copy first, then synced here and to `edi-file-compare`.

## Sync Rule
All three copies must stay in version lock-step:
1. `~/projects/shared/lib/edi_compare_lib.py` ← canonical
2. `~/projects/edi-compare-lib/edi_compare_lib.py` ← published library
3. `~/projects/edi-file-compare/edi_compare_lib.py` ← consumer stub

## Critical Rules for Dispatch/AI
- **Never edit this copy directly** — edit shared/lib first, then sync
- Version must match edi-file-compare
- No new dependencies — pure Python stdlib
