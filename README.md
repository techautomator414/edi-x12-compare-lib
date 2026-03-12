# edi-x12-compare-lib

A portable, self-contained Python library for comparing EDI X12 5010 and translated flat file (FF) output between two systems.

**Python 3.6+. Standard library only. Zero external dependencies.**

Drop `edi_compare_lib.py` anywhere and import it — no package installation required.

---

## What It Does

Designed for healthcare EDI translation QA, this library parses and compares:

- **X12 5010** — All HIPAA transaction sets (837P, 837I, 835, 270/271, 276/277, 278, 834, 820, 999)
- **Flat Files (FF)** — Translated output in fixed-width or pipe-delimited format
- **999 Acknowledgments** — Accept/reject status comparison with error detail extraction

The **smart align engine** handles structural mismatches between files — missing or extra segments are detected and flagged, and comparison continues (rather than stopping at the first mismatch).

---

## Quick Start

```python
from edi_compare_lib import parse_x12, segments_by_transaction, compare_segment_lists

# Parse both files
r1 = parse_x12(open('system1.x12').read())
r2 = parse_x12(open('system2.x12').read())

# Group by ST/SE transaction block (envelope-aware)
blocks1 = segments_by_transaction(r1)
blocks2 = segments_by_transaction(r2)

# Compare each block
for b1, b2 in zip(blocks1, blocks2):
    defects = compare_segment_lists(
        s1_segments=b1['segments'],
        s2_segments=b2['segments'],
        file_base='my_file',
        file_type='x12',
        ignore_fields={},           # optional: skip timestamp/control fields
        diff_mode='realign',        # 'realign' or 'stop_on_first'
        isa_seq=b1['isa_seq'],
        st_seq=b1['st_seq'],
    )
    for d in defects:
        print(d.severity, d.segment_id, d.field_name, d.system1_value, '->', d.system2_value)
```

---

## Flat File Comparison

```python
from edi_compare_lib import parse_ff, records_by_transaction, compare_segment_lists

r1 = parse_ff(open('system1.ff').read())
r2 = parse_ff(open('system2.ff').read())

b1 = records_by_transaction(r1)[0]
b2 = records_by_transaction(r2)[0]

defects = compare_segment_lists(
    s1_segments=b1['segments'],
    s2_segments=b2['segments'],
    file_base='my_ff_file',
    file_type='ff',
    ignore_fields={'ff': ['HDR.5']},    # skip translation timestamp
)
```

---

## 999 Acknowledgment Comparison

```python
from edi_compare_lib import parse_999

ack1 = parse_999(open('system1.999').read())
ack2 = parse_999(open('system2.999').read())

print('S1 accepted:', ack1.is_accepted)
print('S2 accepted:', ack2.is_accepted)

if ack1.group_status != ack2.group_status:
    print('STATUS FLIP:', ack1.group_status, '->', ack2.group_status)
```

---

## API Reference

### Parsers

| Function | Input | Returns |
|---|---|---|
| `parse_x12(content)` | Raw X12 string | `X12ParseResult` |
| `segments_by_transaction(result)` | `X12ParseResult` | List of transaction dicts |
| `parse_ff(content)` | Raw FF string (fixed-width or pipe) | `FFParseResult` |
| `records_by_transaction(result)` | `FFParseResult` | List of transaction dicts |
| `parse_999(content)` | Raw 999 X12 string | `AckResult` |

### Transaction Dict Format

Each entry returned by `segments_by_transaction()` or `records_by_transaction()`:

```python
{
    'isa_seq':          int,   # 1-based ISA envelope ordinal
    'st_seq':           int,   # 1-based global ST ordinal across all ISAs
    'segments':         list,  # 5-tuples: (seg_id, elements, pos, raw, line_num)
    'transaction_code': str,   # e.g. '837', '835', 'FF'
    'st_control':       str,   # ST-02 control number
}
```

### Core Diff Engine

```python
compare_segment_lists(
    s1_segments,          # list of 5-tuples from System 1
    s2_segments,          # list of 5-tuples from System 2
    file_base,            # str — prefix for defect IDs
    file_type,            # 'x12', 'ff', or '999'
    ignore_fields,        # dict — {'x12': ['ISA.09', 'GS.04', ...]}
    diff_mode='realign',  # 'realign' or 'stop_on_first'
    anchor_set=None,      # set of segment IDs used for realignment
    isa_seq=None,         # stamped on every Defect
    st_seq=None,          # stamped on every Defect
) -> List[Defect]
```

**diff_mode options:**
- `realign` — On structural mismatch, scans ahead for next anchor segment and resyncs. Reports EXTRA_SEGMENT or MISSING_SEGMENT defects. Comparison continues.
- `stop_on_first` — Flags first structural mismatch as CRITICAL. Remaining segments marked UNCHECKED.

### Defect Object

```python
d.defect_id        # str  — unique ID, e.g. "myfile_x12_0003"
d.defect_type      # str  — see DefectType constants
d.severity         # str  — 'critical' | 'high' | 'medium' | 'low'
d.file_type        # str  — 'x12' | 'ff' | '999'
d.segment_id       # str  — e.g. 'CLM', 'NM1'
d.element_position # int  — 0-based element index
d.field_name       # str  — e.g. 'CLM.03'
d.system1_value    # str  — value from System 1
d.system2_value    # str  — value from System 2
d.line_s1          # int  — source line in System 1 file
d.line_s2          # int  — source line in System 2 file
d.isa_seq          # int  — ISA envelope ordinal
d.st_seq           # int  — ST transaction ordinal (global)
d.qualifier_value  # str  — NM1 entity code, HL level, etc.
d.to_dict()        # dict — all fields as JSON-serializable dict
d.location_key()   # str  — precise location key incl. envelope context
d.category_key()   # str  — stable cross-run trend key
```

### DefectType Constants

| Constant | Meaning |
|---|---|
| `VALUE_MISMATCH` | Element value differs |
| `MISSING_SEGMENT` | Segment present in S1 but not S2 |
| `EXTRA_SEGMENT` | Segment present in S2 but not S1 |
| `STRUCTURAL_SHIFT` | Unresolvable segment order mismatch |
| `WHITESPACE_DIFF` | Value matches after strip() but raw differs |
| `ELEMENT_COUNT_DIFF` | Different number of elements in segment |
| `STATUS_FLIP` | 999 accept/reject status differs |
| `UNCHECKED` | Segment not compared due to upstream defect |

### Severity Rules

| Severity | Triggers |
|---|---|
| `critical` | STRUCTURAL_SHIFT, STATUS_FLIP |
| `high` | CLM/SVC/SV1/SV2/SV3 value mismatches; NM1 billing/payer/member entity mismatches |
| `medium` | Other value mismatches, ELEMENT_COUNT_DIFF |
| `low` | WHITESPACE_DIFF, DELIMITER_DIFF |

### Ignore Fields Format

Skip elements that are expected to differ (timestamps, control numbers):

```python
ignore_fields = {
    'x12': [
        'ISA.09',   # Interchange date
        'ISA.10',   # Interchange time
        'ISA.13',   # Interchange control number
        'GS.04',    # Group date
        'GS.05',    # Group time
        'GS.06',    # Group control number
    ],
    'ff': ['HDR.5'],   # Translation timestamp
}
```

Format: `"SEGMENT_ID.element_index"` (0-based, includes segment ID at position 0).

---

## Supported X12 5010 Transaction Sets

| TX | Description |
|---|---|
| 837P | Professional Claims |
| 837I | Institutional Claims |
| 837D | Dental Claims |
| 835 | Electronic Remittance Advice |
| 270/271 | Eligibility Inquiry/Response |
| 276/277 | Claim Status Inquiry/Response |
| 278 | Prior Authorization |
| 834 | Benefit Enrollment |
| 820 | Premium Payment |
| 999 | Implementation Acknowledgment |

---

## Requirements

- Python 3.6 or higher
- No third-party packages required
- Single file — `edi_compare_lib.py`

---

## License

MIT License. See [LICENSE](LICENSE).
