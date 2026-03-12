"""
edi_compare_lib.py
==================
Portable, self-contained EDI X12 5010 / Flat-File comparison library.

Python 3.6+. Standard library only. Zero external dependencies.
No package structure required — drop this single file anywhere and import it.

Exports
-------
Public API (all you need for most integrations):

    parse_x12(content)              -> X12ParseResult
    segments_by_transaction(result) -> list of transaction dicts
    parse_ff(content)               -> FFParseResult
    records_by_transaction(result)  -> list of transaction dicts
    parse_999(content)              -> AckResult
    compare_segment_lists(...)      -> list of Defect
    get_qualifier(segment_id, elems)-> str
    classify_severity(...)          -> Severity constant

Data classes (plain Python objects, no dataclasses module):

    X12Segment, X12ParseResult
    FFRecord, FFParseResult
    AckResult, TransactionAck, ErrorDetail
    Defect, DefectType, Severity, FileType, CompareStatus
    FileCompareResult, FileTripletResult

Quick-start example
-------------------
    from edi_compare_lib import parse_x12, segments_by_transaction, compare_segment_lists

    r1 = parse_x12(open('sys1.x12').read())
    r2 = parse_x12(open('sys2.x12').read())
    blocks1 = segments_by_transaction(r1)
    blocks2 = segments_by_transaction(r2)

    for b1, b2 in zip(blocks1, blocks2):
        defects = compare_segment_lists(
            s1_segments=b1['segments'],
            s2_segments=b2['segments'],
            file_base='my_file',
            file_type='x12',
            ignore_fields={},
            isa_seq=b1['isa_seq'],
            st_seq=b1['st_seq'],
        )
        for d in defects:
            print(d)

License: MIT (same as host project)
"""

# ============================================================================
# SECTION 1 — DEFECT MODEL
# ============================================================================

class DefectType(object):
    VALUE_MISMATCH     = "value_mismatch"
    EXTRA_SEGMENT      = "extra_segment"
    MISSING_SEGMENT    = "missing_segment"
    DELIMITER_DIFF     = "delimiter_diff"
    WHITESPACE_DIFF    = "whitespace_diff"
    STRUCTURAL_SHIFT   = "structural_shift"
    STATUS_FLIP        = "status_flip"
    ELEMENT_COUNT_DIFF = "element_count_diff"
    UNCHECKED          = "unchecked"


class Severity(object):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class FileType(object):
    X12  = "x12"
    FF   = "ff"
    X999 = "999"


class CompareStatus(object):
    MATCH        = "match"
    MISMATCH     = "mismatch"
    ERROR        = "error"
    MISSING_FILE = "missing_file"
    SKIPPED      = "skipped"


_KEY_SEGMENTS = {"CLM", "CLP", "SVC", "SV1", "SV2", "SV3", "CAS", "AMT"}
_ID_SEGMENTS  = {"NM1", "N3", "N4", "DMG", "REF", "SBR"}
_HIGH_SEVERITY_NM1_QUALIFIERS = {"85", "87", "PR", "IL", "QC"}


def classify_severity(defect_type, segment_id, element_position,
                      qualifier_value=None):
    """
    Determine defect severity.
    qualifier_value enables NM1 entity-aware severity for ID segments.
    """
    if defect_type in (DefectType.STATUS_FLIP, DefectType.STRUCTURAL_SHIFT):
        return Severity.CRITICAL
    if defect_type in (DefectType.WHITESPACE_DIFF, DefectType.DELIMITER_DIFF):
        return Severity.LOW
    if defect_type == DefectType.VALUE_MISMATCH:
        if segment_id in _KEY_SEGMENTS:
            return Severity.HIGH
        if segment_id in _ID_SEGMENTS:
            if (segment_id == "NM1"
                    and qualifier_value in _HIGH_SEVERITY_NM1_QUALIFIERS):
                return Severity.HIGH
            return Severity.HIGH
        return Severity.MEDIUM
    return Severity.MEDIUM


class Defect(object):
    """Single comparison defect."""

    _FIELDS = [
        "defect_id", "defect_type", "severity", "file_type",
        "segment_id", "element_position", "field_name",
        "system1_value", "system2_value",
        "line_s1", "line_s2", "context_s1", "context_s2", "notes",
        "isa_seq", "st_seq", "qualifier_value",
    ]

    def __init__(self, defect_id, defect_type, severity, file_type,
                 segment_id, element_position, field_name,
                 system1_value, system2_value,
                 line_s1=None, line_s2=None,
                 context_s1="", context_s2="", notes="",
                 isa_seq=None, st_seq=None, qualifier_value=None):
        self.defect_id        = defect_id
        self.defect_type      = defect_type
        self.severity         = severity
        self.file_type        = file_type
        self.segment_id       = segment_id
        self.element_position = element_position
        self.field_name       = field_name
        self.system1_value    = system1_value
        self.system2_value    = system2_value
        self.line_s1          = line_s1
        self.line_s2          = line_s2
        self.context_s1       = context_s1 or ""
        self.context_s2       = context_s2 or ""
        self.notes            = notes or ""
        self.isa_seq          = isa_seq
        self.st_seq           = st_seq
        self.qualifier_value  = qualifier_value or ""

    def location_key(self):
        parts = []
        if self.isa_seq is not None and self.isa_seq > 1:
            parts.append("ISA{}".format(self.isa_seq))
        if self.st_seq is not None:
            parts.append("ST{}".format(self.st_seq))
        parts.append(self.segment_id)
        parts.append(str(self.element_position)
                     if self.element_position is not None else "")
        parts.append(self.qualifier_value or "")
        return ":".join(parts)

    def category_key(self):
        return "{}:{}:{}".format(
            self.segment_id,
            str(self.element_position)
            if self.element_position is not None else "",
            self.qualifier_value or "",
        )

    def to_dict(self):
        return {f: getattr(self, f) for f in self._FIELDS}

    @classmethod
    def from_dict(cls, d):
        return cls(**{f: d.get(f) for f in cls._FIELDS})

    def __repr__(self):
        return "Defect({}, {}, {}, {}:{})".format(
            self.defect_id, self.defect_type, self.severity,
            self.segment_id, self.element_position)


# ============================================================================
# SECTION 2 — SEGMENT META (qualifier extraction)
# ============================================================================

_QUALIFIER_ELEMENT = {
    "NM1": 1, "PRV": 1, "SBR": 1, "PAT": 1, "HL":  3,
    "REF": 1, "DTP": 1, "AMT": 1, "QTY": 1,
    "CAS": 1, "LQ":  1, "MIA": 1, "MOA": 1,
    "HI":  1, "CR1": 1, "CR2": 1, "CR3": 1,
    "CR4": 1, "CR5": 1, "CR6": 1, "CR7": 1, "CR8": 1,
    "PWK": 1, "SV1": 1, "SV2": 1, "SV3": 1,
    "EQ":  1, "EB":  1, "MSG": 1,
    "TRN": 1, "STC": 1, "UM":  1, "HCR": 1,
    "RMR": 1, "DTM": 1, "INS": 2, "HD":  3, "LX":  1,
}

_COMPOSITE_QUALIFIER_SEGMENTS = {"HI", "SV1", "SV3", "CLM", "STC"}


def get_qualifier(segment_id, elements):
    """
    Extract the qualifier value for a segment instance.

    Args:
        segment_id (str): Segment identifier, e.g. "NM1".
        elements (list):  Full element list including elements[0] == segment_id.

    Returns:
        str: Qualifier string (stripped), or "" if not applicable.
    """
    idx = _QUALIFIER_ELEMENT.get(segment_id)
    if idx is None or idx >= len(elements):
        return ""
    raw = elements[idx].strip() if elements[idx] else ""
    if segment_id in _COMPOSITE_QUALIFIER_SEGMENTS and ":" in raw:
        return raw.split(":")[0].strip()
    return raw


# ============================================================================
# SECTION 3 — X12 PARSER
# ============================================================================

class X12Segment(object):
    def __init__(self, segment_id, elements, position, raw_text, line_number=0):
        self.segment_id  = segment_id
        self.elements    = elements
        self.position    = position
        self.raw_text    = raw_text
        self.line_number = line_number

    def element(self, index, default=""):
        return self.elements[index] if index < len(self.elements) else default

    def element_count(self):
        return len(self.elements)

    def as_tuple(self):
        return (self.segment_id, self.elements, self.position,
                self.raw_text, self.line_number)


class X12Envelope(object):
    def __init__(self):
        self.isa_segment    = None
        self.iea_segment    = None
        self.groups         = []
        self.control_number = ""


class X12Group(object):
    def __init__(self):
        self.gs_segment     = None
        self.ge_segment     = None
        self.transactions   = []
        self.func_id        = ""
        self.control_number = ""


class X12Transaction(object):
    def __init__(self):
        self.st_segment       = None
        self.se_segment       = None
        self.segments         = []
        self.transaction_code = ""
        self.control_number   = ""


class X12ParseResult(object):
    def __init__(self):
        self.envelopes     = []
        self.all_segments  = []
        self.segment_count = 0
        self.error         = ""

    @property
    def is_valid(self):
        return not self.error and len(self.envelopes) > 0


def detect_delimiters(raw_content):
    """Detect X12 delimiters from ISA segment (always 106 chars)."""
    if len(raw_content) < 106 or not raw_content.startswith("ISA"):
        return None, None, None, None
    element_sep     = raw_content[3]
    sub_element_sep = raw_content[104]
    seg_term        = raw_content[105]
    isa_elements    = raw_content[:106].split(element_sep)
    rep_sep = isa_elements[11] if len(isa_elements) > 11 else "^"
    return element_sep, sub_element_sep, seg_term, rep_sep


def parse_x12(content):
    """
    Parse raw X12 content into structured segments and envelopes.
    Returns X12ParseResult. Python 3.6 compatible.
    """
    content = content.strip()
    if not content:
        r = X12ParseResult()
        r.error = "Empty content"
        return r

    element_sep, sub_sep, seg_term, rep_sep = detect_delimiters(content)
    if element_sep is None:
        r = X12ParseResult()
        r.error = "Cannot detect X12 delimiters - missing or malformed ISA"
        return r

    raw_segments = [s.strip() for s in content.split(seg_term) if s.strip()]
    all_segments = []
    for idx, raw in enumerate(raw_segments):
        elements = raw.split(element_sep)
        seg_id   = elements[0] if elements else ""
        seg = X12Segment(segment_id=seg_id, elements=elements, position=idx,
                         raw_text=raw, line_number=idx + 1)
        all_segments.append(seg)

    envelopes           = []
    current_envelope    = None
    current_group       = None
    current_transaction = None

    for seg in all_segments:
        sid = seg.segment_id
        if sid == "ISA":
            current_envelope = X12Envelope()
            current_envelope.isa_segment    = seg
            current_envelope.control_number = seg.element(13, "")
            envelopes.append(current_envelope)
        elif sid == "IEA":
            if current_envelope:
                current_envelope.iea_segment = seg
        elif sid == "GS":
            current_group = X12Group()
            current_group.gs_segment     = seg
            current_group.func_id        = seg.element(1, "")
            current_group.control_number = seg.element(6, "")
            if current_envelope:
                current_envelope.groups.append(current_group)
        elif sid == "GE":
            if current_group:
                current_group.ge_segment = seg
        elif sid == "ST":
            current_transaction = X12Transaction()
            current_transaction.st_segment       = seg
            current_transaction.transaction_code = seg.element(1, "")
            current_transaction.control_number   = seg.element(2, "")
            current_transaction.segments.append(seg)
            if current_group:
                current_group.transactions.append(current_transaction)
        elif sid == "SE":
            if current_transaction:
                current_transaction.se_segment = seg
                current_transaction.segments.append(seg)
                current_transaction = None
        else:
            if current_transaction:
                current_transaction.segments.append(seg)

    result = X12ParseResult()
    result.envelopes     = envelopes
    result.all_segments  = all_segments
    result.segment_count = len(all_segments)
    return result


def segments_to_flat_list(parse_result):
    """Flatten X12ParseResult to list of 5-tuples (backward compat)."""
    return [seg.as_tuple() for seg in parse_result.all_segments]


def segments_by_transaction(parse_result):
    """
    Return segments grouped by ST/SE block for envelope-aware comparison.

    Returns list of dicts:
      {
        'isa_seq':          int,   # 1-based ISA ordinal
        'st_seq':           int,   # 1-based global ST ordinal across all ISAs
        'segments':         list,  # 5-tuples including ST/SE, excluding ISA/IEA/GS/GE
        'transaction_code': str,   # ST-01
        'st_control':       str,   # ST-02
      }
    """
    blocks = []
    st_seq = 0
    for isa_seq, envelope in enumerate(parse_result.envelopes, start=1):
        for group in envelope.groups:
            for transaction in group.transactions:
                st_seq += 1
                blocks.append({
                    "isa_seq":          isa_seq,
                    "st_seq":           st_seq,
                    "segments":         [s.as_tuple() for s in transaction.segments],
                    "transaction_code": transaction.transaction_code,
                    "st_control":       transaction.control_number,
                })
    return blocks


# ============================================================================
# SECTION 4 — FLAT FILE (FF) PARSER
# ============================================================================

FF_FIELD_LAYOUTS = {
    "HDR":  [("record_type", 4), ("envelope_type", 4), ("control_number", 12),
             ("sender_id", 15), ("receiver_id", 15), ("translation_date", 8),
             ("translation_time", 6), ("status", 12)],
    "PRV":  [("record_type", 4), ("provider_id", 15), ("provider_name", 35)],
    "MBR":  [("record_type", 4), ("member_id", 15), ("member_name", 35)],
    "PYR":  [("record_type", 4), ("payer_id", 15), ("payer_name", 35)],
    "CLM":  [("record_type", 4), ("pcn", 15), ("amt1", 15), ("amt2", 15),
             ("ref_id", 15)],
    "SVC":  [("record_type", 4), ("svc_num", 5), ("proc_code", 10),
             ("amt1", 15), ("amt2", 15)],
    "DGN":  [("record_type", 4), ("diagnosis_code", 10), ("qualifier", 4)],
    "ADJ":  [("record_type", 4), ("group_code", 4), ("reason_code", 6),
             ("amt", 15)],
    "ENR":  [("record_type", 4), ("maintenance_code", 5), ("member_id", 15)],
    "ELG":  [("record_type", 4), ("info_type", 4), ("coverage_type", 10),
             ("amt", 15)],
    "STS":  [("record_type", 4), ("status_info", 40)],
    "AUTH": [("record_type", 4), ("cert_type", 4), ("svc_type", 4)],
    "COV":  [("record_type", 4), ("maintenance_type", 5), ("plan_code", 15)],
    "TRL":  [("record_type", 4), ("trailer_type", 4), ("control_number", 12),
             ("claim_count", 10), ("svc_count", 10)],
}

FF_KEY_FIELDS = {
    "HDR": [1, 2], "PRV": [1], "MBR": [1], "PYR": [1], "CLM": [1],
    "SVC": [1, 2], "DGN": [1], "ADJ": [1, 2], "ENR": [1, 2],
    "ELG": [1, 2], "STS": [1], "AUTH": [1, 2], "COV": [1, 2], "TRL": [1, 2],
}


def _parse_fw_line(line, layout):
    fields = []
    pos    = 0
    for _fname, width in layout:
        val = line[pos:pos + width] if pos + width <= len(line) else line[pos:]
        fields.append(val.strip())
        pos += width
    return fields


def _detect_ff_format(content):
    first_line = content.split("\n")[0].strip()
    if not first_line:
        return "fixed_width"
    return "pipe" if "|" in first_line[3:] else "fixed_width"


def _parse_pipe_line(line):
    fields      = line.split("|")
    record_type = fields[0] if fields else ""
    layout      = FF_FIELD_LAYOUTS.get(record_type, [])
    field_names = ([f[0] for f in layout] if layout
                   else ["field_{}".format(i) for i in range(len(fields))])
    return record_type, fields, field_names


class FFRecord(object):
    def __init__(self, record_type, fields, line_number, raw_text,
                 field_names=None, key_values=None):
        self.record_type = record_type
        self.fields      = fields
        self.line_number = line_number
        self.raw_text    = raw_text
        self.field_names = field_names or []
        self.key_values  = key_values  or []

    def field_value(self, index, default=""):
        return self.fields[index] if index < len(self.fields) else default

    def named_field(self, name, default=""):
        if name in self.field_names:
            return self.field_value(self.field_names.index(name), default)
        return default


class FFParseResult(object):
    def __init__(self):
        self.records            = []
        self.record_count       = 0
        self.record_types_found = []
        self.error              = ""

    @property
    def is_valid(self):
        return not self.error and len(self.records) > 0


def parse_ff(content):
    """
    Parse flat file content. Auto-detects fixed-width vs pipe-delimited.
    Returns FFParseResult. Python 3.6 compatible.
    """
    content = content.strip()
    if not content:
        r = FFParseResult()
        r.error = "Empty content"
        return r

    fmt          = _detect_ff_format(content)
    records      = []
    record_types = set()

    for line_num, line in enumerate(content.split("\n"), start=1):
        raw_line = line.rstrip()
        if not raw_line:
            continue
        if fmt == "pipe":
            record_type, fields, field_names = _parse_pipe_line(raw_line)
        else:
            record_type = raw_line[:4].strip()
            layout      = FF_FIELD_LAYOUTS.get(record_type, [])
            if layout:
                fields      = _parse_fw_line(raw_line, layout)
                field_names = [f[0] for f in layout]
            else:
                fields      = [record_type, raw_line[4:].strip()]
                field_names = ["record_type", "data"]

        key_values = [fields[ki] for ki in FF_KEY_FIELDS.get(record_type, [])
                      if ki < len(fields)]
        records.append(FFRecord(
            record_type=record_type, fields=fields,
            line_number=line_num, raw_text=raw_line,
            field_names=field_names, key_values=key_values))
        record_types.add(record_type)

    result                    = FFParseResult()
    result.records            = records
    result.record_count       = len(records)
    result.record_types_found = sorted(record_types)
    return result


def _ff_records_to_flat(parse_result):
    return [
        (rec.record_type, rec.fields, idx, rec.raw_text, rec.line_number)
        for idx, rec in enumerate(parse_result.records)
    ]


def records_to_flat_list(parse_result):
    """Flatten FFParseResult to list of 5-tuples (backward compat)."""
    return _ff_records_to_flat(parse_result)


def records_by_transaction(parse_result):
    """
    Wrap FF records as a single logical transaction for engine loop parity.
    FF has no ISA/ST envelope — isa_seq=1, st_seq=1 are fixed constants.

    Returns:
        [{'isa_seq': 1, 'st_seq': 1, 'segments': [...], 'transaction_code': 'FF', 'st_control': ''}]
    """
    return [{
        "isa_seq":          1,
        "st_seq":           1,
        "segments":         _ff_records_to_flat(parse_result),
        "transaction_code": "FF",
        "st_control":       "",
    }]


# ============================================================================
# SECTION 5 — 999 PARSER
# ============================================================================

class ErrorDetail(object):
    def __init__(self):
        self.segment_id_ref     = ""
        self.segment_position   = ""
        self.loop_id            = ""
        self.syntax_error_code  = ""
        self.element_position   = ""
        self.element_ref        = ""
        self.element_error_code = ""


class TransactionAck(object):
    def __init__(self):
        self.transaction_code = ""
        self.control_number   = ""
        self.status           = ""
        self.error_code       = ""
        self.errors           = []


class AckResult(object):
    def __init__(self):
        self.isa_sender        = ""
        self.isa_receiver      = ""
        self.isa_control       = ""
        self.func_id           = ""
        self.group_control     = ""
        self.version           = ""
        self.group_status      = ""
        self.total_ts_included = ""
        self.total_ts_received = ""
        self.total_ts_accepted = ""
        self.group_error_code  = ""
        self.transaction_acks  = []
        self.x12_result        = None
        self.error             = ""

    @property
    def is_accepted(self):  return self.group_status == "A"
    @property
    def is_rejected(self):  return self.group_status in ("R", "E")
    @property
    def is_valid(self):     return not self.error and self.group_status != ""


def parse_999(content):
    """
    Parse 999 Implementation Acknowledgment content.
    Returns AckResult. Python 3.6 compatible.
    """
    x12_result = parse_x12(content)
    if not x12_result.is_valid:
        r = AckResult()
        r.error      = "X12 parse failed: " + x12_result.error
        r.x12_result = x12_result
        return r

    result            = AckResult()
    result.x12_result = x12_result

    if x12_result.envelopes:
        isa = x12_result.envelopes[0].isa_segment
        if isa:
            result.isa_sender   = isa.element(6, "").strip()
            result.isa_receiver = isa.element(8, "").strip()
            result.isa_control  = isa.element(13, "").strip()

    current_tx_ack = None
    current_error  = None

    for seg in x12_result.all_segments:
        sid = seg.segment_id
        if sid == "AK1":
            result.func_id       = seg.element(1, "")
            result.group_control = seg.element(2, "")
            result.version       = seg.element(3, "")
        elif sid == "AK2":
            current_tx_ack = TransactionAck()
            current_tx_ack.transaction_code = seg.element(1, "")
            current_tx_ack.control_number   = seg.element(2, "")
            current_tx_ack.errors           = []
            result.transaction_acks.append(current_tx_ack)
        elif sid == "IK3":
            current_error = ErrorDetail()
            current_error.segment_id_ref    = seg.element(1, "")
            current_error.segment_position  = seg.element(2, "")
            current_error.loop_id           = seg.element(3, "")
            current_error.syntax_error_code = seg.element(4, "")
            if current_tx_ack is not None:
                current_tx_ack.errors.append(current_error)
        elif sid == "IK4":
            if current_error is not None:
                current_error.element_position  = seg.element(1, "")
                current_error.element_ref       = seg.element(2, "")
                current_error.element_error_code = seg.element(3, "")
        elif sid == "IK5":
            if current_tx_ack is not None:
                current_tx_ack.status     = seg.element(1, "")
                current_tx_ack.error_code = seg.element(2, "")
        elif sid == "AK9":
            result.group_status      = seg.element(1, "")
            result.total_ts_included = seg.element(2, "")
            result.total_ts_received = seg.element(3, "")
            result.total_ts_accepted = seg.element(4, "")
            if seg.element_count() > 5:
                result.group_error_code = seg.element(5, "")

    return result


# ============================================================================
# SECTION 6 — SMART DIFF ENGINE
# ============================================================================

def _find_matching_anchor(segments, target_id, target_key_elements,
                          start_idx, anchor_set, max_lookahead=50):
    limit = min(start_idx + max_lookahead, len(segments))
    for i in range(start_idx, limit):
        seg_id = segments[i][0]
        if seg_id != target_id:
            continue
        if target_key_elements and len(segments[i][1]) > 1:
            seg_elements = segments[i][1]
            if (target_key_elements
                    and len(seg_elements) > 1
                    and target_key_elements[0] == seg_elements[1]):
                return i
        return i
    return -1


def _elements_match(e1, e2, ignore_positions):
    max_len    = max(len(e1), len(e2)) if (e1 or e2) else 0
    mismatches = []
    for i in range(max_len):
        if i in ignore_positions:
            continue
        v1 = e1[i] if i < len(e1) else ""
        v2 = e2[i] if i < len(e2) else ""
        if v1 != v2:
            mismatches.append((i, v1, v2))
    return mismatches


def _build_ignore_set(ignore_fields, segment_id, file_type_key):
    positions  = set()
    field_list = ignore_fields.get(file_type_key, [])
    for field_ref in field_list:
        parts = field_ref.split(".")
        if len(parts) == 2 and parts[0] == segment_id:
            try:
                positions.add(int(parts[1]))
            except ValueError:
                pass
    return positions


def _make_defect(defect_id, defect_type, severity, file_type, segment_id,
                 element_position, field_name, system1_value, system2_value,
                 line_s1, line_s2, context_s1="", context_s2="", notes="",
                 isa_seq=None, st_seq=None, qualifier_value=None):
    return Defect(
        defect_id=defect_id, defect_type=defect_type, severity=severity,
        file_type=file_type, segment_id=segment_id,
        element_position=element_position, field_name=field_name,
        system1_value=system1_value, system2_value=system2_value,
        line_s1=line_s1, line_s2=line_s2,
        context_s1=context_s1, context_s2=context_s2, notes=notes,
        isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qualifier_value,
    )


def compare_segment_lists(
        s1_segments,
        s2_segments,
        file_base,
        file_type,
        ignore_fields,
        diff_mode="realign",
        anchor_set=None,
        isa_seq=None,
        st_seq=None):
    """
    Compare two ordered lists of parsed segments or FF records.

    Args:
        s1_segments (list):  5-tuples (seg_id, elements, pos, raw, line_num) from System 1.
        s2_segments (list):  Same format from System 2.
        file_base (str):     Base filename prefix for defect IDs.
        file_type (str):     "x12", "ff", or "999".
        ignore_fields (dict):file_type -> list of "SEG.elem" strings to skip.
        diff_mode (str):     "realign" (default) or "stop_on_first".
        anchor_set (set):    Segment IDs used as realignment sync points.
        isa_seq (int|None):  ISA envelope ordinal, stamped on every Defect.
        st_seq (int|None):   ST ordinal, stamped on every Defect.

    Returns:
        List of Defect objects.
    """
    if anchor_set is None:
        anchor_set = {
            "ISA", "GS", "ST", "HL", "CLM", "CLP", "NM1", "SBR",
            "SE", "GE", "IEA", "LX", "SV1", "SV2", "SV3",
            "HDR", "PRV", "MBR", "PYR", "SVC", "TRL",
        }

    defects    = []
    defect_seq = 0
    i1 = 0
    i2 = 0

    while i1 < len(s1_segments) and i2 < len(s2_segments):
        seg1      = s1_segments[i1]
        seg2      = s2_segments[i2]
        seg_id1   = seg1[0]
        seg_id2   = seg2[0]
        elements1 = seg1[1]
        elements2 = seg2[1]
        line1     = seg1[4] if len(seg1) > 4 else i1 + 1
        line2     = seg2[4] if len(seg2) > 4 else i2 + 1
        ctx1      = seg1[3] if len(seg1) > 3 else ""
        ctx2      = seg2[3] if len(seg2) > 3 else ""

        if seg_id1 == seg_id2:
            ignore_pos = _build_ignore_set(ignore_fields, seg_id1, file_type)
            mismatches = _elements_match(elements1, elements2, ignore_pos)
            qual       = get_qualifier(seg_id1, elements1)

            for elem_idx, v1, v2 in mismatches:
                defect_seq += 1
                did = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
                if v1.strip() == v2.strip() and v1 != v2:
                    dtype = DefectType.WHITESPACE_DIFF
                elif len(elements1) != len(elements2):
                    dtype = DefectType.ELEMENT_COUNT_DIFF
                else:
                    dtype = DefectType.VALUE_MISMATCH
                sev = classify_severity(dtype, seg_id1, elem_idx, qual)
                defects.append(_make_defect(
                    did, dtype, sev, file_type, seg_id1, elem_idx,
                    "{}.{:02d}".format(seg_id1, elem_idx),
                    v1, v2, line1, line2, ctx1, ctx2,
                    isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qual))
            i1 += 1
            i2 += 1

        else:
            # Structural mismatch
            if diff_mode == "stop_on_first":
                defect_seq += 1
                did  = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
                qual = get_qualifier(seg_id1, elements1)
                defects.append(_make_defect(
                    did, DefectType.STRUCTURAL_SHIFT, Severity.CRITICAL,
                    file_type, seg_id1, None,
                    "Structural mismatch: S1={} vs S2={}".format(seg_id1, seg_id2),
                    seg_id1, seg_id2, line1, line2, ctx1, ctx2,
                    notes="Comparison stopped. Remaining segments unchecked.",
                    isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qual))
                remaining = max(len(s1_segments) - i1,
                                len(s2_segments) - i2) - 1
                if remaining > 0:
                    defect_seq += 1
                    did = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
                    defects.append(_make_defect(
                        did, DefectType.UNCHECKED, Severity.MEDIUM,
                        file_type, "*", None,
                        "{} segments unchecked".format(remaining),
                        "", "", line1, line2,
                        notes="Upstream defect at S1:{} S2:{}".format(line1, line2),
                        isa_seq=isa_seq, st_seq=st_seq))
                break

            else:
                # Realign mode
                match_in_s2 = _find_matching_anchor(
                    s2_segments, seg_id1,
                    elements1[1:2] if len(elements1) > 1 else [],
                    i2 + 1, anchor_set, max_lookahead=20)
                match_in_s1 = _find_matching_anchor(
                    s1_segments, seg_id2,
                    elements2[1:2] if len(elements2) > 1 else [],
                    i1 + 1, anchor_set, max_lookahead=20)

                use_s2 = (match_in_s2 >= 0 and (
                    match_in_s1 < 0
                    or (match_in_s2 - i2) <= (match_in_s1 - i1)))

                if use_s2:
                    for j in range(i2, match_in_s2):
                        defect_seq += 1
                        did      = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
                        extra    = s2_segments[j]
                        extra_id = extra[0]
                        extra_q  = get_qualifier(extra_id, extra[1])
                        extra_ln = extra[4] if len(extra) > 4 else j + 1
                        extra_ctx = extra[3] if len(extra) > 3 else ""
                        defects.append(_make_defect(
                            did, DefectType.EXTRA_SEGMENT,
                            classify_severity(DefectType.EXTRA_SEGMENT, extra_id, None, extra_q),
                            file_type, extra_id, None,
                            "Extra segment in System 2: {}".format(extra_id),
                            "(not present)", extra_ctx or str(extra[1]),
                            line1, extra_ln,
                            notes="Realigned after extra segment(s) in S2",
                            isa_seq=isa_seq, st_seq=st_seq, qualifier_value=extra_q))
                    i2 = match_in_s2

                elif match_in_s1 >= 0:
                    for j in range(i1, match_in_s1):
                        defect_seq += 1
                        did      = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
                        miss     = s1_segments[j]
                        miss_id  = miss[0]
                        miss_q   = get_qualifier(miss_id, miss[1])
                        miss_ln  = miss[4] if len(miss) > 4 else j + 1
                        miss_ctx = miss[3] if len(miss) > 3 else ""
                        defects.append(_make_defect(
                            did, DefectType.MISSING_SEGMENT,
                            classify_severity(DefectType.MISSING_SEGMENT, miss_id, None, miss_q),
                            file_type, miss_id, None,
                            "Missing segment in System 2: {}".format(miss_id),
                            miss_ctx or str(miss[1]), "(not present)",
                            miss_ln, line2,
                            notes="Realigned after missing segment(s) in S2",
                            isa_seq=isa_seq, st_seq=st_seq, qualifier_value=miss_q))
                    i1 = match_in_s1

                else:
                    defect_seq += 1
                    did  = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
                    qual = get_qualifier(seg_id1, elements1)
                    defects.append(_make_defect(
                        did, DefectType.STRUCTURAL_SHIFT, Severity.CRITICAL,
                        file_type, seg_id1, None,
                        "Unresolvable mismatch: S1={} vs S2={}".format(seg_id1, seg_id2),
                        ctx1 or seg_id1, ctx2 or seg_id2, line1, line2,
                        notes="Could not realign within lookahead. Both pointers advanced.",
                        isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qual))
                    i1 += 1
                    i2 += 1

    # Trailing — System 1 only
    while i1 < len(s1_segments):
        seg    = s1_segments[i1]
        seg_id = seg[0]
        qual   = get_qualifier(seg_id, seg[1])
        seg_ln = seg[4] if len(seg) > 4 else i1 + 1
        defect_seq += 1
        defects.append(_make_defect(
            "{}_{}_{:04d}".format(file_base, file_type, defect_seq),
            DefectType.MISSING_SEGMENT,
            classify_severity(DefectType.MISSING_SEGMENT, seg_id, None, qual),
            file_type, seg_id, None,
            "Trailing segment in System 1 only: {}".format(seg_id),
            seg[3] if len(seg) > 3 else str(seg[1]), "(not present)",
            seg_ln, None, isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qual))
        i1 += 1

    # Trailing — System 2 only
    while i2 < len(s2_segments):
        seg    = s2_segments[i2]
        seg_id = seg[0]
        qual   = get_qualifier(seg_id, seg[1])
        seg_ln = seg[4] if len(seg) > 4 else i2 + 1
        defect_seq += 1
        defects.append(_make_defect(
            "{}_{}_{:04d}".format(file_base, file_type, defect_seq),
            DefectType.EXTRA_SEGMENT,
            classify_severity(DefectType.EXTRA_SEGMENT, seg_id, None, qual),
            file_type, seg_id, None,
            "Trailing segment in System 2 only: {}".format(seg_id),
            "(not present)", seg[3] if len(seg) > 3 else str(seg[1]),
            None, seg_ln, isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qual))
        i2 += 1

    return defects


# ============================================================================
# SECTION 7 — RESULT CONTAINERS
# ============================================================================

class FileCompareResult(object):
    def __init__(self, file_type, status, system1_path, system2_path,
                 defect_count=0, defects=None, timestamp_info=None,
                 segment_count_s1=0, segment_count_s2=0,
                 diff_mode_used="realign"):
        self.file_type        = file_type
        self.status           = status
        self.system1_path     = system1_path
        self.system2_path     = system2_path
        self.defect_count     = defect_count
        self.defects          = defects if defects is not None else []
        self.timestamp_info   = timestamp_info
        self.segment_count_s1 = segment_count_s1
        self.segment_count_s2 = segment_count_s2
        self.diff_mode_used   = diff_mode_used

    def to_dict(self):
        return {
            "file_type": self.file_type, "status": self.status,
            "system1_path": self.system1_path, "system2_path": self.system2_path,
            "defect_count": self.defect_count, "defects": self.defects,
            "timestamp_info": self.timestamp_info,
            "segment_count_s1": self.segment_count_s1,
            "segment_count_s2": self.segment_count_s2,
            "diff_mode_used": self.diff_mode_used,
        }


class FileTripletResult(object):
    def __init__(self, base_name, transaction_type, complexity,
                 x12_result=None, ff_result=None, x999_result=None,
                 total_defects=0, has_critical=False):
        self.base_name        = base_name
        self.transaction_type = transaction_type
        self.complexity       = complexity
        self.x12_result       = x12_result
        self.ff_result        = ff_result
        self.x999_result      = x999_result
        self.total_defects    = total_defects
        self.has_critical     = has_critical

    def to_dict(self):
        return {
            "base_name": self.base_name,
            "transaction_type": self.transaction_type,
            "complexity": self.complexity,
            "x12_result": self.x12_result,
            "ff_result": self.ff_result,
            "x999_result": self.x999_result,
            "total_defects": self.total_defects,
            "has_critical": self.has_critical,
        }

    def all_results(self):
        return [r for r in [self.x12_result, self.ff_result, self.x999_result] if r]


# ============================================================================
# SECTION 8 — PUBLIC API SURFACE
# ============================================================================

__all__ = [
    # Parsers
    "parse_x12", "segments_by_transaction", "segments_to_flat_list",
    "parse_ff",  "records_by_transaction",  "records_to_flat_list",
    "parse_999",
    # Core diff engine
    "compare_segment_lists",
    # Segment intelligence
    "get_qualifier", "classify_severity",
    # Data models
    "Defect", "DefectType", "Severity", "FileType", "CompareStatus",
    "FileCompareResult", "FileTripletResult",
    "X12Segment", "X12ParseResult",
    "FFRecord", "FFParseResult",
    "AckResult", "TransactionAck", "ErrorDetail",
    # FF layout metadata (useful for external tooling)
    "FF_FIELD_LAYOUTS", "FF_KEY_FIELDS",
    # X12 delimiter detection utility
    "detect_delimiters",
]
