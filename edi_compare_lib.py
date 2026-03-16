"""
edi_compare_lib.py
==================
Portable, self-contained EDI X12 5010 / Flat-File comparison library.

Python 3.6+. Standard library only. Zero external dependencies.
No package structure required — drop this single file anywhere and import it.

v1.4.2 — synced with file_compare project v1.4.2
  - DefectType: full 28-type taxonomy (ISA envelope, GS functional group,
    structural refinements, SNIP/999, orphan/matching, claim rollup)
  - classify_severity(): full qualifier-aware rules — DTP date type, CLM
    element position, INS maintenance type, STC status category, HI, SV*,
    HL structure, REF qualifier, SE/GE/IEA trailer counts
  - compare_segment_lists(): replaced with 4-phase BC-style alignment
    pipeline (EDI key anchors → patience unique-line anchors → closeness
    matching → LCS fallback); skip_segments, skew_tolerance,
    similarity_threshold parameters added
  - segment_meta: IK3/IK4 error code tables, STC category codes,
    DTP qualifier labels, ISA/GS version/funcid maps, describe_qualifier()
  - FileCompareResult.from_dict(), FileTripletResult.from_dict() added
  - FileTripletResult: mode and pair_name fields added
  - __version__ = "1.4.2"

Exports
-------
Public API:

    parse_x12(content)                   -> X12ParseResult
    segments_by_transaction(result)      -> list of transaction dicts
    parse_ff(content)                    -> FFParseResult
    records_by_transaction(result)       -> list of transaction dicts
    parse_999(content)                   -> AckResult
    compare_segment_lists(...)           -> list of Defect
    get_qualifier(segment_id, elems)     -> str
    classify_severity(...)               -> Severity constant
    describe_qualifier(seg_id, qual)     -> str

Data classes:

    X12Segment, X12ParseResult
    FFRecord, FFParseResult
    AckResult, TransactionAck, ErrorDetail
    Defect, DefectType, Severity, FileType, CompareStatus
    FileCompareResult, FileTripletResult, TimestampInfo

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

__version__      = "1.4.2"
__release_date__ = "2026-03-16"

import re
import bisect
import difflib
from collections import defaultdict, deque


# ============================================================================
# SECTION 1 — DEFECT MODEL
# ============================================================================

class DefectType(object):
    # ── Existing (preserved) ─────────────────────────────────────────────────
    VALUE_MISMATCH      = "value_mismatch"
    EXTRA_SEGMENT       = "extra_segment"
    MISSING_SEGMENT     = "missing_segment"
    DELIMITER_DIFF      = "delimiter_diff"
    WHITESPACE_DIFF     = "whitespace_diff"
    STRUCTURAL_SHIFT    = "structural_shift"   # kept for backward compat
    STATUS_FLIP         = "status_flip"
    ELEMENT_COUNT_DIFF  = "element_count_diff"
    UNCHECKED           = "unchecked"

    # ── ISA interchange envelope ──────────────────────────────────────────────
    ISA_SENDER_MISMATCH     = "isa_sender_mismatch"     # ISA06
    ISA_RECEIVER_MISMATCH   = "isa_receiver_mismatch"   # ISA08
    ISA_ENV_MISMATCH        = "isa_env_mismatch"        # ISA15 P vs T
    ISA_VERSION_MISMATCH    = "isa_version_mismatch"    # ISA12
    ISA_DELIMITER_MISMATCH  = "isa_delimiter_mismatch"  # ISA11 or ISA16
    ISA_ACK_POLICY_MISMATCH = "isa_ack_policy_mismatch" # ISA14
    ISA_QUALIFIER_MISMATCH  = "isa_qualifier_mismatch"  # ISA05 or ISA07

    # ── GS functional group ───────────────────────────────────────────────────
    GS_VERSION_MISMATCH = "gs_version_mismatch"   # GS08
    GS_FUNCID_MISMATCH  = "gs_funcid_mismatch"    # GS01

    # ── Structural (refined) ──────────────────────────────────────────────────
    SEGMENT_ORDER_VIOLATION = "segment_order_violation"
    ALIGNMENT_FAILURE       = "alignment_failure"
    LOOP_STRUCTURE_MISMATCH = "loop_structure_mismatch"
    TRAILER_COUNT_MISMATCH  = "trailer_count_mismatch"
    SEGMENT_COUNT_INTEGRITY = "segment_count_integrity"

    # ── Claim rollup ──────────────────────────────────────────────────────────
    CLAIM_COUNT_MISMATCH = "claim_count_mismatch"

    # ── SNIP / 999 ────────────────────────────────────────────────────────────
    SNIP_VALIDATION_FAILURE = "snip_validation_failure"
    TX_COUNT_MISMATCH       = "tx_count_mismatch"

    # ── Orphan / file matching ────────────────────────────────────────────────
    ORPHAN_SYS1          = "orphan_sys1"
    ORPHAN_SYS2          = "orphan_sys2"
    DATE_SUBDIR_MISMATCH = "date_subdir_mismatch"


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


# ── Severity routing constants ────────────────────────────────────────────────

_KEY_SEGMENTS   = {"CLM", "CLP", "SVC", "SV1", "SV2", "SV3", "CAS", "AMT"}
_ID_SEGMENTS    = {"NM1", "N3", "N4", "DMG", "REF", "SBR"}
_HIGH_NM1_QUALS = {"85", "87", "PR", "IL", "QC"}

# DTP-01 qualifiers whose date values are operationally critical
# Verified via ASC X12 Glass 005010X222A1, 005010X220A1
_CRITICAL_DTP_QUALS = {
    "472",  # Service Date — 837 Loop 2400 (REQUIRED)
    "435",  # Admission Date/Hour — 837 Loop 2300 (inpatient/ambulance)
    "096",  # Discharge Date — 837 Loop 2300 (inpatient)
    "348",  # Benefit Begin — 834 Loop 2300 (coverage effective, REQUIRED on add)
    "349",  # Benefit End — 834 Loop 2300 (coverage termination)
}
_HIGH_DTP_QUALS = {
    "303",  # Maintenance Effective — 834 Loop 2300
    "343",  # Premium Paid to Date End — 834
    "291",  # Plan/Coverage Eligibility Date — 270/271
    "304",  # Latest Visit or Consultation — 837
    "454",  # Initial Treatment Date — 837
    "439",  # Accident Date — 837
    "484",  # Last Menstrual Period — 837
    "455",  # Last X-Ray Date — 837
    "300",  # Enrollment Signature Date — 834
}

# CLM element positions that warrant elevated severity (0-based, includes seg ID at 0)
_CRITICAL_CLM_POSITIONS = {9}    # CLM09 procedure code (institutional)
_HIGH_CLM_POSITIONS     = {5, 6, 7, 11}
# CLM05=place of service composite, CLM06=provider assignment,
# CLM07=assignment of benefits, CLM11=related causes/EPSDT

# INS-03 maintenance type codes
_CRITICAL_INS_MAINT_TYPES = {"030", "021"}           # termination, COBRA
_HIGH_INS_MAINT_TYPES     = {"001", "024", "025", "002"}

# STC-01-1 claim status category codes (277 TR3: 005010X212, Code Source 507)
_CRITICAL_STC_CATEGORIES = {"F0", "F1", "F2", "F3", "F4"}  # Finalized
_HIGH_STC_CATEGORIES     = {
    "A0", "A1", "A2", "A3",   # Acknowledge
    "P0", "P1", "P2", "P3", "P4",  # Pending
    "D0", "E",                 # Info receiver/provider level
}


def classify_severity(defect_type, segment_id, element_position,
                      qualifier_value=None):
    """
    Determine defect severity based on type, segment, element position,
    and qualifier value. Python 3.6 compatible.
    """
    # ── ISA envelope ─────────────────────────────────────────────────────────
    if defect_type in (DefectType.ISA_SENDER_MISMATCH,
                       DefectType.ISA_RECEIVER_MISMATCH,
                       DefectType.ISA_ENV_MISMATCH,
                       DefectType.ISA_VERSION_MISMATCH):
        return Severity.CRITICAL
    if defect_type in (DefectType.ISA_DELIMITER_MISMATCH,
                       DefectType.ISA_ACK_POLICY_MISMATCH,
                       DefectType.ISA_QUALIFIER_MISMATCH):
        return Severity.HIGH

    # ── GS functional group ───────────────────────────────────────────────────
    if defect_type == DefectType.GS_VERSION_MISMATCH:
        return Severity.CRITICAL
    if defect_type == DefectType.GS_FUNCID_MISMATCH:
        return Severity.HIGH

    # ── Structural ────────────────────────────────────────────────────────────
    if defect_type in (DefectType.STATUS_FLIP,
                       DefectType.STRUCTURAL_SHIFT,
                       DefectType.ALIGNMENT_FAILURE):
        return Severity.CRITICAL
    if defect_type in (DefectType.SEGMENT_ORDER_VIOLATION,
                       DefectType.LOOP_STRUCTURE_MISMATCH,
                       DefectType.TRAILER_COUNT_MISMATCH,
                       DefectType.SEGMENT_COUNT_INTEGRITY,
                       DefectType.CLAIM_COUNT_MISMATCH):
        return Severity.HIGH

    # ── SNIP / 999 ────────────────────────────────────────────────────────────
    if defect_type in (DefectType.SNIP_VALIDATION_FAILURE,
                       DefectType.TX_COUNT_MISMATCH):
        return Severity.HIGH

    # ── Orphan ───────────────────────────────────────────────────────────────
    if defect_type in (DefectType.ORPHAN_SYS1, DefectType.ORPHAN_SYS2):
        return Severity.HIGH
    if defect_type == DefectType.DATE_SUBDIR_MISMATCH:
        return Severity.MEDIUM

    # ── Whitespace / delimiter ────────────────────────────────────────────────
    if defect_type in (DefectType.WHITESPACE_DIFF, DefectType.DELIMITER_DIFF):
        return Severity.LOW

    # ── Element count mismatch ────────────────────────────────────────────────
    if defect_type == DefectType.ELEMENT_COUNT_DIFF:
        if segment_id in _KEY_SEGMENTS:
            return Severity.HIGH
        return Severity.MEDIUM

    # ── Value mismatch — segment + element + qualifier aware ─────────────────
    if defect_type == DefectType.VALUE_MISMATCH:
        if segment_id == "NM1":
            if qualifier_value in _HIGH_NM1_QUALS:
                return Severity.HIGH
            return Severity.MEDIUM

        if segment_id == "DTP":
            if qualifier_value in _CRITICAL_DTP_QUALS:
                if element_position is None or element_position == 3:
                    return Severity.CRITICAL
            if qualifier_value in _HIGH_DTP_QUALS:
                if element_position is None or element_position == 3:
                    return Severity.HIGH
            return Severity.MEDIUM

        if segment_id == "CLM":
            if element_position in _CRITICAL_CLM_POSITIONS:
                return Severity.CRITICAL
            if element_position in _HIGH_CLM_POSITIONS:
                return Severity.HIGH
            return Severity.HIGH  # all CLM mismatches are at least HIGH

        if segment_id == "INS":
            if qualifier_value in _CRITICAL_INS_MAINT_TYPES:
                return Severity.CRITICAL
            if qualifier_value in _HIGH_INS_MAINT_TYPES:
                return Severity.HIGH
            return Severity.MEDIUM

        if segment_id == "STC":
            if qualifier_value in _CRITICAL_STC_CATEGORIES:
                return Severity.CRITICAL
            if qualifier_value in _HIGH_STC_CATEGORIES:
                return Severity.HIGH
            return Severity.MEDIUM

        if segment_id == "HI":
            return Severity.HIGH

        if segment_id in ("SV1", "SV2", "SV3"):
            if element_position == 1:
                return Severity.CRITICAL
            return Severity.HIGH

        if segment_id in ("CLP", "CAS", "AMT"):
            return Severity.HIGH

        if segment_id in _KEY_SEGMENTS:
            return Severity.HIGH

        if segment_id in _ID_SEGMENTS:
            return Severity.HIGH

        if segment_id in ("SE", "GE", "IEA"):
            if element_position == 1:
                return Severity.HIGH
            return Severity.MEDIUM

        if segment_id == "HL":
            if element_position in (2, 3, 4):
                return Severity.HIGH
            return Severity.MEDIUM

        if segment_id == "REF":
            if qualifier_value in ("1G", "9F", "G1", "F8"):
                return Severity.HIGH
            return Severity.MEDIUM

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
        return "Defect({}, {}, {}, {}:{}:{})".format(
            self.defect_id, self.defect_type, self.severity,
            self.segment_id, self.element_position, self.qualifier_value)


# ============================================================================
# SECTION 2 — SEGMENT META (qualifier extraction + reference tables)
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


# ISA12 version identifier descriptions
ISA_VERSIONS = {
    "00501": "X12 5010 (HIPAA)",
    "00401": "X12 4010 (legacy)",
    "00400": "X12 4.0 (legacy)",
    "00200": "X12 2.0 (legacy)",
}

# GS01 functional identifier descriptions
GS_FUNC_IDS = {
    "HC": "Health Care Claim (837)",
    "HP": "Health Care Claim Payment (835)",
    "BE": "Benefit Enrollment (834)",
    "RA": "Premium Payment (820)",
    "HN": "Health Care Claim Status (276/277)",
    "HB": "Health Care Eligibility Response (271)",
    "HS": "Health Care Eligibility Inquiry (270)",
    "HI": "Health Care Services Review (278)",
    "FA": "Functional Acknowledgment (999/997)",
}

# IK3 syntax error codes (005010X231A1)
IK3_SYNTAX_ERRORS = {
    "1": "Unrecognized segment ID",
    "2": "Unexpected segment",
    "3": "Mandatory segment missing",
    "4": "Loop occurs over maximum times",
    "5": "Segment exceeds maximum use",
    "6": "Segment not in defined transaction set",
    "7": "Segment not in proper sequence",
    "8": "Segment has data element errors",
}

# IK4 element error codes (005010X231A1)
IK4_ELEMENT_ERRORS = {
    "1": "Mandatory data element missing",
    "2": "Conditional required data element missing",
    "3": "Too many data elements",
    "4": "Data element too short",
    "5": "Data element too long",
    "6": "Invalid character in data element",
    "7": "Invalid code value",
    "8": "Invalid date",
    "9": "Invalid time",
    "10": "Exclusion condition violated",
}

# STC-01-1 claim status category codes (277 TR3: 005010X212, Code Source 507)
STC_CATEGORY_CODES = {
    "A0": "Acknowledge - Not Found",
    "A1": "Acknowledge - Pending",
    "A2": "Acknowledge - Returned as Unprocessable",
    "A3": "Acknowledge - Returned as Not Found",
    "F0": "Finalized - Payment for Claim",
    "F1": "Finalized - Denied",
    "F2": "Finalized - Adjusted",
    "F3": "Finalized - Additional Information Requested",
    "F4": "Finalized - Pending",
    "P0": "Pending - Cannot Process",
    "P1": "Pending - Waiting for Information",
    "P2": "Pending - Waiting for DTP",
    "P3": "Pending - Requested Information",
    "P4": "Pending - Validation",
    "D0": "Data Reporting Acknowledgment (2200B/2200C level only)",
    "E":  "Error codes (2200B/2200C level only)",
}

# DTP-01 qualifier descriptions (verified via Glass 005010X222A1, 005010X220A1)
DTP_QUALIFIER_LABELS = {
    "472": "Service Date (837 Loop 2400)",
    "435": "Admission Date/Hour (837 Loop 2300)",
    "096": "Discharge Date (837 Loop 2300)",
    "348": "Benefit Begin — Coverage Effective (834)",
    "349": "Benefit End — Coverage Termination (834)",
    "303": "Maintenance Effective Date (834)",
    "300": "Enrollment Signature Date (834)",
    "343": "Premium Paid to Date End (834)",
    "291": "Plan/Coverage Eligibility Date (270/271)",
    "304": "Latest Visit or Consultation (837)",
    "454": "Initial Treatment Date (837)",
    "439": "Accident Date (837)",
    "484": "Last Menstrual Period Date (837)",
    "455": "Last X-Ray Date (837)",
    "102": "Issue Date",
}


def describe_qualifier(segment_id, qualifier_value):
    """
    Return a human-readable label for a known qualifier value.
    Used by report generators for display only.
    Python 3.6 compatible.
    """
    labels = {
        "NM1": {
            "85": "Billing Provider", "87": "Pay-To Provider",
            "IL": "Subscriber/Member", "PR": "Payer", "QC": "Patient",
            "77": "Service Location", "DN": "Referring Provider",
            "82": "Rendering Provider", "DK": "Ordering Provider",
            "P3": "Primary Care Provider", "FA": "Facility",
            "GB": "Other Insured", "GW": "Admitting Physician",
            "PE": "Payee", "TT": "Crossover Carrier",
        },
        "HL": {
            "20": "Information Source", "22": "Subscriber",
            "23": "Dependent", "PT": "Patient",
        },
        "SBR": {"P": "Primary Payer", "S": "Secondary Payer", "T": "Tertiary Payer"},
        "PRV": {
            "BI": "Billing Provider", "PE": "Performing Provider",
            "RF": "Referring Provider", "AT": "Attending Provider",
            "OS": "Operating Physician",
        },
        "CAS": {
            "CO": "Contractual Obligation", "CR": "Correction/Reversal",
            "OA": "Other Adjustment", "PI": "Payer Initiated",
            "PR": "Patient Responsibility",
        },
    }
    return labels.get(segment_id, {}).get(qualifier_value, qualifier_value)


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
        'segments':         list,  # 5-tuples including ST/SE, excl. ISA/IEA/GS/GE
        'transaction_code': str,   # ST-01
        'st_control':       str,   # ST-02
      }
    st_seq is GLOBAL — a file with two ISAs each containing one ST
    produces st_seq values of 1 and 2 (not 1 and 1).
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
    FF has no ISA/ST envelope — isa_seq=1 and st_seq=1 are fixed constants.

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
                current_error.element_position   = seg.element(1, "")
                current_error.element_ref        = seg.element(2, "")
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
# SECTION 6 — SMART DIFF ENGINE  (4-phase BC-style alignment pipeline)
# ============================================================================
#
# Alignment pipeline (Option-B approach):
#   Phase 0: EDI key anchors  — greedy forward match on 2-token EDI keys
#   Phase 1: Patience anchors — unique normalized lines, LIS-sorted backbone
#   Phase 2: Closeness match  — windowed similarity + EDI key bonus
#   Phase 3: LCS fallback     — difflib.SequenceMatcher on remaining gaps
#
# Two diff modes:
#   'realign'       — Full 4-phase pipeline; comparison continues after resync.
#   'stop_on_first' — Flag first structural defect; mark rest as UNCHECKED.
#
# Config knobs:
#   skew_tolerance       : closeness window width (default 50)
#   similarity_threshold : minimum difflib ratio (default 0.74)
# ============================================================================

_DEFAULT_SKEW_TOLERANCE       = 50
_DEFAULT_SIMILARITY_THRESHOLD = 0.74


# ── Normalization ─────────────────────────────────────────────────────────────

def _collapse_spaces(s):
    return re.sub(r" {2,}", " ", s.rstrip("\n").strip())


def _normalize_seg(seg_tuple):
    raw = seg_tuple[3] if len(seg_tuple) > 3 else ""
    if raw:
        return _collapse_spaces(raw)
    return _collapse_spaces(" ".join(str(e) for e in seg_tuple[1]))


# ── EDI key extraction ────────────────────────────────────────────────────────

def _edi_key(seg_tuple):
    """
    Build a domain key for a segment tuple (2-token policy).
    Numeric-leading: key = 'tok0 tok1'.
    NM1/HL/CLM/CLP/SVC/LX: key = seg_id + first qualifier element.
    Others: key = seg_id.
    """
    seg_id = seg_tuple[0]
    raw    = seg_tuple[3] if len(seg_tuple) > 3 else ""
    text   = _collapse_spaces(raw) if raw else seg_id
    toks   = text.split(" ")

    if toks and toks[0].isdigit():
        if len(toks) >= 2:
            return toks[0] + " " + toks[1]
        return toks[0]

    elems = seg_tuple[1] if len(seg_tuple) > 1 else []
    if seg_id in ("NM1", "HL", "CLM", "CLP", "SVC", "LX") and len(elems) > 1:
        return seg_id + " " + str(elems[1])
    return seg_id


# ── Phase 0: EDI key anchors ──────────────────────────────────────────────────

def _edi_key_anchors(s1_segs, s2_segs):
    s2_by_key = defaultdict(deque)
    for j, seg in enumerate(s2_segs):
        s2_by_key[_edi_key(seg)].append(j)

    anchors = []
    cursor  = 0
    for i, seg in enumerate(s1_segs):
        k  = _edi_key(seg)
        dq = s2_by_key.get(k)
        if not dq:
            continue
        while dq and dq[0] < cursor:
            dq.popleft()
        if dq:
            j = dq.popleft()
            anchors.append((i, j))
            cursor = j + 1
    return anchors


# ── Phase 1: Patience unique-line anchors ─────────────────────────────────────

def _patience_anchors(s1_segs, s2_segs):
    na = [_normalize_seg(s) for s in s1_segs]
    nb = [_normalize_seg(s) for s in s2_segs]

    pos_a = defaultdict(list)
    pos_b = defaultdict(list)
    for i, v in enumerate(na):
        pos_a[v].append(i)
    for j, v in enumerate(nb):
        pos_b[v].append(j)

    seq      = []
    val_in_a = []
    for i, v in enumerate(na):
        if len(pos_a[v]) == 1 and len(pos_b.get(v, [])) == 1:
            seq.append(pos_b[v][0])
            val_in_a.append((i, v))

    if not seq:
        return []

    piles = []
    back  = [-1] * len(seq)
    where = [-1] * len(seq)

    for idx, jpos in enumerate(seq):
        p = bisect.bisect_left(piles, jpos)
        if p == len(piles):
            piles.append(jpos)
        else:
            piles[p] = jpos
        where[p] = idx
        back[idx] = where[p - 1] if p > 0 else -1

    anchors = []
    if piles:
        top_idx = where[len(piles) - 1]
        k = top_idx
        while k != -1:
            i_in_a, v = val_in_a[k]
            j_in_b    = pos_b[v][0]
            anchors.append((i_in_a, j_in_b))
            k = back[k]
        anchors.reverse()
    return anchors


# ── Merge anchor sets into monotonic backbone ─────────────────────────────────

def _merge_anchors(edi_anchors, patience_anchors):
    combined = sorted(set(edi_anchors + patience_anchors))
    if not combined:
        return []

    rights = [r for _, r in combined]
    piles  = []
    back   = []
    where  = []

    for idx, r in enumerate(rights):
        p = bisect.bisect_left(piles, r)
        if p == len(piles):
            piles.append(r)
        else:
            piles[p] = r
        where.append((p, idx))
        back.append(where[p - 1][1] if p > 0 else -1)

    chosen = []
    if piles:
        k = where[len(piles) - 1][1]
        while k != -1:
            chosen.append(k)
            k = back[k]
        chosen.reverse()

    return [combined[i] for i in chosen]


# ── Phase 2: Closeness matching ───────────────────────────────────────────────

def _closeness_match(s1_segs, s2_segs, i0, i1, j0, j1,
                     skew_tolerance, similarity_threshold):
    used  = set()
    pairs = []

    edi_keys_l = [_edi_key(s) for s in s1_segs]
    edi_keys_r = [_edi_key(s) for s in s2_segs]

    for i in range(i0, i1):
        norm_i = _normalize_seg(s1_segs[i])
        k_i    = edi_keys_l[i]

        best       = None
        best_score = similarity_threshold
        win_start  = max(j0, j0 + (i - i0) - skew_tolerance)
        win_end    = min(j1, j0 + (i - i0) + skew_tolerance + 1)

        for j in range(win_start, win_end):
            if j in used:
                continue
            norm_j = _normalize_seg(s2_segs[j])
            score  = difflib.SequenceMatcher(
                None, norm_i, norm_j, autojunk=False).ratio()
            if k_i and edi_keys_r[j] == k_i:
                score += 0.20
            if score > best_score:
                best       = j
                best_score = score

        if best is not None:
            pairs.append((i, best))
            used.add(best)
        else:
            pairs.append((i, None))

    for j in range(j0, j1):
        if j not in used:
            pairs.append((None, j))

    pairs.sort(key=lambda p: (
        min(p[0] if p[0] is not None else 10**9,
            p[1] if p[1] is not None else 10**9),
        p[0] if p[0] is not None else 10**9,
        p[1] if p[1] is not None else 10**9,
    ))
    return pairs


# ── Phase 3: LCS fallback ─────────────────────────────────────────────────────

def _lcs_block(s1_segs, s2_segs, i0, i1, j0, j1):
    na = [_normalize_seg(s) for s in s1_segs[i0:i1]]
    nb = [_normalize_seg(s) for s in s2_segs[j0:j1]]
    sm = difflib.SequenceMatcher(None, na, nb, autojunk=False)

    pairs = []
    for tag, a1, a2, b1, b2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(a2 - a1):
                pairs.append((i0 + a1 + k, j0 + b1 + k))
        elif tag == "delete":
            for ii in range(i0 + a1, i0 + a2):
                pairs.append((ii, None))
        elif tag == "insert":
            for jj in range(j0 + b1, j0 + b2):
                pairs.append((None, jj))
        else:  # replace
            n = min(a2 - a1, b2 - b1)
            for k in range(n):
                pairs.append((i0 + a1 + k, j0 + b1 + k))
            for ii in range(i0 + a1 + n, i0 + a2):
                pairs.append((ii, None))
            for jj in range(j0 + b1 + n, j0 + b2):
                pairs.append((None, jj))
    return pairs


# ── Full 4-phase alignment pipeline ──────────────────────────────────────────

def _align_bc_style(s1_segs, s2_segs,
                    skew_tolerance=_DEFAULT_SKEW_TOLERANCE,
                    similarity_threshold=_DEFAULT_SIMILARITY_THRESHOLD):
    """
    Full Option-B pipeline returning list of (i, j) 0-based index pairs.
    None on either side = unmatched (missing/extra).
    """
    edi_anch = _edi_key_anchors(s1_segs, s2_segs)
    pat_anch = _patience_anchors(s1_segs, s2_segs)
    anchors  = _merge_anchors(edi_anch, pat_anch)

    pairs  = []
    prev_i = 0
    prev_j = 0

    for (ai, aj) in anchors:
        li0, li1 = prev_i, ai
        rj0, rj1 = prev_j, aj
        if li0 < li1 or rj0 < rj1:
            gap = _closeness_match(s1_segs, s2_segs, li0, li1, rj0, rj1,
                                   skew_tolerance, similarity_threshold)
            unmatched_l = [p[0] for p in gap if p[0] is not None and p[1] is None]
            unmatched_r = [p[1] for p in gap if p[1] is not None and p[0] is None]
            if unmatched_l and unmatched_r:
                lcs = _lcs_block(s1_segs, s2_segs,
                                 min(unmatched_l), max(unmatched_l) + 1,
                                 min(unmatched_r), max(unmatched_r) + 1)
                clean = [p for p in gap
                         if not (p[0] in unmatched_l or p[1] in unmatched_r)]
                gap = clean + lcs
            pairs.extend(gap)

        pairs.append((ai, aj))
        prev_i = ai + 1
        prev_j = aj + 1

    li0, li1 = prev_i, len(s1_segs)
    rj0, rj1 = prev_j, len(s2_segs)
    if li0 < li1 or rj0 < rj1:
        gap = _closeness_match(s1_segs, s2_segs, li0, li1, rj0, rj1,
                               skew_tolerance, similarity_threshold)
        unmatched_l = [p[0] for p in gap if p[0] is not None and p[1] is None]
        unmatched_r = [p[1] for p in gap if p[1] is not None and p[0] is None]
        if unmatched_l and unmatched_r:
            lcs = _lcs_block(s1_segs, s2_segs,
                             min(unmatched_l), max(unmatched_l) + 1,
                             min(unmatched_r), max(unmatched_r) + 1)
            clean = [p for p in gap
                     if not (p[0] in unmatched_l or p[1] in unmatched_r)]
            gap = clean + lcs
        pairs.extend(gap)

    pairs.sort(key=lambda p: (
        p[0] if p[0] is not None else 10**9,
        p[1] if p[1] is not None else 10**9,
    ))
    return pairs


# ── Preserved helpers ─────────────────────────────────────────────────────────

def _find_matching_anchor(segments, target_id, target_key_elements,
                          start_idx, anchor_set,
                          max_lookahead=_DEFAULT_SKEW_TOLERANCE):
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


# ── Public entry point ────────────────────────────────────────────────────────

def compare_segment_lists(
        s1_segments,
        s2_segments,
        file_base,
        file_type,
        ignore_fields,
        diff_mode="realign",
        anchor_set=None,
        isa_seq=None,
        st_seq=None,
        skip_segments=None,
        skew_tolerance=_DEFAULT_SKEW_TOLERANCE,
        similarity_threshold=_DEFAULT_SIMILARITY_THRESHOLD):
    """
    Compare two ordered lists of parsed segments / records.

    Args:
        s1_segments (list):  5-tuples (seg_id, elements, pos, raw, line_num)
        s2_segments (list):  Same format from System 2.
        file_base (str):     Base filename prefix for defect IDs.
        file_type (str):     "x12", "ff", or "999".
        ignore_fields (dict):file_type -> list of "SEG.elem" strings to skip.
        diff_mode (str):     "realign" (default) or "stop_on_first".
        anchor_set (set):    Segment IDs used as realignment sync points.
        isa_seq (int|None):  Ordinal ISA envelope, stamped on every Defect.
        st_seq (int|None):   Ordinal ST in file, stamped on every Defect.
        skip_segments (set): Segment IDs to suppress entirely (no defect emitted).
        skew_tolerance (int):Closeness window width (default 50).
        similarity_threshold (float): Min difflib ratio (default 0.74).

    Returns:
        List of Defect objects.
    """
    if anchor_set is None:
        anchor_set = {
            "ISA", "GS", "ST", "HL", "CLM", "CLP", "NM1", "SBR",
            "SE", "GE", "IEA", "LX", "SV1", "SV2", "SV3",
            "HDR", "PRV", "MBR", "PYR", "SVC", "TRL",
        }
    if skip_segments is None:
        skip_segments = set()

    if diff_mode == "realign" and len(s1_segments) > 0 and len(s2_segments) > 0:
        return _compare_with_alignment(
            s1_segments, s2_segments, file_base, file_type,
            ignore_fields, anchor_set, skip_segments,
            isa_seq, st_seq, skew_tolerance, similarity_threshold)
    else:
        return _compare_sequential(
            s1_segments, s2_segments, file_base, file_type,
            ignore_fields, diff_mode, anchor_set, skip_segments,
            isa_seq, st_seq)


# ── Realign path: 4-phase alignment → defect walk ────────────────────────────

def _compare_with_alignment(s1_segs, s2_segs, file_base, file_type,
                             ignore_fields, anchor_set, skip_segments,
                             isa_seq, st_seq, skew_tolerance,
                             similarity_threshold):
    pairs      = _align_bc_style(s1_segs, s2_segs,
                                 skew_tolerance, similarity_threshold)
    defects    = []
    defect_seq = 0

    for (i, j) in pairs:
        if i is not None and j is not None:
            seg1      = s1_segs[i]
            seg2      = s2_segs[j]
            seg_id1   = seg1[0]
            seg_id2   = seg2[0]
            elements1 = seg1[1]
            elements2 = seg2[1]
            line1     = seg1[4] if len(seg1) > 4 else i + 1
            line2     = seg2[4] if len(seg2) > 4 else j + 1
            ctx1      = seg1[3] if len(seg1) > 3 else ""
            ctx2      = seg2[3] if len(seg2) > 3 else ""

            if seg_id1 in skip_segments or seg_id2 in skip_segments:
                continue

            if seg_id1 != seg_id2:
                defect_seq += 1
                did  = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
                qual = get_qualifier(seg_id1, elements1)
                defects.append(_make_defect(
                    did, DefectType.ALIGNMENT_FAILURE, Severity.CRITICAL,
                    file_type, seg_id1, None,
                    "Alignment failure: S1={} vs S2={}".format(seg_id1, seg_id2),
                    ctx1 or seg_id1, ctx2 or seg_id2, line1, line2,
                    notes="4-phase aligner could not reconcile segment types.",
                    isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qual))
                continue

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
                elif seg_id1 == "HL" and elem_idx in (2, 3, 4):
                    dtype = DefectType.LOOP_STRUCTURE_MISMATCH
                else:
                    dtype = DefectType.VALUE_MISMATCH
                sev = classify_severity(dtype, seg_id1, elem_idx, qual)
                defects.append(_make_defect(
                    did, dtype, sev, file_type, seg_id1, elem_idx,
                    "{}.{:02d}".format(seg_id1, elem_idx),
                    v1, v2, line1, line2, ctx1, ctx2,
                    isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qual))

        elif i is not None:
            seg    = s1_segs[i]
            seg_id = seg[0]
            if seg_id in skip_segments:
                continue
            qual   = get_qualifier(seg_id, seg[1])
            seg_ln = seg[4] if len(seg) > 4 else i + 1
            defect_seq += 1
            did = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
            defects.append(_make_defect(
                did, DefectType.MISSING_SEGMENT,
                classify_severity(DefectType.MISSING_SEGMENT, seg_id, None, qual),
                file_type, seg_id, None,
                "Missing segment in System 2: {}".format(seg_id),
                seg[3] if len(seg) > 3 else str(seg[1]), "(not present)",
                seg_ln, None,
                notes="Detected by 4-phase alignment",
                isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qual))

        else:
            seg    = s2_segs[j]
            seg_id = seg[0]
            if seg_id in skip_segments:
                continue
            qual   = get_qualifier(seg_id, seg[1])
            seg_ln = seg[4] if len(seg) > 4 else j + 1
            defect_seq += 1
            did = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
            defects.append(_make_defect(
                did, DefectType.EXTRA_SEGMENT,
                classify_severity(DefectType.EXTRA_SEGMENT, seg_id, None, qual),
                file_type, seg_id, None,
                "Extra segment in System 2: {}".format(seg_id),
                "(not present)", seg[3] if len(seg) > 3 else str(seg[1]),
                None, seg_ln,
                notes="Detected by 4-phase alignment",
                isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qual))

    return defects


# ── Sequential path (stop_on_first mode) ─────────────────────────────────────

def _compare_sequential(s1_segments, s2_segments, file_base, file_type,
                        ignore_fields, diff_mode, anchor_set, skip_segments,
                        isa_seq, st_seq):
    """
    Original sequential compare logic.
    Used when diff_mode='stop_on_first' or one list is empty.
    """
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

        if seg_id1 in skip_segments and seg_id2 in skip_segments:
            i1 += 1; i2 += 1; continue
        if seg_id1 in skip_segments:
            i1 += 1; continue
        if seg_id2 in skip_segments:
            i2 += 1; continue

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
            i1 += 1; i2 += 1

        else:
            # Structural mismatch — stop_on_first
            defect_seq += 1
            did  = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
            qual = get_qualifier(seg_id1, elements1)
            defects.append(_make_defect(
                did, DefectType.SEGMENT_ORDER_VIOLATION, Severity.HIGH,
                file_type, seg_id1, None,
                "Segment order violation: S1={} vs S2={}".format(seg_id1, seg_id2),
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
                    "{} segments unchecked due to upstream defect".format(remaining),
                    "", "", line1, line2,
                    notes="Upstream defect at S1 line {}, S2 line {}".format(
                        line1, line2),
                    isa_seq=isa_seq, st_seq=st_seq))
            break

    while i1 < len(s1_segments):
        seg    = s1_segments[i1]
        seg_id = seg[0]
        if seg_id not in skip_segments:
            qual   = get_qualifier(seg_id, seg[1])
            seg_ln = seg[4] if len(seg) > 4 else i1 + 1
            defect_seq += 1
            did = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
            defects.append(_make_defect(
                did, DefectType.MISSING_SEGMENT,
                classify_severity(DefectType.MISSING_SEGMENT, seg_id, None, qual),
                file_type, seg_id, None,
                "Trailing segment in System 1 only: {}".format(seg_id),
                seg[3] if len(seg) > 3 else str(seg[1]), "(not present)",
                seg_ln, None,
                isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qual))
        i1 += 1

    while i2 < len(s2_segments):
        seg    = s2_segments[i2]
        seg_id = seg[0]
        if seg_id not in skip_segments:
            qual   = get_qualifier(seg_id, seg[1])
            seg_ln = seg[4] if len(seg) > 4 else i2 + 1
            defect_seq += 1
            did = "{}_{}_{:04d}".format(file_base, file_type, defect_seq)
            defects.append(_make_defect(
                did, DefectType.EXTRA_SEGMENT,
                classify_severity(DefectType.EXTRA_SEGMENT, seg_id, None, qual),
                file_type, seg_id, None,
                "Trailing segment in System 2 only: {}".format(seg_id),
                "(not present)", seg[3] if len(seg) > 3 else str(seg[1]),
                None, seg_ln,
                isa_seq=isa_seq, st_seq=st_seq, qualifier_value=qual))
        i2 += 1

    return defects


# ============================================================================
# SECTION 7 — RESULT CONTAINERS
# ============================================================================

class TimestampInfo(object):
    def __init__(self, system1_mtime=None, system2_mtime=None,
                 delta_seconds=None, within_tolerance=True,
                 system1_exists=True, system2_exists=True):
        self.system1_mtime    = system1_mtime
        self.system2_mtime    = system2_mtime
        self.delta_seconds    = delta_seconds
        self.within_tolerance = within_tolerance
        self.system1_exists   = system1_exists
        self.system2_exists   = system2_exists

    def to_dict(self):
        return {
            "system1_mtime":    self.system1_mtime,
            "system2_mtime":    self.system2_mtime,
            "delta_seconds":    self.delta_seconds,
            "within_tolerance": self.within_tolerance,
            "system1_exists":   self.system1_exists,
            "system2_exists":   self.system2_exists,
        }


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
            "file_type":        self.file_type,
            "status":           self.status,
            "system1_path":     self.system1_path,
            "system2_path":     self.system2_path,
            "defect_count":     self.defect_count,
            "defects":          self.defects,
            "timestamp_info":   self.timestamp_info,
            "segment_count_s1": self.segment_count_s1,
            "segment_count_s2": self.segment_count_s2,
            "diff_mode_used":   self.diff_mode_used,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(**{k: d.get(k) for k in [
            "file_type", "status", "system1_path", "system2_path",
            "defect_count", "defects", "timestamp_info",
            "segment_count_s1", "segment_count_s2", "diff_mode_used",
        ]})


class FileTripletResult(object):
    def __init__(self, base_name, transaction_type, complexity,
                 x12_result=None, ff_result=None, x999_result=None,
                 total_defects=0, has_critical=False,
                 mode="inbound", pair_name="Default Pair"):
        self.base_name        = base_name
        self.transaction_type = transaction_type
        self.complexity       = complexity
        self.x12_result       = x12_result
        self.ff_result        = ff_result
        self.x999_result      = x999_result
        self.total_defects    = total_defects
        self.has_critical     = has_critical
        self.mode             = mode
        self.pair_name        = pair_name

    def to_dict(self):
        return {
            "base_name":        self.base_name,
            "transaction_type": self.transaction_type,
            "complexity":       self.complexity,
            "x12_result":       self.x12_result,
            "ff_result":        self.ff_result,
            "x999_result":      self.x999_result,
            "total_defects":    self.total_defects,
            "has_critical":     self.has_critical,
            "mode":             self.mode,
            "pair_name":        self.pair_name,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(**{k: d.get(k) for k in [
            "base_name", "transaction_type", "complexity",
            "x12_result", "ff_result", "x999_result",
            "total_defects", "has_critical", "mode", "pair_name",
        ]})

    def all_results(self):
        return [r for r in [self.x12_result, self.ff_result, self.x999_result]
                if r]


# ============================================================================
# SECTION 8 — PUBLIC API SURFACE
# ============================================================================

__all__ = [
    # Version
    "__version__", "__release_date__",
    # Parsers
    "parse_x12", "segments_by_transaction", "segments_to_flat_list",
    "detect_delimiters",
    "parse_ff",  "records_by_transaction",  "records_to_flat_list",
    "parse_999",
    # Core diff engine
    "compare_segment_lists",
    # Segment intelligence
    "get_qualifier", "classify_severity", "describe_qualifier",
    # Data models
    "Defect", "DefectType", "Severity", "FileType", "CompareStatus",
    "TimestampInfo", "FileCompareResult", "FileTripletResult",
    "X12Segment", "X12ParseResult",
    "FFRecord", "FFParseResult",
    "AckResult", "TransactionAck", "ErrorDetail",
    # FF layout metadata
    "FF_FIELD_LAYOUTS", "FF_KEY_FIELDS",
    # Reference tables (new in v1.4.2)
    "ISA_VERSIONS", "GS_FUNC_IDS",
    "IK3_SYNTAX_ERRORS", "IK4_ELEMENT_ERRORS",
    "STC_CATEGORY_CODES", "DTP_QUALIFIER_LABELS",
]
