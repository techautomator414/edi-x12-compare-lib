"""
test_edi_compare_lib.py  —  v1.4.2
===================================
Unit tests for edi_compare_lib.py

Run: python3 test_edi_compare_lib.py [-v]

Coverage:
  - Delimiter detection
  - X12 parser (parse, envelope hierarchy, segments_by_transaction)
  - FF parser (fixed-width, pipe, records_by_transaction)
  - 999 parser (accepted, rejected, IK3/IK4 errors)
  - Segment meta: get_qualifier, describe_qualifier
  - Severity: all DefectType branches, qualifier-aware routing
    (DTP, CLM, INS, STC, HI, SV1/2/3, HL, REF, NM1, SE/GE/IEA)
  - compare_segment_lists:
      realign (4-phase), stop_on_first, skip_segments,
      skew_tolerance / similarity_threshold, isa/st_seq stamping,
      ignore_fields, whitespace_diff, LOOP_STRUCTURE_MISMATCH
  - DefectType taxonomy completeness
  - FileCompareResult / FileTripletResult from_dict round-trip
  - __version__ is "1.4.2"
"""

import sys
import unittest

from edi_compare_lib import (
    __version__,
    parse_x12, segments_by_transaction, segments_to_flat_list,
    detect_delimiters,
    parse_ff, records_by_transaction, records_to_flat_list,
    parse_999,
    compare_segment_lists,
    get_qualifier, classify_severity, describe_qualifier,
    DefectType, Severity, FileType, CompareStatus,
    FileCompareResult, FileTripletResult, TimestampInfo,
    IK3_SYNTAX_ERRORS, IK4_ELEMENT_ERRORS, STC_CATEGORY_CODES,
    DTP_QUALIFIER_LABELS, ISA_VERSIONS, GS_FUNC_IDS,
)

# ─── Shared fixtures ─────────────────────────────────────────────────────────

ISA = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       "
    "*260101*1200*^*00501*000000001*0*P*:~"
)
GS  = "GS*HC*SENDER*RECEIVER*20260101*1200*1*X*005010X222A1~"
GE  = "GE*1*1~"
IEA = "IEA*1*000000001~"


def make_x12(*tx_bodies):
    """Wrap one or more ST/SE bodies in a complete ISA/GS/GE/IEA envelope."""
    segs = [ISA, GS]
    for body in tx_bodies:
        segs.append(body)
    segs += [GE, IEA]
    return "".join(segs)


def seg(seg_id, *elems):
    """Build a 5-tuple segment: (seg_id, elements, pos, raw, line)."""
    elements = [seg_id] + list(elems)
    return (seg_id, elements, 0, seg_id + "*" + "*".join(elems) + "~", 1)


# ─── Version ────────────────────────────────────────────────────────────────

class TestVersion(unittest.TestCase):
    def test_version_is_142(self):
        self.assertEqual(__version__, "1.4.2")


# ─── Delimiter detection ────────────────────────────────────────────────────

class TestDelimiters(unittest.TestCase):
    def test_standard_isa(self):
        e, s, t, r = detect_delimiters(ISA)
        self.assertEqual(e, "*")
        self.assertEqual(t, "~")
        self.assertEqual(s, ":")

    def test_short_content(self):
        e, s, t, r = detect_delimiters("ISA*short")
        self.assertIsNone(e)

    def test_non_isa(self):
        e, s, t, r = detect_delimiters("GS*HC*...")
        self.assertIsNone(e)


# ─── X12 Parser ─────────────────────────────────────────────────────────────

class TestX12Parser(unittest.TestCase):
    def test_valid_parse(self):
        r = parse_x12(make_x12("ST*837*0001~CLM*A*150~SE*3*0001~"))
        self.assertTrue(r.is_valid)
        self.assertEqual(len(r.envelopes), 1)

    def test_empty_content(self):
        r = parse_x12("")
        self.assertFalse(r.is_valid)
        self.assertIn("Empty", r.error)

    def test_malformed_isa(self):
        r = parse_x12("NOT_AN_ISA*data~")
        self.assertFalse(r.is_valid)

    def test_segment_count(self):
        r = parse_x12(make_x12("ST*837*0001~CLM*A*150~SE*3*0001~"))
        # ISA GS ST CLM SE GE IEA = 7
        self.assertEqual(r.segment_count, 7)

    def test_envelope_hierarchy(self):
        r = parse_x12(make_x12("ST*837*0001~CLM*A*150~SE*3*0001~"))
        env = r.envelopes[0]
        self.assertIsNotNone(env.isa_segment)
        self.assertIsNotNone(env.iea_segment)
        self.assertEqual(len(env.groups), 1)
        grp = env.groups[0]
        self.assertIsNotNone(grp.gs_segment)
        self.assertIsNotNone(grp.ge_segment)
        self.assertEqual(len(grp.transactions), 1)


class TestSegmentsByTransaction(unittest.TestCase):
    def test_single_transaction(self):
        r = parse_x12(make_x12("ST*837*0001~CLM*A*150~SE*3*0001~"))
        blocks = segments_by_transaction(r)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["transaction_code"], "837")
        self.assertEqual(blocks[0]["isa_seq"], 1)
        self.assertEqual(blocks[0]["st_seq"], 1)

    def test_two_transactions_global_seq(self):
        r = parse_x12(make_x12(
            "ST*837*0001~CLM*A*100~SE*3*0001~",
            "ST*837*0002~CLM*B*200~SE*3*0002~",
        ))
        blocks = segments_by_transaction(r)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0]["st_seq"], 1)
        self.assertEqual(blocks[1]["st_seq"], 2)

    def test_segments_exclude_envelope(self):
        r = parse_x12(make_x12("ST*837*0001~CLM*A*150~SE*3*0001~"))
        blocks = segments_by_transaction(r)
        seg_ids = [s[0] for s in blocks[0]["segments"]]
        self.assertNotIn("ISA", seg_ids)
        self.assertNotIn("GS",  seg_ids)
        self.assertIn("ST",  seg_ids)
        self.assertIn("CLM", seg_ids)
        self.assertIn("SE",  seg_ids)


# ─── FF Parser ──────────────────────────────────────────────────────────────

class TestFFParser(unittest.TestCase):
    FW   = "HDR INTP000000000001   SENDER001      RECEIVER001    202601011200  ACCEPTED    "
    PIPE = "HDR|INTP|000000000001|SENDER001|RECEIVER001|20260101|1200|ACCEPTED"

    def test_fixed_width(self):
        r = parse_ff(self.FW)
        self.assertTrue(r.is_valid)
        self.assertEqual(r.records[0].record_type, "HDR")

    def test_pipe_delimited(self):
        r = parse_ff(self.PIPE)
        self.assertTrue(r.is_valid)
        self.assertEqual(r.records[0].record_type, "HDR")

    def test_empty(self):
        r = parse_ff("")
        self.assertFalse(r.is_valid)
        self.assertIn("Empty", r.error)

    def test_records_by_transaction(self):
        r = parse_ff(self.FW)
        txns = records_by_transaction(r)
        self.assertEqual(len(txns), 1)
        self.assertEqual(txns[0]["isa_seq"], 1)
        self.assertEqual(txns[0]["st_seq"], 1)
        self.assertEqual(txns[0]["transaction_code"], "FF")

    def test_record_count(self):
        r = parse_ff(self.FW + "\nCLM PCN001         100.00         200.00         REF001         ")
        self.assertEqual(r.record_count, 2)


# ─── 999 Parser ─────────────────────────────────────────────────────────────

_ACK_ACCEPTED = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       "
    "*260101*1200*^*00501*000000001*0*P*:~"
    "GS*FA*SENDER*RECEIVER*20260101*1200*1*X*005010X231A1~"
    "ST*999*0001~"
    "AK1*HC*1*005010X222A1~"
    "AK2*837*0001~"
    "IK5*A~"
    "AK9*A*1*1*1~"
    "SE*5*0001~"
    "GE*1*1~"
    "IEA*1*000000001~"
)

_ACK_REJECTED = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       "
    "*260101*1200*^*00501*000000001*0*P*:~"
    "GS*FA*SENDER*RECEIVER*20260101*1200*1*X*005010X231A1~"
    "ST*999*0001~"
    "AK1*HC*1*005010X222A1~"
    "AK2*837*0001~"
    "IK3*CLM*5**3~"
    "IK4*1**7~"
    "IK5*R*5~"
    "AK9*R*1*1*0~"
    "SE*7*0001~"
    "GE*1*1~"
    "IEA*1*000000001~"
)


class Test999Parser(unittest.TestCase):
    def test_accepted(self):
        a = parse_999(_ACK_ACCEPTED)
        self.assertTrue(a.is_valid)
        self.assertTrue(a.is_accepted)
        self.assertFalse(a.is_rejected)
        self.assertEqual(a.group_status, "A")
        self.assertEqual(a.total_ts_included, "1")

    def test_rejected(self):
        a = parse_999(_ACK_REJECTED)
        self.assertTrue(a.is_valid)
        self.assertTrue(a.is_rejected)
        self.assertFalse(a.is_accepted)
        self.assertEqual(a.group_status, "R")

    def test_tx_ack_count(self):
        a = parse_999(_ACK_ACCEPTED)
        self.assertEqual(len(a.transaction_acks), 1)
        self.assertEqual(a.transaction_acks[0].status, "A")

    def test_ik3_ik4_parsed(self):
        a = parse_999(_ACK_REJECTED)
        ta = a.transaction_acks[0]
        self.assertEqual(len(ta.errors), 1)
        e = ta.errors[0]
        self.assertEqual(e.syntax_error_code, "3")    # Mandatory segment missing
        self.assertEqual(e.element_error_code, "7")   # Invalid code value

    def test_invalid_content(self):
        a = parse_999("not valid x12 content")
        self.assertFalse(a.is_valid)
        self.assertIn("X12 parse failed", a.error)


# ─── Segment meta ────────────────────────────────────────────────────────────

class TestQualifier(unittest.TestCase):
    def test_nm1(self):
        self.assertEqual(get_qualifier("NM1", ["NM1", "85", "1", "SMITH"]), "85")

    def test_hl(self):
        self.assertEqual(get_qualifier("HL", ["HL", "1", "", "20", "1"]), "20")

    def test_dtp(self):
        self.assertEqual(get_qualifier("DTP", ["DTP", "472", "D8", "20260101"]), "472")

    def test_composite_hi(self):
        self.assertEqual(get_qualifier("HI", ["HI", "BK:I10:Z00.00"]), "BK")

    def test_composite_sv1(self):
        self.assertEqual(get_qualifier("SV1", ["SV1", "HC:99213:25"]), "HC")

    def test_unknown_segment(self):
        self.assertEqual(get_qualifier("ZZZ", ["ZZZ", "val"]), "")

    def test_short_elements(self):
        self.assertEqual(get_qualifier("NM1", ["NM1"]), "")


class TestDescribeQualifier(unittest.TestCase):
    def test_nm1_85(self):
        self.assertEqual(describe_qualifier("NM1", "85"), "Billing Provider")

    def test_sbr_p(self):
        self.assertEqual(describe_qualifier("SBR", "P"), "Primary Payer")

    def test_unknown_returns_input(self):
        self.assertEqual(describe_qualifier("NM1", "XX"), "XX")

    def test_unknown_segment(self):
        self.assertEqual(describe_qualifier("ZZZ", "A"), "A")


class TestReferenceTables(unittest.TestCase):
    def test_ik3_has_code_3(self):
        self.assertIn("3", IK3_SYNTAX_ERRORS)
        self.assertEqual(IK3_SYNTAX_ERRORS["3"], "Mandatory segment missing")

    def test_ik4_has_code_7(self):
        self.assertIn("7", IK4_ELEMENT_ERRORS)
        self.assertEqual(IK4_ELEMENT_ERRORS["7"], "Invalid code value")

    def test_stc_finalized_denied(self):
        self.assertIn("F1", STC_CATEGORY_CODES)

    def test_dtp_service_date(self):
        self.assertIn("472", DTP_QUALIFIER_LABELS)

    def test_isa_versions(self):
        self.assertIn("00501", ISA_VERSIONS)

    def test_gs_func_ids(self):
        self.assertIn("HC", GS_FUNC_IDS)


# ─── classify_severity — full coverage ──────────────────────────────────────

class TestClassifySeverity(unittest.TestCase):
    # ISA envelope types
    def test_isa_sender(self):
        self.assertEqual(classify_severity(DefectType.ISA_SENDER_MISMATCH, "ISA", 6), Severity.CRITICAL)
    def test_isa_receiver(self):
        self.assertEqual(classify_severity(DefectType.ISA_RECEIVER_MISMATCH, "ISA", 8), Severity.CRITICAL)
    def test_isa_env(self):
        self.assertEqual(classify_severity(DefectType.ISA_ENV_MISMATCH, "ISA", 15), Severity.CRITICAL)
    def test_isa_version(self):
        self.assertEqual(classify_severity(DefectType.ISA_VERSION_MISMATCH, "ISA", 12), Severity.CRITICAL)
    def test_isa_delimiter(self):
        self.assertEqual(classify_severity(DefectType.ISA_DELIMITER_MISMATCH, "ISA", 11), Severity.HIGH)
    def test_isa_qualifier(self):
        self.assertEqual(classify_severity(DefectType.ISA_QUALIFIER_MISMATCH, "ISA", 5), Severity.HIGH)
    def test_isa_ack_policy(self):
        self.assertEqual(classify_severity(DefectType.ISA_ACK_POLICY_MISMATCH, "ISA", 14), Severity.HIGH)

    # GS functional group types
    def test_gs_version(self):
        self.assertEqual(classify_severity(DefectType.GS_VERSION_MISMATCH, "GS", 8), Severity.CRITICAL)
    def test_gs_funcid(self):
        self.assertEqual(classify_severity(DefectType.GS_FUNCID_MISMATCH, "GS", 1), Severity.HIGH)

    # Structural
    def test_status_flip(self):
        self.assertEqual(classify_severity(DefectType.STATUS_FLIP, "AK9", None), Severity.CRITICAL)
    def test_structural_shift(self):
        self.assertEqual(classify_severity(DefectType.STRUCTURAL_SHIFT, "ST", None), Severity.CRITICAL)
    def test_alignment_failure(self):
        self.assertEqual(classify_severity(DefectType.ALIGNMENT_FAILURE, "CLM", None), Severity.CRITICAL)
    def test_segment_order(self):
        self.assertEqual(classify_severity(DefectType.SEGMENT_ORDER_VIOLATION, "NM1", None), Severity.HIGH)
    def test_trailer_count(self):
        self.assertEqual(classify_severity(DefectType.TRAILER_COUNT_MISMATCH, "GE", 1), Severity.HIGH)
    def test_segment_count_integrity(self):
        self.assertEqual(classify_severity(DefectType.SEGMENT_COUNT_INTEGRITY, "SE", 1), Severity.HIGH)
    def test_loop_structure(self):
        self.assertEqual(classify_severity(DefectType.LOOP_STRUCTURE_MISMATCH, "HL", 3), Severity.HIGH)
    def test_claim_count(self):
        self.assertEqual(classify_severity(DefectType.CLAIM_COUNT_MISMATCH, "CLM", None), Severity.HIGH)

    # SNIP / 999
    def test_snip_validation(self):
        self.assertEqual(classify_severity(DefectType.SNIP_VALIDATION_FAILURE, "IK3", 4), Severity.HIGH)
    def test_tx_count(self):
        self.assertEqual(classify_severity(DefectType.TX_COUNT_MISMATCH, "AK9", 2), Severity.HIGH)

    # Orphan
    def test_orphan_sys1(self):
        self.assertEqual(classify_severity(DefectType.ORPHAN_SYS1, "FILE", None), Severity.HIGH)
    def test_date_subdir(self):
        self.assertEqual(classify_severity(DefectType.DATE_SUBDIR_MISMATCH, "FILE", None), Severity.MEDIUM)

    # Whitespace / delimiter
    def test_whitespace(self):
        self.assertEqual(classify_severity(DefectType.WHITESPACE_DIFF, "NM1", 2), Severity.LOW)
    def test_delimiter(self):
        self.assertEqual(classify_severity(DefectType.DELIMITER_DIFF, "ISA", 3), Severity.LOW)

    # Value mismatch — DTP date-type-aware
    def test_dtp_service_date_critical(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "DTP", 3, qualifier_value="472"),
            Severity.CRITICAL)
    def test_dtp_service_date_non_date_elem(self):
        # elem 1 = qualifier code itself — not the date; should be MEDIUM
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "DTP", 1, qualifier_value="472"),
            Severity.MEDIUM)
    def test_dtp_high_qual(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "DTP", 3, qualifier_value="303"),
            Severity.HIGH)
    def test_dtp_other(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "DTP", 3, qualifier_value="999"),
            Severity.MEDIUM)

    # Value mismatch — CLM position-aware
    def test_clm_high(self):
        self.assertEqual(classify_severity(DefectType.VALUE_MISMATCH, "CLM", 3), Severity.HIGH)
    def test_clm_pos5(self):
        self.assertEqual(classify_severity(DefectType.VALUE_MISMATCH, "CLM", 5), Severity.HIGH)
    def test_clm_pos9(self):
        self.assertEqual(classify_severity(DefectType.VALUE_MISMATCH, "CLM", 9), Severity.CRITICAL)

    # Value mismatch — INS maintenance-type
    def test_ins_termination(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "INS", 3, qualifier_value="030"),
            Severity.CRITICAL)
    def test_ins_change(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "INS", 3, qualifier_value="001"),
            Severity.HIGH)
    def test_ins_other(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "INS", 3, qualifier_value="999"),
            Severity.MEDIUM)

    # Value mismatch — STC status category
    def test_stc_finalized_critical(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "STC", 1, qualifier_value="F1"),
            Severity.CRITICAL)
    def test_stc_pending_high(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "STC", 1, qualifier_value="P0"),
            Severity.HIGH)

    # Value mismatch — procedure codes
    def test_sv1_proc_critical(self):
        self.assertEqual(classify_severity(DefectType.VALUE_MISMATCH, "SV1", 1), Severity.CRITICAL)
    def test_sv1_other_high(self):
        self.assertEqual(classify_severity(DefectType.VALUE_MISMATCH, "SV1", 2), Severity.HIGH)
    def test_hi_high(self):
        self.assertEqual(classify_severity(DefectType.VALUE_MISMATCH, "HI", 1), Severity.HIGH)

    # Value mismatch — NM1 entity aware
    def test_nm1_billing(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "NM1", 2, qualifier_value="85"),
            Severity.HIGH)
    def test_nm1_other(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "NM1", 2, qualifier_value="XX"),
            Severity.MEDIUM)

    # Value mismatch — HL, SE/GE/IEA, REF
    def test_hl_level_high(self):
        self.assertEqual(classify_severity(DefectType.VALUE_MISMATCH, "HL", 3), Severity.HIGH)
    def test_hl_id_medium(self):
        self.assertEqual(classify_severity(DefectType.VALUE_MISMATCH, "HL", 1), Severity.MEDIUM)
    def test_se_count_high(self):
        self.assertEqual(classify_severity(DefectType.VALUE_MISMATCH, "SE", 1), Severity.HIGH)
    def test_ge_other_medium(self):
        self.assertEqual(classify_severity(DefectType.VALUE_MISMATCH, "GE", 2), Severity.MEDIUM)
    def test_ref_prior_auth_high(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "REF", 2, qualifier_value="G1"),
            Severity.HIGH)
    def test_ref_other_high(self):
        # REF is in _ID_SEGMENTS → always HIGH regardless of qualifier
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "REF", 2, qualifier_value="XX"),
            Severity.HIGH)

    # Element count
    def test_elem_count_key_seg(self):
        self.assertEqual(classify_severity(DefectType.ELEMENT_COUNT_DIFF, "CLM", 3), Severity.HIGH)
    def test_elem_count_other(self):
        self.assertEqual(classify_severity(DefectType.ELEMENT_COUNT_DIFF, "PWK", 2), Severity.MEDIUM)


# ─── compare_segment_lists — core diff engine ────────────────────────────────

class TestSmartDiff(unittest.TestCase):

    def test_exact_match(self):
        s = [seg("CLM", "A", "150")]
        self.assertEqual(compare_segment_lists(s, s, "t", "x12", {}), [])

    def test_value_mismatch(self):
        s1 = [seg("CLM", "A", "150")]
        s2 = [seg("CLM", "A", "200")]
        d = compare_segment_lists(s1, s2, "t", "x12", {}, isa_seq=1, st_seq=1)
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0].defect_type, DefectType.VALUE_MISMATCH)
        self.assertEqual(d[0].system1_value, "150")
        self.assertEqual(d[0].system2_value, "200")

    def test_whitespace_diff(self):
        s1 = [seg("CLM", "A ", "150")]
        s2 = [seg("CLM", "A",  "150")]
        d = compare_segment_lists(s1, s2, "t", "x12", {})
        self.assertTrue(any(x.defect_type == DefectType.WHITESPACE_DIFF for x in d))

    def test_element_count_diff(self):
        s1 = [("CLM", ["CLM", "A", "150", "extra"], 0, "CLM~", 1)]
        s2 = [("CLM", ["CLM", "A", "150"],           0, "CLM~", 1)]
        d = compare_segment_lists(s1, s2, "t", "x12", {})
        self.assertTrue(any(x.defect_type == DefectType.ELEMENT_COUNT_DIFF for x in d))

    def test_missing_trailing(self):
        s1 = [seg("CLM", "A"), seg("SV1", "HC:99213")]
        s2 = [seg("CLM", "A")]
        d = compare_segment_lists(s1, s2, "t", "x12", {})
        self.assertTrue(any(x.defect_type == DefectType.MISSING_SEGMENT for x in d))

    def test_extra_trailing(self):
        s1 = [seg("CLM", "A")]
        s2 = [seg("CLM", "A"), seg("SV1", "HC:99213")]
        d = compare_segment_lists(s1, s2, "t", "x12", {})
        self.assertTrue(any(x.defect_type == DefectType.EXTRA_SEGMENT for x in d))

    def test_isa_st_seq_stamped(self):
        s1 = [seg("CLM", "X", "999")]
        s2 = [seg("CLM", "X", "888")]
        d = compare_segment_lists(s1, s2, "t", "x12", {}, isa_seq=3, st_seq=7)
        self.assertEqual(d[0].isa_seq, 3)
        self.assertEqual(d[0].st_seq, 7)

    def test_ignore_fields(self):
        s1 = [("ISA", ["ISA"] + [""] * 12 + ["OLD_DATE"], 0, "ISA~", 1)]
        s2 = [("ISA", ["ISA"] + [""] * 12 + ["NEW_DATE"], 0, "ISA~", 1)]
        d = compare_segment_lists(s1, s2, "t", "x12", {"x12": ["ISA.13"]})
        self.assertEqual(d, [])

    def test_stop_on_first_emits_segment_order_violation(self):
        s1 = [seg("CLM", "A"), seg("NM1", "85"), seg("SE", "3")]
        s2 = [seg("CLM", "A"), seg("SE", "2")]
        d = compare_segment_lists(s1, s2, "t", "x12", {}, diff_mode="stop_on_first")
        types = [x.defect_type for x in d]
        self.assertIn(DefectType.SEGMENT_ORDER_VIOLATION, types)

    def test_stop_on_first_emits_unchecked(self):
        s1 = [seg("CLM", "A"), seg("NM1", "85"), seg("SV1", "HC:99213"), seg("SE", "3")]
        s2 = [seg("CLM", "A"), seg("SE", "2")]
        d = compare_segment_lists(s1, s2, "t", "x12", {}, diff_mode="stop_on_first")
        types = [x.defect_type for x in d]
        self.assertIn(DefectType.UNCHECKED, types)

    def test_realign_extra_in_s2(self):
        s1 = [seg("CLM", "A"), seg("SE", "2", "0001")]
        s2 = [seg("CLM", "A"), seg("NM1", "85", "1"), seg("SE", "3", "0001")]
        d = compare_segment_lists(s1, s2, "t", "x12", {}, diff_mode="realign")
        self.assertTrue(any(x.defect_type == DefectType.EXTRA_SEGMENT for x in d))

    def test_realign_missing_in_s2(self):
        s1 = [seg("CLM", "A"), seg("NM1", "85", "1"), seg("SE", "3", "0001")]
        s2 = [seg("CLM", "A"), seg("SE", "2", "0001")]
        d = compare_segment_lists(s1, s2, "t", "x12", {}, diff_mode="realign")
        self.assertTrue(any(x.defect_type == DefectType.MISSING_SEGMENT for x in d))

    def test_skip_segments(self):
        # ISA segments differ — but ISA is in skip list → zero defects
        s1 = [("ISA", ["ISA", "00", "old_date"], 0, "ISA~", 1)]
        s2 = [("ISA", ["ISA", "00", "new_date"], 0, "ISA~", 1)]
        d = compare_segment_lists(s1, s2, "t", "x12", {}, skip_segments={"ISA"})
        self.assertEqual(d, [])

    def test_skip_segments_missing_not_emitted(self):
        s1 = [seg("CLM", "A"), seg("DTP", "472", "D8", "20260101")]
        s2 = [seg("CLM", "A")]
        # skip DTP — missing DTP should not produce a defect
        d = compare_segment_lists(s1, s2, "t", "x12", {}, skip_segments={"DTP"})
        self.assertFalse(any(x.segment_id == "DTP" for x in d))

    def test_loop_structure_mismatch_hl(self):
        # HL-03 (level code) differs → LOOP_STRUCTURE_MISMATCH
        s1 = [("HL", ["HL", "1", "0", "20", "1"], 0, "HL~", 1)]
        s2 = [("HL", ["HL", "1", "0", "22", "1"], 0, "HL~", 1)]
        d = compare_segment_lists(s1, s2, "t", "x12", {})
        self.assertTrue(any(x.defect_type == DefectType.LOOP_STRUCTURE_MISMATCH for x in d))

    def test_skew_tolerance_param(self):
        # With tolerance=0 no closeness match should occur — large gap
        # Just verifies the parameter is accepted without error
        s1 = [seg("CLM", "A"), seg("SE", "2")]
        s2 = [seg("CLM", "A"), seg("NM1", "85"), seg("SE", "3")]
        d = compare_segment_lists(s1, s2, "t", "x12", {},
                                  skew_tolerance=0, similarity_threshold=0.99)
        self.assertIsInstance(d, list)

    def test_defect_id_format(self):
        s1 = [seg("CLM", "A", "100")]
        s2 = [seg("CLM", "A", "200")]
        d = compare_segment_lists(s1, s2, "base_file", "x12", {})
        self.assertTrue(d[0].defect_id.startswith("base_file_x12_"))


# ─── Defect object methods ───────────────────────────────────────────────────

class TestDefectMethods(unittest.TestCase):
    def _make(self):
        s1 = [seg("CLM", "A", "999")]
        s2 = [seg("CLM", "A", "888")]
        return compare_segment_lists(s1, s2, "base", "x12", {}, isa_seq=2, st_seq=5)[0]

    def test_to_dict_keys(self):
        dct = self._make().to_dict()
        for k in ["defect_id", "defect_type", "severity", "file_type",
                  "segment_id", "element_position", "field_name",
                  "system1_value", "system2_value", "isa_seq", "st_seq"]:
            self.assertIn(k, dct)

    def test_from_dict_round_trip(self):
        from edi_compare_lib import Defect
        d = self._make()
        d2 = Defect.from_dict(d.to_dict())
        self.assertEqual(d.defect_id, d2.defect_id)
        self.assertEqual(d.severity,  d2.severity)

    def test_location_key_includes_isa_st(self):
        k = self._make().location_key()
        self.assertIn("ISA2", k)
        self.assertIn("ST5",  k)
        self.assertIn("CLM",  k)

    def test_category_key_starts_with_seg(self):
        self.assertTrue(self._make().category_key().startswith("CLM:"))

    def test_isa_seq_1_omitted_from_location_key(self):
        s1 = [seg("CLM", "X", "1")]
        s2 = [seg("CLM", "X", "2")]
        d = compare_segment_lists(s1, s2, "t", "x12", {}, isa_seq=1, st_seq=1)[0]
        self.assertNotIn("ISA1", d.location_key())


# ─── Result container round-trips ────────────────────────────────────────────

class TestResultContainers(unittest.TestCase):
    def test_file_compare_result_from_dict(self):
        r = FileCompareResult(
            file_type="x12", status="mismatch",
            system1_path="/a", system2_path="/b",
            defect_count=3, defects=[],
            segment_count_s1=10, segment_count_s2=11)
        r2 = FileCompareResult.from_dict(r.to_dict())
        self.assertEqual(r2.defect_count, 3)
        self.assertEqual(r2.status, "mismatch")

    def test_file_triplet_result_from_dict(self):
        t = FileTripletResult(
            base_name="837P_simple", transaction_type="837P",
            complexity="simple", total_defects=5, has_critical=True,
            mode="outbound", pair_name="TestPair")
        t2 = FileTripletResult.from_dict(t.to_dict())
        self.assertEqual(t2.mode, "outbound")
        self.assertEqual(t2.pair_name, "TestPair")
        self.assertTrue(t2.has_critical)

    def test_triplet_all_results_filters_none(self):
        t = FileTripletResult("x", "837P", "simple", x12_result={"a": 1})
        self.assertEqual(len(t.all_results()), 1)

    def test_timestamp_info_to_dict(self):
        ti = TimestampInfo(system1_mtime="2026-01-01", delta_seconds=5)
        d = ti.to_dict()
        self.assertIn("system1_mtime", d)
        self.assertEqual(d["delta_seconds"], 5)


# ─── DefectType taxonomy completeness ────────────────────────────────────────

class TestDefectTypeTaxonomy(unittest.TestCase):
    """Ensure all 28 DefectType constants exist and are non-empty strings."""
    _EXPECTED = [
        "VALUE_MISMATCH", "EXTRA_SEGMENT", "MISSING_SEGMENT",
        "DELIMITER_DIFF", "WHITESPACE_DIFF", "STRUCTURAL_SHIFT",
        "STATUS_FLIP", "ELEMENT_COUNT_DIFF", "UNCHECKED",
        "ISA_SENDER_MISMATCH", "ISA_RECEIVER_MISMATCH", "ISA_ENV_MISMATCH",
        "ISA_VERSION_MISMATCH", "ISA_DELIMITER_MISMATCH",
        "ISA_ACK_POLICY_MISMATCH", "ISA_QUALIFIER_MISMATCH",
        "GS_VERSION_MISMATCH", "GS_FUNCID_MISMATCH",
        "SEGMENT_ORDER_VIOLATION", "ALIGNMENT_FAILURE",
        "LOOP_STRUCTURE_MISMATCH", "TRAILER_COUNT_MISMATCH",
        "SEGMENT_COUNT_INTEGRITY", "CLAIM_COUNT_MISMATCH",
        "SNIP_VALIDATION_FAILURE", "TX_COUNT_MISMATCH",
        "ORPHAN_SYS1", "ORPHAN_SYS2", "DATE_SUBDIR_MISMATCH",
    ]

    def test_all_types_present(self):
        for name in self._EXPECTED:
            val = getattr(DefectType, name, None)
            self.assertIsNotNone(val, "DefectType.{} missing".format(name))
            self.assertIsInstance(val, str)
            self.assertTrue(val, "DefectType.{} is empty".format(name))


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
