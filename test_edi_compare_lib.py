"""
Unit tests for edi_compare_lib.py
Run: python3 test_edi_compare_lib.py
"""

import sys
import unittest

from edi_compare_lib import (
    parse_x12, segments_by_transaction, segments_to_flat_list,
    parse_ff, records_by_transaction, records_to_flat_list,
    parse_999,
    compare_segment_lists,
    get_qualifier, classify_severity,
    DefectType, Severity, FileType,
    detect_delimiters,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

ISA = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       "
    "*260101*1200*^*00501*000000001*0*P*:~"
)
GS  = "GS*HC*SENDER*RECEIVER*20260101*1200*1*X*005010X222A1~"
GE  = "GE*1*1~"
IEA = "IEA*1*000000001~"

def make_x12(*tx_bodies):
    """Wrap one or more ST/SE bodies in a full ISA/GS/GE/IEA envelope."""
    segs = [ISA, GS]
    for body in tx_bodies:
        segs.append(body)
    segs += [GE, IEA]
    return "".join(segs)

def seg(seg_id, *elems):
    """Build a 5-tuple segment."""
    elements = [seg_id] + list(elems)
    return (seg_id, elements, 0, seg_id + "*" + "*".join(elems) + "~", 1)


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestDelimiters(unittest.TestCase):
    def test_standard_isa(self):
        e, s, t, r = detect_delimiters(ISA)
        self.assertEqual(e, "*")
        self.assertEqual(t, "~")
        self.assertEqual(s, ":")

    def test_short_content(self):
        e, s, t, r = detect_delimiters("ISA*short")
        self.assertIsNone(e)


class TestX12Parser(unittest.TestCase):
    def test_valid_parse(self):
        content = make_x12("ST*837*0001~CLM*A*150~SE*3*0001~")
        r = parse_x12(content)
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
        content = make_x12("ST*837*0001~CLM*A*150~SE*3*0001~")
        r = parse_x12(content)
        # ISA GS ST CLM SE GE IEA = 7
        self.assertEqual(r.segment_count, 7)


class TestSegmentsByTransaction(unittest.TestCase):
    def test_single_transaction(self):
        content = make_x12("ST*837*0001~CLM*A*150~SE*3*0001~")
        r = parse_x12(content)
        blocks = segments_by_transaction(r)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["transaction_code"], "837")
        self.assertEqual(blocks[0]["isa_seq"], 1)
        self.assertEqual(blocks[0]["st_seq"], 1)

    def test_two_transactions(self):
        content = make_x12(
            "ST*837*0001~CLM*A*100~SE*3*0001~",
            "ST*837*0002~CLM*B*200~SE*3*0002~",
        )
        r = parse_x12(content)
        blocks = segments_by_transaction(r)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0]["st_seq"], 1)
        self.assertEqual(blocks[1]["st_seq"], 2)

    def test_segments_exclude_envelope(self):
        content = make_x12("ST*837*0001~CLM*A*150~SE*3*0001~")
        r = parse_x12(content)
        blocks = segments_by_transaction(r)
        seg_ids = [s[0] for s in blocks[0]["segments"]]
        self.assertNotIn("ISA", seg_ids)
        self.assertNotIn("GS", seg_ids)
        self.assertIn("ST", seg_ids)
        self.assertIn("CLM", seg_ids)


class TestFFParser(unittest.TestCase):
    FW = "HDR INTP000000000001   SENDER001      RECEIVER001    202601011200  ACCEPTED    "
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

    def test_records_by_transaction(self):
        r = parse_ff(self.FW)
        txns = records_by_transaction(r)
        self.assertEqual(len(txns), 1)
        self.assertEqual(txns[0]["isa_seq"], 1)
        self.assertEqual(txns[0]["st_seq"], 1)
        self.assertEqual(txns[0]["transaction_code"], "FF")


class Test999Parser(unittest.TestCase):
    ACK = (
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

    def test_accepted(self):
        a = parse_999(self.ACK)
        self.assertTrue(a.is_valid)
        self.assertTrue(a.is_accepted)
        self.assertFalse(a.is_rejected)
        self.assertEqual(a.group_status, "A")

    def test_tx_acks(self):
        a = parse_999(self.ACK)
        self.assertEqual(len(a.transaction_acks), 1)
        self.assertEqual(a.transaction_acks[0].status, "A")
        self.assertEqual(a.transaction_acks[0].transaction_code, "837")


class TestSmartDiff(unittest.TestCase):
    def test_value_mismatch(self):
        s1 = [seg("CLM", "A", "150")]
        s2 = [seg("CLM", "A", "200")]
        defects = compare_segment_lists(s1, s2, "t", "x12", {}, isa_seq=1, st_seq=1)
        self.assertEqual(len(defects), 1)
        self.assertEqual(defects[0].defect_type, DefectType.VALUE_MISMATCH)
        self.assertEqual(defects[0].system1_value, "150")
        self.assertEqual(defects[0].system2_value, "200")

    def test_match(self):
        s1 = [seg("CLM", "A", "150")]
        s2 = [seg("CLM", "A", "150")]
        defects = compare_segment_lists(s1, s2, "t", "x12", {})
        self.assertEqual(defects, [])

    def test_missing_trailing(self):
        s1 = [seg("CLM", "A"), seg("SV1", "HC:99213")]
        s2 = [seg("CLM", "A")]
        defects = compare_segment_lists(s1, s2, "t", "x12", {})
        self.assertTrue(any(d.defect_type == DefectType.MISSING_SEGMENT for d in defects))

    def test_extra_trailing(self):
        s1 = [seg("CLM", "A")]
        s2 = [seg("CLM", "A"), seg("SV1", "HC:99213")]
        defects = compare_segment_lists(s1, s2, "t", "x12", {})
        self.assertTrue(any(d.defect_type == DefectType.EXTRA_SEGMENT for d in defects))

    def test_realign_extra_in_s2(self):
        s1 = [seg("CLM", "A"), seg("SE", "2", "0001")]
        s2 = [seg("CLM", "A"), seg("NM1", "85", "1"), seg("SE", "3", "0001")]
        defects = compare_segment_lists(s1, s2, "t", "x12", {}, diff_mode="realign")
        self.assertTrue(any(d.defect_type == DefectType.EXTRA_SEGMENT for d in defects))

    def test_stop_on_first(self):
        s1 = [seg("CLM", "A"), seg("NM1", "85", "1"), seg("SE", "3", "0001")]
        s2 = [seg("CLM", "A"), seg("SE", "2", "0001")]
        defects = compare_segment_lists(s1, s2, "t", "x12", {}, diff_mode="stop_on_first")
        self.assertTrue(any(d.defect_type == DefectType.STRUCTURAL_SHIFT for d in defects))

    def test_whitespace_diff(self):
        s1 = [seg("CLM", "A ", "150")]   # trailing space
        s2 = [seg("CLM", "A",  "150")]
        defects = compare_segment_lists(s1, s2, "t", "x12", {})
        self.assertTrue(any(d.defect_type == DefectType.WHITESPACE_DIFF for d in defects))

    def test_ignore_fields(self):
        s1 = [("ISA", ["ISA"] + [""] * 12 + ["OLD_DATE"], 0, "ISA~", 1)]
        s2 = [("ISA", ["ISA"] + [""] * 12 + ["NEW_DATE"], 0, "ISA~", 1)]
        defects = compare_segment_lists(
            s1, s2, "t", "x12", {"x12": ["ISA.13"]}
        )
        self.assertEqual(defects, [])

    def test_isa_st_seq_stamped(self):
        s1 = [seg("CLM", "X", "999")]
        s2 = [seg("CLM", "X", "888")]
        defects = compare_segment_lists(s1, s2, "t", "x12", {}, isa_seq=3, st_seq=7)
        self.assertEqual(defects[0].isa_seq, 3)
        self.assertEqual(defects[0].st_seq, 7)


class TestQualifierAndSeverity(unittest.TestCase):
    def test_nm1_qualifier(self):
        elems = ["NM1", "85", "1", "SMITH", "JOHN", "", "", "XX", "1234567890"]
        self.assertEqual(get_qualifier("NM1", elems), "85")

    def test_hl_qualifier(self):
        elems = ["HL", "1", "", "20", "1"]
        self.assertEqual(get_qualifier("HL", elems), "20")

    def test_unknown_segment(self):
        self.assertEqual(get_qualifier("ZZZ", ["ZZZ", "val"]), "")

    def test_severity_clm(self):
        self.assertEqual(classify_severity(DefectType.VALUE_MISMATCH, "CLM", 3), Severity.HIGH)

    def test_severity_whitespace(self):
        self.assertEqual(classify_severity(DefectType.WHITESPACE_DIFF, "NM1", 2), Severity.LOW)

    def test_severity_structural(self):
        self.assertEqual(classify_severity(DefectType.STRUCTURAL_SHIFT, "ST", None), Severity.CRITICAL)

    def test_severity_nm1_billing(self):
        self.assertEqual(
            classify_severity(DefectType.VALUE_MISMATCH, "NM1", 2, qualifier_value="85"),
            Severity.HIGH
        )


class TestDefectMethods(unittest.TestCase):
    def _make(self):
        s1 = [seg("CLM", "A", "999")]
        s2 = [seg("CLM", "A", "888")]
        defects = compare_segment_lists(s1, s2, "base", "x12", {}, isa_seq=2, st_seq=5)
        return defects[0]

    def test_to_dict(self):
        d = self._make()
        dct = d.to_dict()
        self.assertIn("defect_id", dct)
        self.assertIn("severity", dct)
        self.assertEqual(dct["isa_seq"], 2)

    def test_location_key(self):
        d = self._make()
        key = d.location_key()
        self.assertIn("ISA2", key)
        self.assertIn("ST5", key)
        self.assertIn("CLM", key)

    def test_category_key(self):
        d = self._make()
        key = d.category_key()
        self.assertTrue(key.startswith("CLM:"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
