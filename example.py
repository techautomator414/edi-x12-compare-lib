"""
Example usage of edi_compare_lib.py
"""

from edi_compare_lib import (
    parse_x12, segments_by_transaction,
    parse_ff, records_by_transaction,
    parse_999,
    compare_segment_lists,
    get_qualifier, classify_severity,
    DefectType, Severity,
)

# ─── X12 Comparison ───────────────────────────────────────────────────────────

S1_X12 = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       "
    "*260101*1200*^*00501*000000001*0*P*:~"
    "GS*HC*SENDER*RECEIVER*20260101*1200*1*X*005010X222A1~"
    "ST*837*0001~"
    "CLM*CLAIM001*150.00***11:B:1*Y*A*Y*I~"
    "SE*3*0001~"
    "GE*1*1~"
    "IEA*1*000000001~"
)

S2_X12 = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       "
    "*260101*1201*^*00501*000000002*0*P*:~"
    "GS*HC*SENDER*RECEIVER*20260101*1201*2*X*005010X222A1~"
    "ST*837*0001~"
    "CLM*CLAIM001*200.00***11:B:1*Y*A*Y*I~"   # amount differs
    "SE*3*0001~"
    "GE*1*2~"
    "IEA*1*000000002~"
)

IGNORE = {
    "x12": ["ISA.09", "ISA.10", "ISA.13", "GS.04", "GS.05", "GS.06", "GE.02", "IEA.02"]
}

r1 = parse_x12(S1_X12)
r2 = parse_x12(S2_X12)

print("=== X12 Comparison ===")
for b1, b2 in zip(segments_by_transaction(r1), segments_by_transaction(r2)):
    defects = compare_segment_lists(
        s1_segments=b1["segments"],
        s2_segments=b2["segments"],
        file_base="example",
        file_type="x12",
        ignore_fields=IGNORE,
        diff_mode="realign",
        isa_seq=b1["isa_seq"],
        st_seq=b1["st_seq"],
    )
    for d in defects:
        print(f"  [{d.severity.upper()}] {d.field_name}: {d.system1_value!r} -> {d.system2_value!r}")

print()

# ─── Flat File Comparison ─────────────────────────────────────────────────────

S1_FF = "HDR INTP000000000001   SENDER001      RECEIVER001    202601011200  ACCEPTED    "
S2_FF = "HDR INTP000000000001   SENDER001      RECEIVER001    202601011201  REJECTED    "

r1 = parse_ff(S1_FF)
r2 = parse_ff(S2_FF)

b1 = records_by_transaction(r1)[0]
b2 = records_by_transaction(r2)[0]

print("=== FF Comparison ===")
defects = compare_segment_lists(
    s1_segments=b1["segments"],
    s2_segments=b2["segments"],
    file_base="example_ff",
    file_type="ff",
    ignore_fields={"ff": ["HDR.5"]},  # skip translation time
)
for d in defects:
    print(f"  [{d.severity.upper()}] {d.field_name}: {d.system1_value!r} -> {d.system2_value!r}")

print()

# ─── 999 Parse ────────────────────────────────────────────────────────────────

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

ack = parse_999(ACK)
print("=== 999 Parse ===")
print(f"  Group status : {ack.group_status}")
print(f"  Accepted     : {ack.is_accepted}")
print(f"  TS acks      : {len(ack.transaction_acks)}")
for ta in ack.transaction_acks:
    print(f"    TX {ta.transaction_code} / ctrl {ta.control_number} -> {ta.status}")
