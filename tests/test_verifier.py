"""Unit tests for the JVM type-state verifier."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.verifier import verify_class  # noqa: E402
from builder import (ACC_PUBLIC, ACC_STATIC, Asm, ClassBuilder,  # noqa: E402
                     bad_return_address_class,
                     legacy_jsr_cleanup_class, legacy_jsr_wide_class,
                     legacy_nested_cleanup_class, legal_construction_class,
                     uninitialized_escape_class)

DIAG = "com/acme/Diag"


def diag_builder():
    b = ClassBuilder()
    x = b.cp.cls(DIAG)
    init = b.cp.methodref(DIAG, "<init>", "()V")
    return b, x, init


def state_at(res, off):
    for s in res["states"]:
        if s["offset"] == off:
            return s
    raise AssertionError(f"no state at offset {off} in {res['states']}")


class LegalPathTests(unittest.TestCase):
    def test_legal_construction_passes(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0xB7).u2(init)     # 4 invokespecial <init>
        a.op(0x4B)              # 7 astore_0
        a.op(0x2A)              # 8 aload_0
        a.op(0x57)              # 9 pop
        a.op(0xB1)              # 10 return
        b.add_method("run", a.build(), max_stack=2, max_locals=1)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["method"], "run")
        self.assertEqual(state_at(res, 0)["insn"], f"new {DIAG}")
        self.assertEqual(state_at(res, 4)["stack"],
                         [f"uninit(new@0 {DIAG})", f"uninit(new@0 {DIAG})"])
        self.assertEqual(state_at(res, 8)["locals"], [f"ref {DIAG}"])

    def test_construction_inside_try_passes_and_handler_state(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0xB7).u2(init)     # 4 invokespecial <init>
        a.op(0x4B)              # 7 astore_0
        a.op(0xB1)              # 8 return
        a.label("h")            # 9
        a.op(0x57)              # 9 pop
        a.op(0xB1)              # 10 return
        b.add_method("run", a.build(), max_stack=2, max_locals=1,
                     exceptions=[(0, 9, 9, 0)])
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(len(res["handlers"]), 1)
        h = res["handlers"][0]
        self.assertEqual((h["start_pc"], h["end_pc"], h["handler_pc"]), (0, 9, 9))
        self.assertEqual(h["catch"], "java/lang/Throwable")
        self.assertEqual(h["stack"], ["ref java/lang/Throwable"])
        self.assertEqual(h["locals"], ["top"])
        self.assertTrue(h["reachable"])

    def test_typed_catch_reported(self):
        b, x, init = diag_builder()
        exc = b.cp.cls("java/lang/Exception")
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.op(0x57)              # 1 pop
        a.op(0xB1)              # 2 return
        a.label("h")            # 3
        a.op(0x57)              # 3 pop
        a.op(0xB1)              # 4 return
        b.add_method("run", a.build(), max_stack=1, max_locals=0,
                     exceptions=[(0, 3, 3, "java/lang/Exception")])
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["handlers"][0]["catch"], "java/lang/Exception")
        self.assertEqual(res["handlers"][0]["stack"],
                         ["ref java/lang/Exception"])

    def test_init_initializes_every_copy_of_the_identity(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0x4B)              # 4 astore_0  (one copy into local 0)
        a.op(0xB7).u2(init)     # 5 invokespecial <init>
        a.op(0x2A)              # 8 aload_0
        a.op(0x57)              # 9 pop
        a.op(0xB1)              # 10 return
        b.add_method("run", a.build(), max_stack=2, max_locals=1)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(state_at(res, 8)["locals"], [f"ref {DIAG}"])

    def test_constructor_with_arguments(self):
        b = ClassBuilder()
        x = b.cp.cls(DIAG)
        init = b.cp.methodref(DIAG, "<init>", "(I)V")
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0x08)              # 4 iconst_5
        a.op(0xB7).u2(init)     # 5 invokespecial <init>(I)V
        a.op(0x57)              # 8 pop
        a.op(0xB1)              # 9 return
        b.add_method("run", a.build(), max_stack=3, max_locals=0)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))

    def test_same_identity_uninitialized_merge_passes(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x4B)              # 3 astore_0
        a.op(0x03)              # 4 iconst_0
        a.branch(0x99, "j")     # 5 ifeq j
        a.branch(0xA7, "j")     # 8 goto j
        a.label("j")            # 11
        a.op(0x2A)              # 11 aload_0
        a.op(0xB7).u2(init)     # 12 invokespecial <init>
        a.op(0xB1)              # 15 return
        b.add_method("run", a.build(), max_stack=2, max_locals=1)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))

    def test_distinct_refs_merge_to_object(self):
        b, x, init = diag_builder()
        s = b.cp.string("hello")
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.branch(0x99, "l1")    # 1 ifeq l1
        a.op(0xBB).u2(x)        # 4 new
        a.op(0x59)              # 7 dup
        a.op(0xB7).u2(init)     # 8 invokespecial <init>
        a.op(0x4B)              # 11 astore_0
        a.branch(0xA7, "j")     # 12 goto j
        a.label("l1")           # 15
        a.op(0x12, s)           # 15 ldc "hello"
        a.op(0x4B)              # 17 astore_0
        a.label("j")            # 18
        a.op(0x2A)              # 18 aload_0
        a.op(0x57)              # 19 pop
        a.op(0xB1)              # 20 return
        b.add_method("run", a.build(), max_stack=2, max_locals=1)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(state_at(res, 18)["locals"], ["ref java/lang/Object"])

    def test_athrow_of_initialized_object_passes(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0xB7).u2(init)     # 4 invokespecial <init>
        a.op(0xBF)              # 7 athrow
        a.label("h")            # 8
        a.op(0x57)              # 8 pop
        a.op(0xB1)              # 9 return
        b.add_method("run", a.build(), max_stack=2, max_locals=0,
                     exceptions=[(0, 8, 8, 0)])
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertTrue(res["handlers"][0]["reachable"])

    def test_goto_w_and_iinc_and_ldc(self):
        b = ClassBuilder()
        s = b.cp.string("x")
        a = Asm()
        a.branch(0xC8, "over", wide=True)  # 0 goto_w over
        a.op(0x00)              # 5 nop
        a.label("over")         # 6
        a.op(0x03)              # 6 iconst_0
        a.op(0x3B)              # 7 istore_0
        a.op(0x84, 0x00, 0x01)  # 8 iinc 0 1
        a.op(0x1A)              # 11 iload_0
        a.op(0x57)              # 12 pop
        a.op(0x12, s)           # 13 ldc "x"
        a.op(0x4B)              # 15 astore_0
        a.op(0xB1)              # 16 return
        b.add_method("run", a.build(), max_stack=1, max_locals=1)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(state_at(res, 16)["locals"],
                         ["ref java/lang/String"])
        self.assertFalse(state_at(res, 5)["reachable"])

    def test_if_acmpeq_on_nulls(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x01)              # 0 aconst_null
        a.op(0x01)              # 1 aconst_null
        a.branch(0xA5, "t")     # 2 if_acmpeq t
        a.op(0xB1)              # 5 return
        a.label("t")            # 6
        a.op(0xB1)              # 6 return
        b.add_method("run", a.build(), max_stack=2, max_locals=0)
        res = verify_class(b.build())
        self.assertTrue(res["ok"], res.get("error"))


class LegacySubroutineTests(unittest.TestCase):
    """Old-javac jsr/jsr_w + astore + ret shared cleanup segments."""

    def test_two_call_sites_share_one_cleanup_segment(self):
        res = verify_class(legacy_jsr_cleanup_class())
        self.assertTrue(res.get("ok"), res.get("error"))
        # The two call sites (jsr at 0 and 5), the cleanup entry (11), the
        # saved-continuation store (11), the ret (13) and both return points
        # (3 and 15) all carry a reviewable incoming frame.
        offsets = {s["offset"]: s for s in res["states"]}
        for off in (0, 3, 4, 5, 8, 11, 13, 15):
            self.assertIn(off, offsets)
            self.assertTrue(offsets[off]["reachable"],
                            f"offset {off} should be reachable")
        # The two jsr calls converge at the cleanup entry; the incoming
        # returnAddress is therefore the set {3, 8} of both continuations.
        self.assertEqual(offsets[11]["stack"], ["returnAddress(3,8)"])
        self.assertEqual(offsets[11]["locals"][:2], ["top", "top"])
        # astore_1 saves it; ret 1 resumes at both continuations.
        self.assertEqual(offsets[13]["locals"][1], "returnAddress(3,8)")
        # Handler (call site B) entry state: caught Throwable on the stack.
        h = res["handlers"][0]
        self.assertEqual((h["start_pc"], h["end_pc"], h["handler_pc"]),
                         (0, 3, 4))
        self.assertEqual(h["stack"], ["ref java/lang/Throwable"])
        self.assertTrue(h["reachable"])
        # Both return points converge with identical empty stacks.
        self.assertEqual(offsets[3]["stack"], [])
        self.assertEqual(offsets[15]["stack"], [])
        self.assertEqual(offsets[8]["stack"], [])

    def test_jsr_w_wide_displacement_passes(self):
        res = verify_class(legacy_jsr_wide_class())
        self.assertTrue(res.get("ok"), res.get("error"))
        offsets = {s["offset"]: s for s in res["states"]}
        # Continuation 5, cleanup entry 32770 and the ret are all reachable.
        for off in (0, 5, 32770, 32771):
            self.assertIn(off, offsets)
            self.assertTrue(offsets[off]["reachable"],
                            f"offset {off} should be reachable")
        self.assertEqual(offsets[32770]["stack"], ["returnAddress(5)"])
        self.assertEqual(offsets[32771]["locals"][1], "returnAddress(5)")
        # The linear padding is never executed (no fall-through from the jsr).
        self.assertFalse(offsets[6]["reachable"])

    def test_nested_cleanup_segments_passes(self):
        res = verify_class(legacy_nested_cleanup_class())
        self.assertTrue(res.get("ok"), res.get("error"))
        offsets = {s["offset"]: s for s in res["states"]}
        for off in (0, 3, 4, 5, 8, 10, 12):
            self.assertIn(off, offsets)
            self.assertTrue(offsets[off]["reachable"],
                            f"offset {off} should be reachable")
        # Outer segment saved in local 1, inner segment in local 2.
        self.assertEqual(offsets[8]["locals"][1], "returnAddress(3)")
        self.assertEqual(offsets[12]["locals"][2], "returnAddress(8)")
        self.assertEqual(offsets[12]["locals"][1], "returnAddress(3)")

    def test_ret_without_saved_return_address_rejected(self):
        res = verify_class(bad_return_address_class())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-return-address")
        self.assertEqual(res["error"]["offset"], 0)

    def test_ret_local_out_of_range_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([
            0xA8, 0x00, 0x04,  # 0 jsr 7
            0xB1,              # 3 return
            0x4B,              # 4 astore_0
            0xA9, 0x05,        # 5 ret 5 (index 5 >= max_locals)
        ]), max_stack=1, max_locals=2)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "local-index-out-of-range")
        self.assertEqual(res["error"]["offset"], 5)

    def test_jsr_target_into_instruction_middle_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.branch(0xA8, "mid")   # 0 jsr mid
        a.op(0x11)              # 3 sipush ...
        a.label("mid")          # 4 (middle of the 16-bit immediate)
        a.u2(0x1234)
        a.op(0x4C)              # 6 astore_1
        a.op(0xA9, 0x01)        # 7 ret 1
        b.add_method("run", a.build(), max_stack=1, max_locals=2)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-branch-target")
        self.assertEqual(res["error"]["offset"], 0)

    def test_aload_of_return_address_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.branch(0xA8, "c")     # 0 jsr c
        a.op(0xB1)              # 3 return
        a.label("c")            # 4
        a.op(0x4C)              # 4 astore_1 (save return address)
        a.op(0x2B)              # 5 aload_1 (illegal: returnAddress is not a ref)
        a.op(0x57)              # 6 pop
        a.op(0xA9, 0x01)        # 7 ret 1
        b.add_method("run", a.build(), max_stack=1, max_locals=2)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "type-mismatch")
        self.assertEqual(res["error"]["offset"], 5)


class RejectionTests(unittest.TestCase):
    def test_uninitialized_local_escapes_to_handler(self):
        res = verify_class(uninitialized_escape_class())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "uninitialized-escapes-to-handler")
        self.assertEqual(res["error"]["offset"], 4)
        self.assertIn("new@0", res["error"]["message"])
        self.assertIn("handler@10", res["error"]["message"])

    def test_uninitialized_merges_with_initialized_ref_rejected(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.branch(0x99, "l1")    # 1 ifeq l1
        a.op(0xBB).u2(x)        # 4 new
        a.branch(0xA7, "j")     # 7 goto j
        a.label("l1")           # 10
        a.op(0x01)              # 10 aconst_null
        a.label("j")            # 11
        a.op(0x4B)              # 11 astore_0
        a.op(0xB1)              # 12 return
        b.add_method("run", a.build(), max_stack=1, max_locals=1)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "incompatible-types")
        self.assertEqual(res["error"]["offset"], 11)

    def test_stack_height_mismatch_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.op(0x03)              # 0 iconst_0
        a.branch(0x99, "j")     # 1 ifeq j
        a.op(0x04)              # 4 iconst_1
        a.branch(0xA7, "j")     # 5 goto j
        a.label("j")            # 8
        a.op(0xB1)              # 8 return
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stack-height-mismatch")
        self.assertEqual(res["error"]["offset"], 8)

    def test_jump_into_instruction_middle_rejected(self):
        b = ClassBuilder()
        a = Asm()
        a.branch(0xA7, "mid")   # 0 goto mid
        a.op(0x11)              # 3 sipush ...
        a.label("mid")          # 4 (middle of the sipush immediate)
        a.u2(0x1234)            # 4..5
        a.op(0x57)              # 6 pop
        a.op(0xB1)              # 7 return
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-branch-target")
        self.assertEqual(res["error"]["offset"], 0)
        self.assertIn("offset 4", res["error"]["message"])

    def test_truncated_file_rejected(self):
        data = legal_construction_class()
        res = verify_class(data[:len(data) - 7])
        self.assertFalse(res["ok"])
        self.assertIn(res["error"]["kind"], ("truncated", "truncated-attribute"))
        self.assertIsInstance(res["error"]["offset"], int)

    def test_truncated_attribute_length_rejected(self):
        b, x, init = diag_builder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=0)
        data = bytearray(b.build())
        off = b.marks["method0.attr_len_off"]
        orig = int.from_bytes(data[off:off + 4], "big")
        data[off:off + 4] = (orig + 32).to_bytes(4, "big")
        res = verify_class(bytes(data))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-attribute")
        self.assertEqual(res["error"]["offset"], b.marks["method0.attr_name_off"])

    def test_invalid_handler_ranges_rejected(self):
        # code: 0: bipush 5 (2 bytes) ; 2: return
        cases = [
            ("end_pc beyond code", (0, 99, 2, 0)),
            ("handler into mid-instruction", (0, 2, 1, 0)),
            ("empty range", (2, 2, 0, 0)),
            ("end_pc mid-instruction", (0, 1, 2, 0)),
        ]
        for name, entry in cases:
            with self.subTest(name=name):
                b = ClassBuilder()
                b.add_method("run", bytes([0x10, 0x05, 0xB1]),
                             max_stack=1, max_locals=0, exceptions=[entry])
                res = verify_class(b.build())
                self.assertFalse(res["ok"])
                self.assertEqual(res["error"]["kind"], "bad-handler-range")
                self.assertIsInstance(res["error"]["offset"], int)
                self.assertGreater(res["error"]["offset"], 0)

    def test_double_init_rejected(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0x59)              # 3 dup
        a.op(0xB7).u2(init)     # 4 invokespecial <init>
        a.op(0xB7).u2(init)     # 7 invokespecial <init> again
        a.op(0xB1)              # 10 return
        b.add_method("run", a.build(), max_stack=2, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "already-initialized")
        self.assertEqual(res["error"]["offset"], 7)

    def test_athrow_of_uninitialized_rejected(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0xBF)              # 3 athrow
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "uninitialized-object-used")
        self.assertEqual(res["error"]["offset"], 3)

    def test_init_on_null_rejected(self):
        b, x, init = diag_builder()
        a = Asm()
        a.op(0x01)              # 0 aconst_null
        a.op(0xB7).u2(init)     # 1 invokespecial <init>
        a.op(0xB1)              # 4 return
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "type-mismatch")
        self.assertEqual(res["error"]["offset"], 1)

    def test_non_constructor_invokespecial_rejected(self):
        b = ClassBuilder()
        x = b.cp.cls(DIAG)
        m = b.cp.methodref(DIAG, "ping", "()V")
        a = Asm()
        a.op(0xBB).u2(x)        # 0 new
        a.op(0xB7).u2(m)        # 3 invokespecial ping
        a.op(0xB1)              # 6 return
        b.add_method("run", a.build(), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "unsupported-invokespecial")
        self.assertEqual(res["error"]["offset"], 3)

    def test_stack_underflow(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0x60, 0xB1]), max_stack=2, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stack-underflow")
        self.assertEqual(res["error"]["offset"], 0)

    def test_stack_overflow(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0x03, 0x03, 0x57, 0x57, 0xB1]),
                     max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "stack-overflow")
        self.assertEqual(res["error"]["offset"], 1)

    def test_local_index_out_of_range(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0x03, 0x3E, 0xB1]),
                     max_stack=1, max_locals=1)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "local-index-out-of-range")
        self.assertEqual(res["error"]["offset"], 1)

    def test_astore_of_int_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0x03, 0x4B, 0xB1]),
                     max_stack=1, max_locals=1)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "type-mismatch")
        self.assertEqual(res["error"]["offset"], 1)

    def test_fall_off_end_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0x03]), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "fall-off-end")
        self.assertEqual(res["error"]["offset"], 0)

    def test_unknown_opcode_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xCA, 0xB1]), max_stack=0, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "unknown-opcode")
        self.assertEqual(res["error"]["offset"], 0)

    def test_truncated_instruction_rejected(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xBB, 0x00]), max_stack=1, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "truncated-instruction")
        self.assertEqual(res["error"]["offset"], 0)

    def test_empty_code_rejected(self):
        b = ClassBuilder()
        b.add_method("run", b"", max_stack=0, max_locals=0)
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "empty-code")

    def test_bad_magic_rejected(self):
        res = verify_class(b"\x00" * 32)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "bad-magic")
        self.assertEqual(res["error"]["offset"], 0)

    def test_non_converging_guard(self):
        res = verify_class(legal_construction_class(), max_steps=2)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "non-converging")
        self.assertIsInstance(res["error"]["offset"], int)


class MethodSelectionTests(unittest.TestCase):
    def _two_method_class(self):
        b = ClassBuilder()
        b.add_method("ma", bytes([0xB1]), max_stack=0, max_locals=0)
        b.add_method("mb", bytes([0xB1]), max_stack=0, max_locals=0)
        return b.build()

    def test_ambiguous_static_void_methods(self):
        res = verify_class(self._two_method_class())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "ambiguous-method")
        self.assertEqual(res["error"]["candidates"], ["ma", "mb"])

    def test_named_method_selected(self):
        res = verify_class(self._two_method_class(), method_name="mb")
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["method"], "mb")

    def test_unknown_method_name(self):
        res = verify_class(self._two_method_class(), method_name="zz")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "no-target-method")

    def test_instance_method_not_a_target(self):
        b = ClassBuilder()
        b.add_method("run", bytes([0xB1]), max_stack=0, max_locals=1,
                     access=ACC_PUBLIC)  # not static
        res = verify_class(b.build())
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["kind"], "no-target-method")


if __name__ == "__main__":
    unittest.main()
