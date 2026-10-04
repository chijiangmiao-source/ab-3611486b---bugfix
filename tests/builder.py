"""Test helper: build real JVM class files (constant pool + Code) by hand.

Used by the unit tests and by the Compose `verify` smoke service to produce
both well-formed and deliberately malformed class files.
"""
import struct

ACC_PUBLIC = 0x0001
ACC_STATIC = 0x0008
ACC_SUPER = 0x0020


def u1(v):
    return struct.pack(">B", v)


def u2(v):
    return struct.pack(">H", v)


def u4(v):
    return struct.pack(">I", v)


class Cp:
    """Constant-pool builder with de-duplication."""

    def __init__(self):
        self.entries = [None]
        self.index = {}

    def _add(self, key, entry):
        if key in self.index:
            return self.index[key]
        idx = len(self.entries)
        self.entries.append(entry)
        self.index[key] = idx
        return idx

    def utf8(self, s):
        return self._add(("Utf8", s), ("utf8", s))

    def cls(self, name):
        return self._add(("Class", name), ("class", self.utf8(name)))

    def string(self, s):
        return self._add(("String", s), ("string", self.utf8(s)))

    def integer(self, v):
        return self._add(("Integer", v), ("int", v))

    def nameandtype(self, n, d):
        return self._add(("NT", n, d), ("nat", self.utf8(n), self.utf8(d)))

    def methodref(self, c, n, d):
        return self._add(("MR", c, n, d),
                         ("methodref", self.cls(c), self.nameandtype(n, d)))

    def render(self):
        out = [u2(len(self.entries))]
        for e in self.entries[1:]:
            tag = e[0]
            if tag == "utf8":
                b = e[1].encode("utf-8")
                out.append(u1(1) + u2(len(b)) + b)
            elif tag == "int":
                out.append(u1(3) + struct.pack(">i", e[1]))
            elif tag == "class":
                out.append(u1(7) + u2(e[1]))
            elif tag == "string":
                out.append(u1(8) + u2(e[1]))
            elif tag == "nat":
                out.append(u1(12) + u2(e[1]) + u2(e[2]))
            elif tag == "methodref":
                out.append(u1(10) + u2(e[1]) + u2(e[2]))
            else:
                raise AssertionError(tag)
        return b"".join(out)


class Asm:
    """Tiny assembler: emits bytes, resolves branch fixups to labels."""

    def __init__(self):
        self.buf = bytearray()
        self.labels = {}
        self.fixups = []  # (operand_pos, insn_pos, label, width)

    @property
    def pc(self):
        return len(self.buf)

    def label(self, name):
        self.labels[name] = len(self.buf)
        return self

    def op(self, *bs):
        self.buf += bytes(bs)
        return self

    def u2(self, v):
        self.buf += u2(v)
        return self

    def branch(self, opcode, label, wide=False):
        insn = len(self.buf)
        self.buf.append(opcode)
        width = 4 if wide else 2
        self.fixups.append((len(self.buf), insn, label, width))
        self.buf += b"\x00" * width
        return self

    def build(self):
        for pos, insn, label, width in self.fixups:
            off = self.labels[label] - insn
            self.buf[pos:pos + width] = off.to_bytes(width, "big", signed=True)
        return bytes(self.buf)


class ClassBuilder:
    """Assembles a complete class file; `marks` records interesting offsets."""

    def __init__(self, this_name="Test", super_name="java/lang/Object"):
        self.cp = Cp()
        self.this_name = this_name
        self.super_name = super_name
        self.methods = []
        self.marks = {}

    def add_method(self, name, code, max_stack=8, max_locals=4, exceptions=(),
                   desc="()V", access=ACC_PUBLIC | ACC_STATIC):
        self.methods.append({
            "name": name, "code": bytes(code), "max_stack": max_stack,
            "max_locals": max_locals, "exceptions": list(exceptions),
            "desc": desc, "access": access,
        })
        return len(self.methods) - 1

    def build(self):
        cp = self.cp
        this_idx = cp.cls(self.this_name)
        super_idx = cp.cls(self.super_name)
        code_utf = cp.utf8("Code")
        for m in self.methods:
            m["name_idx"] = cp.utf8(m["name"])
            m["desc_idx"] = cp.utf8(m["desc"])
            m["catch_idx"] = [
                cp.cls(c) if isinstance(c, str) else 0
                for (_s, _e, _h, c) in m["exceptions"]
            ]
        out = bytearray()
        out += u4(0xCAFEBABE) + u2(0) + u2(52)
        out += cp.render()
        out += u2(ACC_PUBLIC | ACC_SUPER) + u2(this_idx) + u2(super_idx)
        out += u2(0)  # interfaces
        out += u2(0)  # fields
        out += u2(len(self.methods))
        for i, m in enumerate(self.methods):
            body = bytearray()
            body += u2(m["max_stack"]) + u2(m["max_locals"])
            body += u4(len(m["code"])) + m["code"]
            body += u2(len(m["exceptions"]))
            for (s, e, h, _), ci in zip(m["exceptions"], m["catch_idx"]):
                body += u2(s) + u2(e) + u2(h) + u2(ci)
            body += u2(0)  # Code attributes
            out += u2(m["access"]) + u2(m["name_idx"]) + u2(m["desc_idx"])
            out += u2(1)  # one attribute
            self.marks[f"method{i}.attr_name_off"] = len(out)
            out += u2(code_utf)
            self.marks[f"method{i}.attr_len_off"] = len(out)
            out += u4(len(body))
            out += body
        out += u2(0)  # class attributes
        return bytes(out)


# ---------------------------------------------------------------------------
# Shared fixtures (unit tests, API tests and the Compose smoke service)
# ---------------------------------------------------------------------------

def legal_construction_class():
    """A passing class: new/dup/invokespecial inside a try, handler after it."""
    b = ClassBuilder("Smoke")
    x = b.cp.cls("com/acme/Diag")
    init = b.cp.methodref("com/acme/Diag", "<init>", "()V")
    a = Asm()
    a.op(0xBB).u2(x)       # 0 new
    a.op(0x59)             # 3 dup
    a.op(0xB7).u2(init)    # 4 invokespecial <init>
    a.op(0x4B)             # 7 astore_0
    a.op(0xB1)             # 8 return
    a.label("h")           # 9
    a.op(0x57)             # 9 pop
    a.op(0xB1)             # 10 return
    b.add_method("run", a.build(), max_stack=2, max_locals=1,
                 exceptions=[(0, 9, 9, 0)])
    return b.build()


def uninitialized_escape_class():
    """A rejected class: local 0 holds an uninitialized object across an
    exception edge (first rejection expected at code offset 4)."""
    b = ClassBuilder("Bad")
    x = b.cp.cls("com/acme/Diag")
    init = b.cp.methodref("com/acme/Diag", "<init>", "()V")
    a = Asm()
    a.op(0xBB).u2(x)       # 0 new
    a.op(0x4B)             # 3 astore_0   (uninitialized -> local 0)
    a.op(0x00)             # 4 nop        <- exception edge carries uninit
    a.op(0x2A)             # 5 aload_0
    a.op(0xB7).u2(init)    # 6 invokespecial <init>
    a.op(0xB1)             # 9 return
    a.label("h")           # 10
    a.op(0x57)             # 10 pop
    a.op(0xB1)             # 11 return
    b.add_method("run", a.build(), max_stack=2, max_locals=1,
                 exceptions=[(0, 10, 10, 0)])
    return b.build()


def legacy_finally_class():
    """A passing class in the old-javac finally idiom: two jsr call sites
    reuse one shared cleanup segment, which saves the continuation in a
    local and returns via ret.  A catch-all handler sits adjacent to the
    exception table.

      0 jsr C            (continuation 3)
      3 iconst_0         (normal work between the two call sites)
      4 pop
      5 jsr C            (continuation 8)
      8 return
      9 astore_1         C: save returnAddress
     10 nop              (cleanup body)
     11 ret 1            (resume the matching continuation)
     13 pop              h: catch-all handler
     14 return

    exception table: (0, 9, 13, 0)
    """
    b = ClassBuilder("Legacy")
    a = Asm()
    a.branch(0xA8, "clean")  # 0 jsr clean  -> cont 3
    a.op(0x03)               # 3 iconst_0
    a.op(0x57)               # 4 pop
    a.branch(0xA8, "clean")  # 5 jsr clean  -> cont 8
    a.op(0xB1)               # 8 return
    a.label("clean")         # 9
    a.op(0x4C)               # 9 astore_1 (save continuation)
    a.op(0x00)               # 10 nop (cleanup work)
    a.op(0xA9, 0x01)         # 11 ret 1
    a.label("h")             # 13
    a.op(0x57)               # 13 pop
    a.op(0xB1)               # 14 return
    b.add_method("run", a.build(), max_stack=1, max_locals=2,
                 exceptions=[(0, 9, 13, 0)])
    return b.build()


def wide_jsr_finally_class():
    """The same shared-segment idiom entered with the 4-byte jsr_w form
    (wide displacement), with a block of nops between the call and the
    segment so the branch leaves the jsr/jsr_w operand machinery exercised."""
    b = ClassBuilder("LegacyWide")
    a = Asm()
    a.branch(0xC9, "clean", wide=True)  # 0 jsr_w clean -> cont 5
    for _ in range(120):
        a.op(0x00)                      # 5..124 nop
    a.op(0xB1)                          # 125 return
    a.label("clean")                    # 126
    a.op(0x4B)                          # 126 astore_0 (save continuation)
    a.op(0x00)                          # 127 nop (cleanup work)
    a.op(0xA9, 0x00)                    # 128 ret 0
    b.add_method("run", a.build(), max_stack=1, max_locals=1)
    return b.build()


def nested_finally_class():
    """A passing class with a cleanup segment that itself calls a nested
    cleanup segment; the two saved continuations live in distinct locals."""
    b = ClassBuilder("LegacyNested")
    a = Asm()
    a.branch(0xA8, "outer")  # 0 jsr outer -> cont 3
    a.op(0xB1)               # 3 return
    a.label("outer")         # 4
    a.op(0x4C)               # 4 astore_1 (outer continuation)
    a.branch(0xA8, "inner")  # 5 jsr inner -> cont 8
    a.op(0xA9, 0x01)         # 8 ret 1 (resume outer's caller)
    a.label("inner")         # 10
    a.op(0x4D)               # 10 astore_2 (inner continuation)
    a.op(0x00)               # 11 nop (inner cleanup work)
    a.op(0xA9, 0x02)         # 12 ret 2 (resume inside outer)
    b.add_method("run", a.build(), max_stack=1, max_locals=3)
    return b.build()


def bad_return_address_class():
    """A rejected class: ret reads a local that holds an int instead of a
    saved return address (the cleanup continuation was never stored)."""
    b = ClassBuilder("BadRet")
    a = Asm()
    a.op(0x03)               # 0 iconst_0
    a.op(0x3D)               # 1 istore_2
    a.op(0xA9, 0x02)         # 2 ret 2  (local 2 is int, not returnAddress)
    b.add_method("run", a.build(), max_stack=1, max_locals=3)
    return b.build()


def cross_segment_return_class():
    """A rejected class: the inner segment returns through the OUTER
    segment's saved continuation, which never called the inner segment."""
    b = ClassBuilder("CrossRet")
    a = Asm()
    a.branch(0xA8, "outer")  # 0 jsr outer -> cont 3
    a.op(0xB1)               # 3 return
    a.label("outer")         # 4
    a.op(0x4C)               # 4 astore_1 (outer continuation = 3)
    a.branch(0xA8, "inner")  # 5 jsr inner -> cont 8
    a.op(0xA9, 0x01)         # 8 ret 1
    a.label("inner")         # 10
    a.op(0x4D)               # 10 astore_2 (inner continuation = 8)
    a.op(0xA9, 0x01)         # 11 ret 1  <-- resumes 3, but inner must resume 8
    b.add_method("run", a.build(), max_stack=1, max_locals=3)
    return b.build()
