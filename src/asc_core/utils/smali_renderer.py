"""Smali bytecode renderer — walks Dalvik bytecode and produces human-readable smali lines."""

import struct
from models.dvm_opcode import opcodes, Format, IndexFlag
from utils.dvm_regdec import get_vreg_a, get_vreg_b, get_vreg_c, get_index, fetch16

WORD = 2
_STRUCT_H = struct.Struct("<H")
_STRUCT_H_SIGNED = struct.Struct("<h")
_STRUCT_I_SIGNED = struct.Struct("<i")
_STRUCT_I = struct.Struct("<I")
_STRUCT_Q = struct.Struct("<Q")


def _dalvik_to_dot(name: str) -> str:
    if name.startswith("L") and name.endswith(";"):
        return name[1:-1].replace("/", ".")
    return name


def _format_type_ref(dex, idx: int) -> str:
    return _dalvik_to_dot(dex.types[idx].descriptor)


def _format_string_ref(dex, idx: int) -> str:
    try:
        s = dex.strings[idx]
    except (IndexError, KeyError):
        return f"string@{idx}"
    escaped = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{escaped}"'


def _format_method_ref(dex, idx: int) -> str:
    method = dex.methods[idx]
    cls = _dalvik_to_dot(method.cls.fullname)
    proto = method.prototype
    params = "".join(t.descriptor for t in proto.parameters_type)
    ret = dex.types[proto.return_type_idx].descriptor
    return f"{cls}->{method.name}({params}){ret}"


def _format_field_ref(dex, idx: int) -> str:
    field = dex.fields[idx]
    cls = _dalvik_to_dot(field.cls.fullname)
    return f"{cls}->{field.name}:{field.type.descriptor}"


def _format_index(dex, idx_type, idx: int) -> str:
    if idx_type == IndexFlag.kIndexStringRef:
        return _format_string_ref(dex, idx)
    if idx_type == IndexFlag.kIndexTypeRef:
        return _format_type_ref(dex, idx)
    if idx_type == IndexFlag.kIndexMethodRef:
        return _format_method_ref(dex, idx)
    if idx_type == IndexFlag.kIndexFieldRef:
        return _format_field_ref(dex, idx)
    return f"thing@{idx}"


def _format_offset(bc_bytes: bytes, pc: int, offset_units: int) -> str:
    target = pc + offset_units * 2
    if target < 0:
        return f"-0x{-target:x}"
    return f"+0x{target:x}"


def _render_instruction(bc_bytes: bytes, pc: int, op, dex) -> str:
    fmt = op.fmt
    name = op.name

    # k10x: op
    if fmt == Format.k10x:
        return f"    {name}"

    # k12x: op vA, vB
    if fmt == Format.k12x:
        va = get_vreg_a(bc_bytes, pc, op)
        vb = get_vreg_b(bc_bytes, pc, op)
        return f"    {name} v{va}, v{vb}"

    # k11n: op vA, #+B (signed 4-bit)
    if fmt == Format.k11n:
        va = get_vreg_a(bc_bytes, pc, op)
        vb = get_vreg_b(bc_bytes, pc, op)
        return f"    {name} v{va}, #+0x{vb & 0xf:x}"

    # k11x: op vAA
    if fmt == Format.k11x:
        va = get_vreg_a(bc_bytes, pc, op)
        return f"    {name} v{va}"

    # k10t: op +AA (signed 8-bit offset)
    if fmt == Format.k10t:
        offset = _STRUCT_H_SIGNED.unpack_from(bc_bytes, pc)[0] >> 8
        return f"    {name} {_format_offset(bc_bytes, pc, offset)}"

    # k20t: op +AAAA (signed 16-bit offset)
    if fmt == Format.k20t:
        offset = _STRUCT_H_SIGNED.unpack_from(bc_bytes, pc + 2)[0]
        return f"    {name} {_format_offset(bc_bytes, pc, offset)}"

    # k22x: op vAA, vBBBB
    if fmt == Format.k22x:
        va = get_vreg_a(bc_bytes, pc, op)
        vb = get_vreg_b(bc_bytes, pc, op)
        return f"    {name} v{va}, v{vb}"

    # k21t: op vAA, +BBBB (signed 16-bit offset)
    if fmt == Format.k21t:
        va = get_vreg_a(bc_bytes, pc, op)
        offset = _STRUCT_H_SIGNED.unpack_from(bc_bytes, pc + 2)[0]
        return f"    {name} v{va}, {_format_offset(bc_bytes, pc, offset)}"

    # k21s: op vAA, #+BBBB (signed 16-bit literal)
    if fmt == Format.k21s:
        va = get_vreg_a(bc_bytes, pc, op)
        lit = _STRUCT_H_SIGNED.unpack_from(bc_bytes, pc + 2)[0]
        return f"    {name} v{va}, #+0x{lit & 0xffff:x}"

    # k21h: op vAA, #+BBBB0000[00000000]
    if fmt == Format.k21h:
        va = get_vreg_a(bc_bytes, pc, op)
        vb = get_vreg_b(bc_bytes, pc, op)
        if "wide" in name:
            return f"    {name} v{va}, #+0x{vb << 48 & 0xffffffffffffffff:x}"
        return f"    {name} v{va}, #+0x{vb << 16 & 0xffffffff:x}"

    # k21c: op vAA, thing@BBBB
    if fmt == Format.k21c:
        va = get_vreg_a(bc_bytes, pc, op)
        idx = get_index(bc_bytes, op, pc)
        ref = _format_index(dex, op.idx, idx)
        return f"    {name} v{va}, {ref}"

    # k23x: op vAA, vBB, vCC
    if fmt == Format.k23x:
        va = get_vreg_a(bc_bytes, pc, op)
        vb = get_vreg_b(bc_bytes, pc, op)
        vc = get_vreg_c(bc_bytes, pc, op)
        return f"    {name} v{va}, v{vb}, v{vc}"

    # k22b: op vAA, vBB, #+CC
    if fmt == Format.k22b:
        va = get_vreg_a(bc_bytes, pc, op)
        vb = get_vreg_b(bc_bytes, pc, op)
        lit = bc_bytes[pc + 3]
        return f"    {name} v{va}, v{vb}, #+0x{lit:x}"

    # k22t: op vA, vB, +CCCC (signed 16-bit offset)
    if fmt == Format.k22t:
        va = get_vreg_a(bc_bytes, pc, op)
        vb = get_vreg_b(bc_bytes, pc, op)
        offset = _STRUCT_H_SIGNED.unpack_from(bc_bytes, pc + 2)[0]
        return f"    {name} v{va}, v{vb}, {_format_offset(bc_bytes, pc, offset)}"

    # k22s: op vA, vB, #+CCCC (signed 16-bit literal)
    if fmt == Format.k22s:
        va = get_vreg_a(bc_bytes, pc, op)
        vb = get_vreg_b(bc_bytes, pc, op)
        lit = _STRUCT_H_SIGNED.unpack_from(bc_bytes, pc + 2)[0]
        return f"    {name} v{va}, v{vb}, #+0x{lit & 0xffff:x}"

    # k22c: op vA, vB, thing@CCCC
    if fmt == Format.k22c:
        va = get_vreg_a(bc_bytes, pc, op)
        vb = get_vreg_b(bc_bytes, pc, op)
        idx = get_index(bc_bytes, op, pc)
        ref = _format_index(dex, op.idx, idx)
        return f"    {name} v{va}, v{vb}, {ref}"

    # k32x: op vAAAA, vBBBB
    if fmt == Format.k32x:
        va = get_vreg_a(bc_bytes, pc, op)
        vb = get_vreg_b(bc_bytes, pc, op)
        return f"    {name} v{va}, v{vb}"

    # k30t: op +AAAAAAAA (signed 32-bit offset)
    if fmt == Format.k30t:
        offset = _STRUCT_I_SIGNED.unpack_from(bc_bytes, pc + 2)[0]
        return f"    {name} {_format_offset(bc_bytes, pc, offset)}"

    # k31t: op vAA, +BBBBBBBB (signed 32-bit offset)
    if fmt == Format.k31t:
        va = get_vreg_a(bc_bytes, pc, op)
        offset = _STRUCT_I_SIGNED.unpack_from(bc_bytes, pc + 2)[0]
        return f"    {name} v{va}, {_format_offset(bc_bytes, pc, offset)}"

    # k31i: op vAA, #+BBBBBBBB (signed 32-bit literal)
    if fmt == Format.k31i:
        va = get_vreg_a(bc_bytes, pc, op)
        lit = _STRUCT_I_SIGNED.unpack_from(bc_bytes, pc + 2)[0]
        return f"    {name} v{va}, #+0x{lit & 0xffffffff:x}"

    # k31c: op vAA, thing@BBBBBBBB
    if fmt == Format.k31c:
        va = get_vreg_a(bc_bytes, pc, op)
        idx = get_index(bc_bytes, op, pc)
        ref = _format_index(dex, op.idx, idx)
        return f"    {name} v{va}, {ref}"

    # k35c: op {vC, vD, vE, vF, vG}, thing@BBBB (A: count)
    if fmt == Format.k35c:
        w0 = fetch16(bc_bytes, pc, 0)
        count = w0 >> 12
        idx = get_index(bc_bytes, op, pc)
        ref = _format_index(dex, op.idx, idx)
        if count == 0:
            return f"    {name} {{}}, {ref}"
        regs = []
        if count >= 1:
            regs.append(f"v{get_vreg_c(bc_bytes, pc, op)}")
        if count >= 2:
            regs.append(f"v{bc_bytes[pc + 3] >> 4}")
        if count >= 3:
            regs.append(f"v{bc_bytes[pc + 3] & 0xf}")
        if count >= 4:
            regs.append(f"v{bc_bytes[pc + 4] >> 4}")
        if count >= 5:
            regs.append(f"v{bc_bytes[pc + 4] & 0xf}")
        return f"    {name} {{{', '.join(regs)}}}, {ref}"

    # k3rc: op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB (AA: count)
    if fmt == Format.k3rc:
        count = bc_bytes[pc + 1]
        idx = get_index(bc_bytes, op, pc)
        ref = _format_index(dex, op.idx, idx)
        start_reg = _STRUCT_H.unpack_from(bc_bytes, pc + 4)[0]
        if count == 0:
            return f"    {name} {{}}, {ref}"
        if count == 1:
            return f"    {name} {{v{start_reg}}}, {ref}"
        end_reg = start_reg + count - 1
        return f"    {name} {{v{start_reg} .. v{end_reg}}}, {ref}"

    # k51l: op vAA, #+BBBBBBBBBBBBBBBB (64-bit literal)
    if fmt == Format.k51l:
        va = get_vreg_a(bc_bytes, pc, op)
        lit = _STRUCT_Q.unpack_from(bc_bytes, pc + 2)[0]
        return f"    {name} v{va}, #+0x{lit:x}"

    # k45cc: op {vC, vD, vE, vF, vG}, meth@BBBB, proto@HHHH
    if fmt == Format.k45cc:
        w0 = fetch16(bc_bytes, pc, 0)
        count = w0 >> 12
        idx = get_index(bc_bytes, op, pc)
        ref = _format_index(dex, IndexFlag.kIndexMethodRef, idx)
        regs = []
        if count >= 1:
            regs.append(f"v{get_vreg_c(bc_bytes, pc, op)}")
        if count >= 2:
            regs.append(f"v{bc_bytes[pc + 3] >> 4}")
        if count >= 3:
            regs.append(f"v{bc_bytes[pc + 3] & 0xf}")
        if count >= 4:
            regs.append(f"v{bc_bytes[pc + 4] >> 4}")
        if count >= 5:
            regs.append(f"v{bc_bytes[pc + 4] & 0xf}")
        if not regs:
            return f"    {name} {{}}, {ref}"
        return f"    {name} {{{', '.join(regs)}}}, {ref}"

    # k4rcc: op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB, proto@HHHH
    if fmt == Format.k4rcc:
        count = bc_bytes[pc + 1]
        idx = get_index(bc_bytes, op, pc)
        ref = _format_index(dex, IndexFlag.kIndexMethodRef, idx)
        start_reg = _STRUCT_H.unpack_from(bc_bytes, pc + 4)[0]
        if count == 0:
            return f"    {name} {{}}, {ref}"
        if count == 1:
            return f"    {name} {{v{start_reg}}}, {ref}"
        end_reg = start_reg + count - 1
        return f"    {name} {{v{start_reg} .. v{end_reg}}}, {ref}"

    # Fallback
    return f"    {name}  // unknown format {fmt.name}"


def render_smali(bytecode: list, dex) -> list:
    """Walk bytecode instruction by instruction, render each as a smali line."""
    if not bytecode:
        return []
    bc_bytes = bytes(bytecode)
    flow_len = len(bc_bytes)
    lines = []
    pc = 0
    while pc < flow_len:
        opcode = bc_bytes[pc]
        if opcode not in opcodes:
            break
        op = opcodes[opcode]
        line = _render_instruction(bc_bytes, pc, op, dex)
        lines.append(line)
        pc += op.oplen * WORD
    return lines
