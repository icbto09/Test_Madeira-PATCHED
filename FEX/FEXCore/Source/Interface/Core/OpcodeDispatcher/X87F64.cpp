// SPDX-License-Identifier: MIT
/*
$info$
tags: frontend|x86-to-ir, opcodes|dispatcher-implementations
desc: Handles x86/64 x87 to IR
$end_info$
*/

#include "Interface/Core/OpcodeDispatcher.h"
#include "Interface/Core/X86Tables/X86Tables.h"
#include "Interface/IR/IR.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

namespace FEXCore::IR {
class OrderedNode;

#define OpcodeArgs [[maybe_unused]] FEXCore::X86Tables::DecodedOp Op

void OpDispatchBuilder::X87LDENVF64(OpcodeArgs) {
  _StackForceSlow();

  const auto Size = OpSizeFromSrc(Op);
  Ref Mem = MakeSegmentAddress(Op, Op->Src[0]);

  auto NewFCW = _LoadMemGPR(OpSize::i16Bit, Mem, OpSize::i16Bit);
  // ignore the rounding precision, we're always 64-bit in F64.
  // extract rounding mode
  Ref roundingMode = _Bfe(OpSize::i32Bit, 3, 10, NewFCW);
  _SetRoundingMode(roundingMode, false, roundingMode);
  _StoreContextGPR(OpSize::i16Bit, NewFCW, offsetof(FEXCore::Core::CPUState, FCW));

  auto NewFSW = _LoadMemGPR(Size, Mem, Constant(IR::OpSizeToSize(Size)), Size, MemOffsetType::SXTX, 1);
  ReconstructX87StateFromFSW_Helper(NewFSW);

  {
    // FTW
    SetX87FTW(_LoadMemGPR(Size, Mem, Constant(IR::OpSizeToSize(Size) * 2), Size, MemOffsetType::SXTX, 1));
  }
}

void OpDispatchBuilder::X87FLDCWF64(OpcodeArgs) {
  _StackForceSlow();

  Ref NewFCW = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
  // ignore the rounding precision, we're always 64-bit in F64.
  // extract rounding mode
  Ref roundingMode = _Bfe(OpSize::i32Bit, 3, 10, NewFCW);
  _SetRoundingMode(roundingMode, false, roundingMode);
  _StoreContextGPR(OpSize::i16Bit, NewFCW, offsetof(FEXCore::Core::CPUState, FCW));
}

// iOS-Madeira-GTM: precision control in reduced-precision (F64) mode.
// The x87 FCW.PC field (bits 8-9) selects 24, 53 or 64-bit significands for FADD, FSUB, FMUL, FDIV
// and FSQRT. F64 mode always computed in 53 bits, so a game that relies on PC = single (Direct3D 9
// sets it at device creation unless D3DCREATE_FPU_PRESERVE) got different results: GTA San Andreas
// computes floor(x * 0.005f) and gets 0.99999998 instead of 1 for x = 200, and its weather compares
// a value in ST0 with the same value stored as float. When PC = single, the result is rounded to
// float and widened back; for these operations a 53-bit result rounded to 24 bits equals the 24-bit
// result (53 >= 2*24+2), and the current rounding mode applies to the conversion. Values outside the
// float normal range keep their 53-bit value (x87 keeps the 15-bit exponent in PC = single).
// Ported from GTMoraes/FEX 9005a5b (branch gtm-x87pc), where it is on by default.
// Here it is opt-in for its first device tests: MADEIRA_X87_PC=1 in the game's own
// config turns it on; unset or any other value leaves x87 exactly as before.
static bool X87PrecisionControlEnabled() {
  static const bool Enabled = [] {
    const char* Env = getenv("MADEIRA_X87_PC");
    return Env && Env[0] == '1' && Env[1] == '\0';
  }();
  return Enabled;
}

void OpDispatchBuilder::X87PrecisionControlF64(uint8_t StackLoc) {
  if (!X87PrecisionControlEnabled()) {
    return;
  }

  if (StackLoc != 0) {
    _F80StackXchange(StackLoc);
  }

  Ref Value = _ReadStackValue(0);
  Ref Single = _Float_FToF(OpSize::i32Bit, OpSize::i64Bit, Value);
  Ref Rounded = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, Single);

  Ref Gpr = _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, Value, 0);
  Ref BiasedExp = _Bfe(OpSize::i64Bit, 11, 52, Gpr);
  Ref ExpFromFloatMin = Sub(OpSize::i64Bit, BiasedExp, Constant(1023 - 126));
  Ref FCW = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, FCW));
  Ref PC = _Bfe(OpSize::i32Bit, 2, 8, FCW);

  SaveNZCV();
  // Float normal range: biased double exponent in [1023-126, 1023+127]
  SubWithFlags(OpSize::i64Bit, ExpFromFloatMin, 254);
  Ref InRange = _NZCVSelectV(OpSize::i64Bit, CondClass::ULT, Rounded, Value);
  // PC == 00 (single)
  _TestNZ(OpSize::i32Bit, PC, Constant(3));
  Ref Result = _NZCVSelectV(OpSize::i64Bit, CondClass::EQ, InRange, Value);

  _PopStackDestroy();
  _PushStack(Result, Invalid(), OpSize::iInvalid);

  if (StackLoc != 0) {
    _F80StackXchange(StackLoc);
  }
}

// F64 ops
// Float load op with memory operand
void OpDispatchBuilder::FLDF64(OpcodeArgs, IR::OpSize Width) {
  Ref Data = LoadSourceFPR_WithOpSize(Op, Op->Src[0], Width, Op->Flags);
  // Convert to 64bit float
  Ref ConvertedData = Data;
  if (Width == OpSize::i32Bit) {
    ConvertedData = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, Data);
  } else if (Width == OpSize::f80Bit) {
    ConvertedData = _F80CVT(OpSize::i64Bit, Data);
  }
  _PushStack(ConvertedData, Data, Width);
  StoreX87FIP(Op);
}

void OpDispatchBuilder::FBLDF64(OpcodeArgs) {
  // Read from memory
  Ref Data = LoadSourceFPR_WithOpSize(Op, Op->Src[0], OpSize::f80Bit, Op->Flags);
  Ref ConvertedData = _F80BCDLoad(Data);
  ConvertedData = _F80CVT(OpSize::i64Bit, ConvertedData);
  _PushStack(ConvertedData, Invalid(), OpSize::iInvalid);
  StoreX87FIP(Op);
}

void OpDispatchBuilder::FBSTPF64(OpcodeArgs) {
  Ref converted = _F80CVTTo(_ReadStackValue(0), OpSize::i64Bit);
  converted = _F80BCDStore(converted);
  StoreResultFPR_WithOpSize(Op, Op->Dest, converted, OpSize::f80Bit, OpSize::i8Bit);
  _PopStackDestroy();
  StoreX87FIP(Op);
}

void OpDispatchBuilder::FLDF64_Const(OpcodeArgs, uint64_t Num) {
  auto Data = _VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, Constant(Num));
  _PushStack(Data, Data, OpSize::i64Bit);
  StoreX87FIP(Op);
}

void OpDispatchBuilder::FILDF64(OpcodeArgs) {
  const auto ReadWidth = OpSizeFromSrc(Op);

  // Read from memory
  Ref Data = LoadSourceGPR_WithOpSize(Op, Op->Src[0], ReadWidth, Op->Flags);
  if (ReadWidth == OpSize::i16Bit) {
    Data = _Sbfe(OpSize::i64Bit, IR::OpSizeAsBits(ReadWidth), 0, Data);
  }
  auto ConvertedData = _Float_FromGPR_S(OpSize::i64Bit, ReadWidth == OpSize::i32Bit ? OpSize::i32Bit : OpSize::i64Bit, Data);
  if (ReadWidth == OpSize::i64Bit) {
    // A double holds only 53 bits: keep the integer, so that a FISTP m64 of the unchanged value
    // stores it exactly, as 32-bit MSVC's atomic 64-bit load (fild m64; fistp m64) needs.
    _PushStackFromInt64(ConvertedData, _VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, Data));
  } else {
    _PushStack(ConvertedData, Invalid(), OpSize::iInvalid);
  }
  StoreX87FIP(Op);
}

void OpDispatchBuilder::FISTF64(OpcodeArgs, bool Truncate) {
  const auto Size = OpSizeFromSrc(Op);

  Ref data = _ReadStackValue(0);
  bool CanUseFloatReg = Size == OpSize::i64Bit;
  if (CanUseFloatReg) {
    // If possible, it's faster to keep the data in an FPR than doing a GPR transfer.
    if (Truncate) {
      data = _Vector_FToZS(OpSize::i128Bit, OpSize::i64Bit, data);
    } else {
      data = _Vector_FToS(OpSize::i128Bit, OpSize::i64Bit, data);
    }
    // The integer of an unchanged FILD m64, which the conversion would round.
    data = _ReadStackInt64(data);
    StoreResultFPR_WithOpSize(Op, Op->Dest, data, OpSize::i64Bit, OpSize::i8Bit);
  } else {
    if (Truncate) {
      data = _Float_ToGPR_ZS(Size == OpSize::i32Bit ? OpSize::i32Bit : OpSize::i64Bit, OpSize::i64Bit, data);
    } else {
      data = _Float_ToGPR_S(Size == OpSize::i32Bit ? OpSize::i32Bit : OpSize::i64Bit, OpSize::i64Bit, data);
    }
    StoreResultGPR_WithOpSize(Op, Op->Dest, data, Size, OpSize::i8Bit,
                              CTX->IsVectorAtomicTSOEnabled() ? MemoryAccessType::DEFAULT : MemoryAccessType::NONTSO);
  }

  if ((Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) != 0) {
    _PopStackDestroy();
  }
  StoreX87FIP(Op);
}

void OpDispatchBuilder::FADDF64(OpcodeArgs, IR::OpSize Width, bool Integer, OpDispatchBuilder::OpResult ResInST0) {
  if (Op->Src[0].IsNone()) { // Implicit argument case
    auto Offset = Op->OP & 7;
    auto St0 = 0;
    if (ResInST0 == OpResult::RES_STI) {
      _F80AddStack(Offset, St0);
    } else {
      _F80AddStack(St0, Offset);
    }
    X87PrecisionControlF64(ResInST0 == OpResult::RES_STI ? Offset : St0);
    if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
      _PopStackDestroy();
    }
    StoreX87FIP(Op);
    return;
  }

  // We have one memory argument
  Ref arg {};

  if (Integer) {
    arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    if (Width == OpSize::i16Bit) {
      arg = _Sbfe(OpSize::i64Bit, 16, 0, arg);
    }
    arg = _Float_FromGPR_S(OpSize::i64Bit, Width == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, arg);
  } else if (Width == OpSize::i32Bit) {
    arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    arg = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, arg);
  } else if (Width == OpSize::i64Bit) {
    arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  } else {
    FEX_UNREACHABLE;
  }

  // top of stack is at offset zero
  _F80AddValue(0, arg);
  X87PrecisionControlF64(0);
  StoreX87FIP(Op);
}

// FIXME: following is very similar to FADDF64
void OpDispatchBuilder::FMULF64(OpcodeArgs, IR::OpSize Width, bool Integer, OpDispatchBuilder::OpResult ResInST0) {
  if (Op->Src[0].IsNone()) { // Implicit argument case
    auto offset = Op->OP & 7;
    auto st0 = 0;
    if (ResInST0 == OpResult::RES_STI) {
      _F80MulStack(offset, st0);
    } else {
      _F80MulStack(st0, offset);
    }
    X87PrecisionControlF64(ResInST0 == OpResult::RES_STI ? offset : st0);
    if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
      _PopStackDestroy();
    }
    StoreX87FIP(Op);
    return;
  }

  // We have one memory argument
  Ref arg {};

  if (Integer) {
    arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    if (Width == OpSize::i16Bit) {
      arg = _Sbfe(OpSize::i64Bit, 16, 0, arg);
    }
    arg = _Float_FromGPR_S(OpSize::i64Bit, Width == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, arg);
  } else if (Width == OpSize::i32Bit) {
    arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    arg = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, arg);
  } else if (Width == OpSize::i64Bit) {
    arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  } else {
    FEX_UNREACHABLE;
  }

  // top of stack is at offset zero
  _F80MulValue(0, arg);
  X87PrecisionControlF64(0);

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
    _PopStackDestroy();
  }
  StoreX87FIP(Op);
}

void OpDispatchBuilder::FDIVF64(OpcodeArgs, IR::OpSize Width, bool Integer, bool Reverse, OpDispatchBuilder::OpResult ResInST0) {
  if (Op->Src[0].IsNone()) {
    const auto offset = Op->OP & 7;
    const auto st0 = 0;

    if (Reverse) {
      if (ResInST0 == OpResult::RES_STI) {
        _F80DivStack(offset, st0, offset);
      } else {
        _F80DivStack(st0, offset, st0);
      }
    } else {
      if (ResInST0 == OpResult::RES_STI) {
        _F80DivStack(offset, offset, st0);
      } else {
        _F80DivStack(st0, st0, offset);
      }
    }
    X87PrecisionControlF64(ResInST0 == OpResult::RES_STI ? offset : st0);

    if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
      _PopStackDestroy();
    }
    StoreX87FIP(Op);
    return;
  }

  // We have one memory argument
  Ref Arg {};

  if (Width == OpSize::i16Bit || Width == OpSize::i32Bit || Width == OpSize::i64Bit) {
    if (Integer) {
      Arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
      if (Width == OpSize::i16Bit) {
        Arg = _Sbfe(OpSize::i64Bit, 16, 0, Arg);
      }
      Arg = _Float_FromGPR_S(OpSize::i64Bit, Width == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, Arg);
    } else if (Width == OpSize::i32Bit) {
      Arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
      Arg = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, Arg);
    } else if (Width == OpSize::i64Bit) {
      Arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    }
  } else {
    FEX_UNREACHABLE;
  }

  // top of stack is at offset zero
  if (Reverse) {
    _F80DivRValue(Arg, 0);
  } else {
    _F80DivValue(0, Arg);
  }
  X87PrecisionControlF64(0);

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
    _PopStackDestroy();
  }
  StoreX87FIP(Op);
}

void OpDispatchBuilder::FSUBF64(OpcodeArgs, IR::OpSize Width, bool Integer, bool Reverse, OpDispatchBuilder::OpResult ResInST0) {
  if (Op->Src[0].IsNone()) {
    const auto Offset = Op->OP & 7;
    const auto St0 = 0;

    if (Reverse) {
      if (ResInST0 == OpResult::RES_STI) {
        _F80SubStack(Offset, St0, Offset);
      } else {
        _F80SubStack(St0, Offset, St0);
      }
    } else {
      if (ResInST0 == OpResult::RES_STI) {
        _F80SubStack(Offset, Offset, St0);
      } else {
        _F80SubStack(St0, St0, Offset);
      }
    }
    X87PrecisionControlF64(ResInST0 == OpResult::RES_STI ? Offset : St0);

    if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
      _PopStackDestroy();
    }
    StoreX87FIP(Op);

    return;
  }

  // We have one memory argument
  Ref arg {};

  if (Width == OpSize::i16Bit || Width == OpSize::i32Bit || Width == OpSize::i64Bit) {
    if (Integer) {
      arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
      if (Width == OpSize::i16Bit) {
        arg = _Sbfe(OpSize::i64Bit, 16, 0, arg);
      }
      arg = _Float_FromGPR_S(OpSize::i64Bit, Width == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, arg);
    } else if (Width == OpSize::i32Bit) {
      arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
      arg = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, arg);
    } else if (Width == OpSize::i64Bit) {
      arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    }
  } else {
    FEX_UNREACHABLE;
  }

  // top of stack is at offset zero
  if (Reverse) {
    _F80SubRValue(arg, 0);
  } else {
    _F80SubValue(0, arg);
  }
  X87PrecisionControlF64(0);

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
    _PopStackDestroy();
  }
  StoreX87FIP(Op);
}

void OpDispatchBuilder::FTSTF64(OpcodeArgs) {
  // We are going to clobber NZCV, make sure it's in a GPR first.
  SaveNZCV();

  // Now we do our comparison.
  _F80StackTest(0);
  ConvertNZCVToX87();
  StoreX87FIP(Op);
}

void OpDispatchBuilder::FCOMIF64(OpcodeArgs, IR::OpSize Width, bool Integer, OpDispatchBuilder::FCOMIFlags WhichFlags, bool PopTwice) {
  Ref arg {};
  Ref b {};

  if (Op->Src[0].IsNone()) {
    // Implicit arg
    uint8_t offset = Op->OP & 7;
    b = _ReadStackValue(offset);
  } else if (Width == OpSize::i16Bit || Width == OpSize::i32Bit || Width == OpSize::i64Bit) {
    // Memory arg
    if (Integer) {
      arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
      if (Width == OpSize::i16Bit) {
        arg = _Sbfe(OpSize::i64Bit, 16, 0, arg);
      }
      b = _Float_FromGPR_S(OpSize::i64Bit, Width == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, arg);
    } else if (Width == OpSize::i32Bit) {
      arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
      b = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, arg);
    } else if (Width == OpSize::i64Bit) {
      b = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    }
  } else {
    FEX_UNREACHABLE;
  }

  if (WhichFlags == FCOMIFlags::FLAGS_X87) {
    // We are going to clobber NZCV, make sure it's in a GPR first.
    SaveNZCV();

    _F80CmpValue(b);
    ConvertNZCVToX87();
  } else {
    HandleNZCVWrite();
    _F80CmpValue(b);
    ComissFlags();
  }

  if (PopTwice) {
    _PopStackDestroy();
    _PopStackDestroy();
  } else if ((Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) != 0) {
    _PopStackDestroy();
  }
  StoreX87FIP(Op);
}

void OpDispatchBuilder::X87FXTRACTF64(OpcodeArgs) {
  // Split node into SIG and EXP while handling the special zero case.
  // i.e. if val == 0.0, then sig = 0.0, exp = -inf
  // if val == -0.0, then sig = -0.0, exp = -inf
  // if val is +/-Inf, then sig = val, exp = +inf
  // if val is NaN, then sig = val, exp = val
  // otherwise we just extract the 64-bit sig and exp as normal.
  Ref Node = _ReadStackValue(0);

  Ref Gpr = _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, Node, 0);

  // zero case
  Ref ExpZV = _VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, Constant(0xfff0'0000'0000'0000UL));
  Ref SigZV = Node;

  // Inf/NaN case
  Ref ExpInfOnlyV = _VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, Constant(0x7ff0'0000'0000'0000UL));
  Ref ExpNanV = Node;
  Ref SigInfV = Node;

  // non zero case
  Ref ExpNZ = _Bfe(OpSize::i64Bit, 11, 52, Gpr);
  ExpNZ = Sub(OpSize::i64Bit, ExpNZ, Constant(1023));
  Ref ExpNZV = _Float_FromGPR_S(OpSize::i64Bit, OpSize::i64Bit, ExpNZ);

  Ref SigNZ = _And(OpSize::i64Bit, Gpr, Constant(0x800f'ffff'ffff'ffffLL));
  SigNZ = _Or(OpSize::i64Bit, SigNZ, Constant(0x3ff0'0000'0000'0000LL));
  Ref SigNZV = _VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, SigNZ);

  SaveNZCV();

  // Mantissa non-zero => NaN (exp result = input); else Inf (exp result = +Inf)
  Ref Mantissa = _And(OpSize::i64Bit, Gpr, Constant(0x000f'ffff'ffff'ffffULL));
  _TestNZ(OpSize::i64Bit, Mantissa, Constant(~0ULL));
  Ref ExpInfV = _NZCVSelectV(OpSize::i64Bit, CondClass::EQ, ExpInfOnlyV, ExpNanV);

  // Biased exponent == 0x7ff => Inf/NaN path, else non-zero-case.
  Ref BiasedExp = _Bfe(OpSize::i64Bit, 11, 52, Gpr);
  SubWithFlags(OpSize::i64Bit, BiasedExp, 0x7ff);
  Ref ExpNZOrInf = _NZCVSelectV(OpSize::i64Bit, CondClass::EQ, ExpInfV, ExpNZV);
  Ref SigNZOrInf = _NZCVSelectV(OpSize::i64Bit, CondClass::EQ, SigInfV, SigNZV);

  // Zero folds on top.
  _TestNZ(OpSize::i64Bit, Gpr, Constant(0x7fff'ffff'ffff'ffffUL));

  Ref Sig = _NZCVSelectV(OpSize::i64Bit, CondClass::EQ, SigZV, SigNZOrInf);
  Ref Exp = _NZCVSelectV(OpSize::i64Bit, CondClass::EQ, ExpZV, ExpNZOrInf);

  _PopStackDestroy();
  _PushStack(Exp, Invalid(), OpSize::iInvalid);
  _PushStack(Sig, Invalid(), OpSize::iInvalid);
  StoreX87FIP(Op);
}
} // namespace FEXCore::IR
