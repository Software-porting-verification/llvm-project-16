//===-- trec_interface_inl.h ------------------------------------*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of TraceRecorder (TRec), a race detector.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_ptrauth.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "trec_interface.h"
#include "trec_rtl.h"

#define CALLERPC ((uptr)__builtin_return_address(0))
#define PREVCALLERPC \
  (StackTrace::GetPreviousInstructionPc((uptr)__builtin_return_address(0)))
using namespace __trec;
using namespace __trec_metadata;
void __trec_branch(void *cond, __sanitizer::u64 sa, __sanitizer::u64 debugID)
{
  CondBranch(cur_thread(), CALLERPC, (uptr)cond, sa, debugID);
}

void __trec_func_param(u16 param_idx, __sanitizer::u64 sa, void *val,
                       __sanitizer::u64 debugID)
{
  FuncParam(cur_thread(), param_idx, sa, (uptr)val, debugID);
}

void __trec_thread_create(void *arg_val, __sanitizer::u64 arg_debugID, __sanitizer::u64 debugID)
{
  RegisterThreadCreate(cur_thread(), (uptr)arg_val, arg_debugID, debugID);
}

void __trec_func_exit_param(__sanitizer::u64 sa, void *val,
                            __sanitizer::u64 debugID)
{
  FuncExitParam(cur_thread(), sa, (uptr)val, debugID);
}

void __trec_read1(void *addr, bool isPtr, void *val, u64 sai, u64 debugID)
{
  MemoryRead(cur_thread(), PREVCALLERPC, (uptr)addr, kSizeLog1, isPtr,
             (uptr)val, sai, debugID);
}

void __trec_read2(void *addr, bool isPtr, void *val, u64 sai, u64 debugID)
{
  MemoryRead(cur_thread(), PREVCALLERPC, (uptr)addr, kSizeLog2, isPtr,
             (uptr)val, sai, debugID);
}

void __trec_read4(void *addr, bool isPtr, void *val, u64 sai, u64 debugID)
{
  MemoryRead(cur_thread(), PREVCALLERPC, (uptr)addr, kSizeLog4, isPtr,
             (uptr)val, sai, debugID);
}

void __trec_read8(void *addr, bool isPtr, void *val, u64 sai, u64 debugID)
{
  MemoryRead(cur_thread(), PREVCALLERPC, (uptr)addr, kSizeLog8, isPtr,
             (uptr)val, sai, debugID);
}

void __trec_write1(void *addr, bool isPtr, void *val, __sanitizer::u64 addr_sa,
                   __sanitizer::u64 val_sa, __sanitizer::u64 debugID)
{
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, kSizeLog1, isPtr, (uptr)val,
              addr_sa, val_sa, debugID);
}

void __trec_write2(void *addr, bool isPtr, void *val, __sanitizer::u64 addr_sa,
                   __sanitizer::u64 val_sa, __sanitizer::u64 debugID)
{
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, kSizeLog2, isPtr, (uptr)val,
              addr_sa, val_sa, debugID);
}

void __trec_write4(void *addr, bool isPtr, void *val, __sanitizer::u64 addr_sa,
                   __sanitizer::u64 val_sa, __sanitizer::u64 debugID)
{
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, kSizeLog4, isPtr, (uptr)val,
              addr_sa, val_sa, debugID);
}

void __trec_write8(void *addr, bool isPtr, void *val, __sanitizer::u64 addr_sa,
                   __sanitizer::u64 val_sa, __sanitizer::u64 debugID)
{
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, kSizeLog8, isPtr, (uptr)val,
              addr_sa, val_sa, debugID);
}

void __trec_func_entry(__sanitizer::u16 order, __sanitizer::u16 arg_cnt,
                       __sanitizer::u64 debugID)
{
  RecordFuncEntry(cur_thread(), order, arg_cnt, debugID, CALLERPC);
}

void __trec_func_exit(__sanitizer::u64 debugID)
{
  RecordFuncExit(cur_thread(), debugID, PREVCALLERPC);
}
