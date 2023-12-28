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

#define CALLERPC \
  (StackTrace::GetPreviousInstructionPc((uptr)__builtin_return_address(0)))

using namespace __trec;
using namespace __trec_metadata;

void __trec_inst_debug_info(u64 fid, u32 line, u16 col, u64 time, u32 nameID1,
                            u32 nameID2) {
  if (LIKELY(ctx->flags.output_trace) && LIKELY(ctx->flags.output_debug) &&
      LIKELY(cur_thread()->ignore_interceptors == 0))
    if ((ctx->flags.trace_mode == 2 || ctx->flags.trace_mode == 3)) {
      __trec_debug_info::InstDebugInfo info(fid, line, col, time, nameID1,
                                            nameID2);
      ThreadState *thr = cur_thread();
      internal_memcpy(thr->tctx->dbg_temp_buffer, &info, sizeof(info));
      thr->tctx->dbg_temp_buffer_size = sizeof(info);
    }
}
void __trec_setjmp(void *jmpbuf) {
  bool should_record = true;
  if (!IsTrecBBL(cur_thread(), should_record)) {
    RecordSetLongJmp(cur_thread(), should_record, true,
                     StackTrace::GetPreviousInstructionPc(GET_CALLER_PC()),
                     (u64)jmpbuf);
  }
}

void __trec_longjmp(void *jmpbuf) {
  bool should_record = true;
  if (!IsTrecBBL(cur_thread(), should_record)) {
    RecordSetLongJmp(cur_thread(), should_record, false,
                     StackTrace::GetPreviousInstructionPc(GET_CALLER_PC()),
                     (u64)jmpbuf);
  }
}

bool __trec_func_entry() {
  bool should_record = true;
  if (!IsTrecBBL(cur_thread(), should_record)) {
    return RecordFuncEntry(cur_thread(), should_record,
                    StackTrace::GetPreviousInstructionPc(GET_CALLER_PC()));
  }
}

void __trec_func_exit(bool is_record_trace) {
  bool should_record = true;
  if (!IsTrecBBL(cur_thread(), should_record)) {
    RecordFuncExit(cur_thread(), should_record, is_record_trace);
  }
}

void __trec_bbl_entry() {
  bool should_record = true;
  RecordBBLEntry(cur_thread(), should_record);
}

void __trec_bbl_exit() {
  bool should_record = true;
  RecordBBLExit(cur_thread(), should_record);
}

bool __is_trec_bbl() {
  bool should_record = true;
  return IsTrecBBL(cur_thread(), should_record);
}
