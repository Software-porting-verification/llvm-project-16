
//===-- trec_interface.cpp
//------------------------------------------------===//
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

#include "trec_interface.h"

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_ptrauth.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "trec_rtl.h"

#define CALLERPC ((uptr)__builtin_return_address(0))
#define PREVCALLERPC \
  (StackTrace::GetPreviousInstructionPc((uptr)__builtin_return_address(0)))
using namespace __trec;
using namespace __trec_metadata;

void __trec_init() {
  cur_thread_init();
  Initialize(cur_thread());
}

void __trec_flush_memory() {}

void __trec_unaligned_read2(const void *addr, bool isPtr, void *val,
                            __sanitizer::u64 sa, __sanitizer::u64 debugID) {
  UnalignedMemoryAccess(cur_thread(), PREVCALLERPC, (uptr)addr, 2, false, false,
                        isPtr, (uptr)val, sa, 0, debugID);
}

void __trec_unaligned_read4(const void *addr, bool isPtr, void *val,
                            __sanitizer::u64 sa, __sanitizer::u64 debugID) {
  UnalignedMemoryAccess(cur_thread(), PREVCALLERPC, (uptr)addr, 4, false, false,
                        isPtr, (uptr)val, sa, 0, debugID);
}

void __trec_unaligned_read8(const void *addr, bool isPtr, void *val,
                            __sanitizer::u64 sa, __sanitizer::u64 debugID) {
  UnalignedMemoryAccess(cur_thread(), PREVCALLERPC, (uptr)addr, 8, false, false,
                        isPtr, (uptr)val, sa, 0, debugID);
}

void __trec_unaligned_write2(void *addr, bool isPtr, void *val,
                             __sanitizer::u64 addr_sa, __sanitizer::u64 val_sa,
                             __sanitizer::u64 debugID) {
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 2, true, false,
                        isPtr, (uptr)val, addr_sa, val_sa, debugID);
}

void __trec_unaligned_write4(void *addr, bool isPtr, void *val,
                             __sanitizer::u64 addr_sa, __sanitizer::u64 val_sa,
                             __sanitizer::u64 debugID) {
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 4, true, false,
                        isPtr, (uptr)val, addr_sa, val_sa, debugID);
}

void __trec_unaligned_write8(void *addr, bool isPtr, void *val,
                             __sanitizer::u64 addr_sa, __sanitizer::u64 val_sa,
                             __sanitizer::u64 debugID) {
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 8, true, false,
                        isPtr, (uptr)val, addr_sa, val_sa, debugID);
}

// __sanitizer_unaligned_load/store are for user instrumentation.
