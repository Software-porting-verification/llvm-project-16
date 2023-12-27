//===-- trec_rtl_mutex.cpp
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

#include <sanitizer_common/sanitizer_deadlock_detector_interface.h>
#include <sanitizer_common/sanitizer_stackdepot.h>

#include "trec_flags.h"
#include "trec_platform.h"
#include "trec_rtl.h"

namespace __trec {

void MutexCreate(ThreadState *thr, uptr pc, uptr addr, u32 flagz) {
  DPrintf("#%d: MutexCreate %zx flagz=0x%x\n", thr->tid, addr, flagz);
}

void MutexDestroy(ThreadState *thr, uptr pc, uptr addr, u32 flagz) {
  DPrintf("#%d: MutexDestroy %zx\n", thr->tid, addr);
}

void MutexPreLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz) {
  DPrintf("#%d: MutexPreLock %zx flagz=0x%x\n", thr->tid, addr, flagz);
}

void MutexPostLock(ThreadState *thr, uptr pc, uptr addr,
                   __trec_metadata::SourceAddressInfo SAI, u32 flagz, int rec) {
  DPrintf("#%d: MutexPostLock %zx flag=0x%x rec=%d\n", thr->tid, addr, flagz,
          rec);
  if (LIKELY(ctx->flags.output_trace) && LIKELY(ctx->flags.record_mutex) &&
      LIKELY(thr->ignore_interceptors == 0)) {
    __trec_metadata::MutexMeta meta(SAI.getAsUInt64());
    thr->tctx->writer.put_record(__trec_trace::EventType::MutexLock,
                                 addr & (((1ULL) << 48) - 1), pc, &meta,
                                 sizeof(meta));
  }
}

void MutexPostWriteLock(ThreadState *thr, uptr pc, uptr addr,
                        __trec_metadata::SourceAddressInfo SAI, u32 flagz,
                        int rec) {
  DPrintf("#%d: MutexPostWriteLock %zx flag=0x%x rec=%d\n", thr->tid, addr,
          flagz, rec);
  if (ctx->flags.record_rwlock) {
    MutexPostLock(thr, pc, addr, SAI, flagz, rec);
  }
}

int MutexUnlock(ThreadState *thr, uptr pc, uptr addr,
                __trec_metadata::SourceAddressInfo SAI, u32 flagz) {
  DPrintf("#%d: MutexUnlock %zx flagz=0x%x\n", thr->tid, addr, flagz);
  if (LIKELY(ctx->flags.output_trace) && LIKELY(ctx->flags.record_mutex) &&
      LIKELY(thr->ignore_interceptors == 0)) {
    __trec_metadata::MutexMeta meta(SAI.getAsUInt64());
    thr->tctx->writer.put_record(__trec_trace::EventType::MutexUnlock,
                                 addr & (((1ULL) << 48) - 1), pc, &meta,
                                 sizeof(meta));
  }

  return 0;
}

void CondWait(ThreadState *thr, uptr pc, uptr cond,
              __trec_metadata::SourceAddressInfo cond_SAI) {
  if (LIKELY(ctx->flags.output_trace) && LIKELY(ctx->flags.record_cond) &&
      LIKELY(thr->ignore_interceptors == 0)) {
    __trec_metadata::CondMeta meta(cond_SAI.getAsUInt64());
    thr->tctx->writer.put_record(__trec_trace::EventType::CondWait,
                                 cond & (((1ULL) << 48) - 1), pc, &meta,
                                 sizeof(meta));
  }
}

void CondSignal(ThreadState *thr, uptr pc, uptr cond, bool is_broadcast,
                __trec_metadata::SourceAddressInfo SAI) {
  if (LIKELY(ctx->flags.output_trace) && LIKELY(ctx->flags.record_cond) &&
      LIKELY(thr->ignore_interceptors == 0)) {
    __trec_metadata::CondMeta meta(SAI.getAsUInt64());
    thr->tctx->writer.put_record(
        is_broadcast ? __trec_trace::EventType::CondBroadcast
                     : __trec_trace::EventType::CondSignal,
        cond & (((1ULL) << 48) - 1), pc, &meta, sizeof(meta));
  }
}

void MutexPreReadLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz) {
  DPrintf("#%d: MutexPreReadLock %zx flagz=0x%x\n", thr->tid, addr, flagz);
}

void MutexPostReadLock(ThreadState *thr, uptr pc, uptr addr,
                       __trec_metadata::SourceAddressInfo SAI, u32 flagz) {
  DPrintf("#%d: MutexPostReadLock %zx flagz=0x%x\n", thr->tid, addr, flagz);
  if (LIKELY(ctx->flags.output_trace) && LIKELY(ctx->flags.record_mutex) &&
      ctx->flags.record_rwlock && LIKELY(thr->ignore_interceptors == 0)) {
    __trec_metadata::MutexMeta meta(SAI.getAsUInt64());
    thr->tctx->writer.put_record(__trec_trace::EventType::ReaderLock,
                                 addr & (((1ULL) << 48) - 1), pc, &meta,
                                 sizeof(meta));
  }
}

void MutexReadOrWriteUnlock(ThreadState *thr, uptr pc, uptr addr,
                            bool is_writer,
                            __trec_metadata::SourceAddressInfo sa) {
  DPrintf("#%d: MutexReadOrWriteUnlock %zx\n", thr->tid, addr);
  if (ctx->flags.record_rwlock) {
    if (is_writer)
      MutexUnlock(thr, pc, addr, sa);
    else {
      if (LIKELY(ctx->flags.output_trace) && LIKELY(ctx->flags.record_mutex) &&
          LIKELY(thr->ignore_interceptors == 0)) {
        __trec_metadata::CondMeta meta(sa.getAsUInt64());
        thr->tctx->writer.put_record(__trec_trace::EventType::ReaderUnlock,
                                     addr & (((1ULL) << 48) - 1), pc, &meta,
                                     sizeof(meta));
      }
    }
  }
}

void MutexRepair(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: MutexRepair %zx\n", thr->tid, addr);
}

void MutexInvalidAccess(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: MutexInvalidAccess %zx\n", thr->tid, addr);
}

void ReleaseStoreAcquire(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: ReleaseStoreAcquire %zx\n", thr->tid, addr);
}

void ReleaseStore(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: ReleaseStore %zx\n", thr->tid, addr);
}

#if !SANITIZER_GO
void AfterSleep(ThreadState *thr, uptr pc) {
  DPrintf("#%d: AfterSleep %zx\n", thr->tid);
  if (thr->ignore_sync)
    return;
}
#endif

}  // namespace __trec
