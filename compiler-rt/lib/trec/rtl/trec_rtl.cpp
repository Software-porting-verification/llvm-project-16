//===-- trec_rtl.cpp
//------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of TraceRecorder (TRec), a race detector.
//
// Main file (entry points) for the TRec run-time.
//===----------------------------------------------------------------------===//

#include "trec_rtl.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <time.h>

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_symbolizer.h"
#include "trec_defs.h"
#include "trec_mman.h"
#include "trec_platform.h"
#include "ubsan/ubsan_init.h"

#ifdef __SSE3__
// <emmintrin.h> transitively includes <stdlib.h>,
// and it's prohibited to include std headers into trec runtime.
// So we do this dirty trick.
#define _MM_MALLOC_H_INCLUDED
#define __MM_MALLOC_H
#include <emmintrin.h>
typedef __m128i m128;
#endif

namespace __trec
{

#if !SANITIZER_GO && !SANITIZER_APPLE
  __attribute__((tls_model("initial-exec")))
  THREADLOCAL char cur_thread_placeholder[sizeof(ThreadState)] ALIGNED(64);
#endif
  static char ctx_placeholder[sizeof(Context)] ALIGNED(64);
  Context *ctx;

  static char thread_registry_placeholder[sizeof(ThreadRegistry)];

  static ThreadContextBase *CreateThreadContext(u32 tid)
  {
    void *mem = internal_alloc(MBlockThreadContex, sizeof(ThreadContext));
    return new (mem) ThreadContext(tid);
  }

#if !SANITIZER_GO
  static const u32 kThreadQuarantineSize = 16;
#else
  static const u32 kThreadQuarantineSize = 64;
#endif

  Context::Context()
      : initialized(),
        pid(internal_getpid()),
        thread_registry(new(thread_registry_placeholder) ThreadRegistry(
            CreateThreadContext, kMaxTid, kThreadQuarantineSize, kMaxTidReuse)),
        temp_dir_path(nullptr) {}

  int Context::CopyFile(const char *src_path, const char *dest_path)
  {
    char *read_buff = (char *)internal_alloc(
        MBlockShadowStack, TREC_BUFFER_SIZE); // buffer size:32M
    int src_fd = internal_open(src_path, O_RDONLY);
    int dest_fd = internal_open(dest_path, O_CREAT | O_WRONLY | O_TRUNC, 0700);
    if (src_fd < 0 || dest_fd < 0)
      return 1;
    uptr read_bytes = 0;
    while ((read_bytes = internal_read(src_fd, read_buff, TREC_BUFFER_SIZE)) >
           0)
    {
      while (read_bytes > 0)
      {
        char *buff_pos = read_buff;
        uptr write_bytes = internal_write(dest_fd, buff_pos, read_bytes);
        if (write_bytes == (uptr)-1 && errno != EINTR)
        {
          Report("Failed to copy file from %s to %s, errno=%u\n", src_path,
                 dest_path, errno);
          Die();
        }
        else
        {
          read_bytes -= write_bytes;
          buff_pos += write_bytes;
        }
      }
    }
    internal_close(src_fd);
    internal_close(dest_fd);
    internal_free(read_buff);
    return 0;
  }

  void Context::CopyDir(const char *path, int Maintid)
  {
    char parent_path[TREC_DIR_PATH_LEN];
    internal_snprintf(parent_path, TREC_DIR_PATH_LEN - 1, "%s/trec_%lu",
                      trace_dir, internal_getpid());
    char src_path[2 * TREC_DIR_PATH_LEN], dest_path[2 * TREC_DIR_PATH_LEN];

    if (mkdir(path, 0700))
    {
      Report("Create temp directory failed\n");
      Die();
    }

    internal_snprintf(dest_path, 2 * TREC_DIR_PATH_LEN - 1, "%s/header", path);
    if (mkdir(dest_path, 0700))
    {
      Report("Create temp header directory failed\n");
      Die();
    }
    internal_snprintf(dest_path, 2 * TREC_DIR_PATH_LEN - 1, "%s/metadata", path);
    if (mkdir(dest_path, 0700))
    {
      Report("Create temp metadata directory failed\n");
      Die();
    }
    internal_snprintf(dest_path, 2 * TREC_DIR_PATH_LEN - 1, "%s/trace", path);
    if (mkdir(dest_path, 0700))
    {
      Report("Create temp trace directory failed\n");
      Die();
    }

    internal_snprintf(src_path, 2 * TREC_DIR_PATH_LEN - 1, "%s/header/%u.bin",
                      parent_path, Maintid);
    internal_snprintf(dest_path, 2 * TREC_DIR_PATH_LEN - 1, "%s/header/%u.bin",
                      path, Maintid);

    if (CopyFile(src_path, dest_path))
    {
      Report("Parent copy bin header failed\n");
      Die();
    }
    internal_snprintf(src_path, 2 * TREC_DIR_PATH_LEN - 1,
                      "%s/header/modules_%u.txt", parent_path, Maintid);
    internal_snprintf(dest_path, 2 * TREC_DIR_PATH_LEN - 1,
                      "%s/header/modules_%u.txt", path, Maintid);
    if (CopyFile(src_path, dest_path))
    {
      Report("Parent copy module file failed\n");
      Die();
    }

    internal_snprintf(src_path, 2 * TREC_DIR_PATH_LEN - 1, "%s/metadata/%u.bin",
                      parent_path, Maintid);
    internal_snprintf(dest_path, 2 * TREC_DIR_PATH_LEN - 1, "%s/metadata/%u.bin",
                      path, Maintid);
    if (CopyFile(src_path, dest_path))
    {
      Report("Parent copy metadata file failed\n");
      Die();
    }
    internal_snprintf(src_path, 2 * TREC_DIR_PATH_LEN - 1, "%s/trace/%u.bin",
                      parent_path, Maintid);
    internal_snprintf(dest_path, 2 * TREC_DIR_PATH_LEN - 1, "%s/trace/%u.bin",
                      path, Maintid);
    if (CopyFile(src_path, dest_path))
    {
      Report("Parent copy trace file failed\n");
      Die();
    }

    return;
  }

  void Context::InheritDir(const char *path, uptr _pid)
  {
    char dirpath[TREC_DIR_PATH_LEN];
    internal_snprintf(dirpath, TREC_DIR_PATH_LEN - 1, "%s/trec_%lu", trace_dir,
                      _pid);
    if (internal_rename(path, dirpath))
    {
      Report("Child inherit directory failed\n");
      Die();
    }
    return;
  }

  void Context::open_directory(const char *dirpath)
  {
    // open or create
    char path[TREC_DIR_PATH_LEN];
    internal_snprintf(path, TREC_DIR_PATH_LEN - 1, "%s/trec_%lu", dirpath,
                      internal_getpid());

    struct stat _st = {0};
    open_dir_mutex.Lock();
    uptr IS_EXISTS = __sanitizer::internal_stat(path, &_st);
    char filepath[TREC_DIR_PATH_LEN];
    if (IS_EXISTS == 0)
    {
      open_dir_mutex.Unlock();
      return;
    }
    else
    {
      if (mkdir(path, ACCESSPERMS) != 0)
      {
        Report(
            "Could not create directory at %s, errno=%d, exists=%lu, is_dir=%d\n",
            path, errno, IS_EXISTS, S_ISDIR(_st.st_mode));
        Die();
      }
    }
    internal_snprintf(filepath, TREC_DIR_PATH_LEN - 1, "%s/%s", path, "trace");
    if (mkdir(filepath, ACCESSPERMS) != 0)
    {
      Report("Could not create trace directory at %s, errno=%d\n", filepath,
             errno);
      Die();
    }

    internal_snprintf(filepath, TREC_DIR_PATH_LEN - 1, "%s/%s", path, "metadata");
    if (mkdir(filepath, ACCESSPERMS) != 0)
    {
      Report("Could not create metadata directory at %s, errno=%d\n", filepath,
             errno);
      Die();
    }

    internal_snprintf(filepath, TREC_DIR_PATH_LEN - 1, "%s/%s", path, "header");
    if (mkdir(filepath, ACCESSPERMS) != 0)
    {
      Report("Could not create header directory at %s, errno=%d\n", filepath,
             errno);
      Die();
    }
    open_dir_mutex.Unlock();
  }

  // The objects are allocated in TLS, so one may rely on zero-initialization.
  ThreadState::ThreadState(Context *ctx, int tid, int unique_id)
      : tid(tid), unique_id(unique_id) {}

#if !SANITIZER_GO

  static void OnStackUnwind(const SignalContext &sig, const void *,
                            BufferedStackTrace *stack)
  {
    stack->Unwind(StackTrace::GetNextInstructionPc(sig.pc), sig.bp, sig.context,
                  common_flags()->fast_unwind_on_fatal);
  }
  void TrecFlushTraceOnDead()
  {
    uptr num_threads = 0;
    ctx->thread_registry->GetNumberOfThreads(&num_threads);
    ctx->thread_registry->Lock();
    for (uptr tid = 0; tid < num_threads; tid++)
    {
      ThreadContext *tctx =
          (ThreadContext *)ctx->thread_registry->GetThreadLocked(tid);
      if (tctx &&
          tctx->status == __sanitizer::ThreadStatus::ThreadStatusRunning)
      {
        // quickly flush all threads
        if (ctx->flags.output_trace)
          tctx->writer.flush_all();
        tctx->writer.setEnd();
        tctx->writer.reset();
      }
    }
    ctx->thread_registry->Unlock();
  }

  static void TrecOnDeadlySignal(int signo, void *siginfo, void *context)
  {
    TrecFlushTraceOnDead();
    if (ctx->flags.print_debug_on_dead)
      HandleDeadlySignal(siginfo, context, GetTid(), &OnStackUnwind, nullptr);
    Die();
  }
#endif

  void TrecCheckFailed(const char *file, int line, const char *cond, u64 v1,
                       u64 v2)
  {
    // There is high probability that interceptors will check-fail as well,
    // on the other hand there is no sense in processing interceptors
    // since we are going to die soon.
    ScopedIgnoreInterceptors ignore;
#if !SANITIZER_GO
    cur_thread()->ignore_sync++;
    cur_thread()->ignore_reads_and_writes++;
#endif
    Printf(
        "FATAL: TraceRecorder CHECK failed: "
        "%s:%d \"%s\" (0x%zx, 0x%zx)\n",
        file, line, cond, (uptr)v1, (uptr)v2);
    Die();
  }

  void Initialize(ThreadState *thr)
  {
    // Thread safe because done before all threads exist.
    static bool is_initialized = false;
    if (is_initialized)
      return;
    is_initialized = true;
    // We are not ready to handle interceptors yet.
    ScopedIgnoreInterceptors ignore;
    SanitizerToolName = "TraceRecorder";

    ctx = new (ctx_placeholder) Context;
    const char *env_name = SANITIZER_GO ? "GORACE" : "TREC_OPTIONS";
    const char *options = GetEnv(env_name);
    CacheBinaryName();
    CheckASLR();
    InitializeFlags(&ctx->flags, options, env_name);
    AvoidCVE_2016_2143();
    __sanitizer::InitializePlatformEarly();
    __trec::InitializePlatformEarly();

#if !SANITIZER_GO

    InitializeAllocator();
    ReplaceSystemMalloc();
#endif
    Processor *proc = ProcCreate();
    ProcWire(proc, thr);
    InitializeInterceptors();
    InitializePlatform();
#if !SANITIZER_GO
    InitializeAllocatorLate();

    // Do not install SEGV handler
    InstallDeadlySignalHandlers(TrecOnDeadlySignal);
    if (common_flags()->use_sigaltstack)
      SetAlternateSignalStack();
#endif
    // Setup correct file descriptor for error reports.
    // __sanitizer_set_report_path(common_flags()->log_path);

    VPrintf(1, "***** Running under TraceRecorder v2 (pid %d) *****\n",
            (int)internal_getpid());

    // Initialize thread 0.
    int tid = ThreadCreate(thr, 0, 0, true);
    CHECK_EQ(tid, 0);
    ThreadStart(thr, tid, GetTid(), ThreadType::Regular);
    ctx->initialized = true;

#if !SANITIZER_GO
    {
      // symbolizer calls interceptors, ignore them
      ScopedIgnoreInterceptors ignore;
      Symbolizer::LateInitialize();
    }
#endif
  }

  int Finalize(ThreadState *thr)
  {
    if (flags()->atexit_sleep_ms > 0 && ThreadCount(thr) > 1)
      SleepForMillis(flags()->atexit_sleep_ms);

    ThreadFinalize(thr);
    // gyq: always exit with code 0
    return 0;
  }

#if !SANITIZER_GO
  void ForkBefore(ThreadState *thr, uptr pc)
  {
    ctx->thread_registry->Lock();
    if (ctx->flags.output_trace)
    {
      thr->tctx->writer.flush_all();
      thr->tctx->writer.reset();
      unsigned int cur_forked_cnt =
          atomic_fetch_add(&ctx->forked_cnt, 1, memory_order_relaxed);
      if (!ctx->temp_dir_path)
        internal_free(ctx->temp_dir_path);
      ctx->temp_dir_path =
          (char *)internal_alloc(MBlockShadowStack, TREC_DIR_PATH_LEN);
      internal_snprintf(ctx->temp_dir_path, TREC_DIR_PATH_LEN - 1,
                        "%s/temp_%lu_%d", ctx->trace_dir, internal_getpid(),
                        cur_forked_cnt);

      ctx->CopyDir(ctx->temp_dir_path, thr->tid);
    }
  }

  void ForkParentAfter(ThreadState *thr, uptr pc)
  {
    ctx->thread_registry->Unlock();
  }

  void ForkChildAfter(ThreadState *thr, uptr pc)
  {
    ctx->thread_registry->Unlock();

    uptr nthread = 0;
    ctx->thread_registry->GetNumberOfThreads(0, 0, &nthread /* alive threads */);
    VPrintf(1,
            "TraceRecorder: forked new process with pid %d,"
            " parent had %d threads\n",
            (int)internal_getpid(), (int)nthread);
    if (ctx->flags.output_trace && ctx->temp_dir_path)
    {
      ctx->InheritDir(ctx->temp_dir_path, internal_getpid());
      ctx->thread_after_fork = true;
      internal_free(ctx->temp_dir_path);
      ctx->temp_dir_path = nullptr;
    }
  }
#endif

  void UnalignedMemoryAccess(ThreadState *thr, uptr pc, uptr addr, int size,
                             bool kAccessIsWrite, bool kIsAtomic, bool isPtr,
                             uptr val,
                             __trec_metadata::SourceAddressInfo SAI_addr,
                             __trec_metadata::SourceAddressInfo SAI_val,
                             __sanitizer::u64 debugID)
  {
    int kAccessSizeLog;
    switch (size)
    {
    case 1:
      kAccessSizeLog = kSizeLog1;
      break;
    case 2:
      kAccessSizeLog = kSizeLog2;
      break;
    case 4:
      kAccessSizeLog = kSizeLog4;
      break;
    case 8:
      kAccessSizeLog = kSizeLog8;
      break;
    default:
      kAccessSizeLog = kSizeLog1;
    }

    MemoryAccess(thr, pc, addr, kAccessSizeLog, kAccessIsWrite, kIsAtomic, isPtr,
                 val, SAI_addr, SAI_val, debugID);
  }
  void RegisterThreadCreate(ThreadState *thr, u64 arg_val, u64 arg_debugID, u64 debugID)
  {
    if (thr->tctx->createArgs)
      internal_free(thr->tctx->createArgs);
    thr->tctx->createArgs = (TrecThreadCreateArgs *)internal_alloc(MBlockShadowStack, sizeof(TrecThreadCreateArgs));
    thr->tctx->createArgs->arg_val = arg_val;
    thr->tctx->createArgs->arg_debugID = arg_debugID;
    thr->tctx->createArgs->debugID = debugID;
  }
  ALWAYS_INLINE USED void Setjmp(ThreadState *thr, uptr pc, uptr jmpbuf)
  {
    if (LIKELY(ctx->flags.output_trace))
    {
      thr->tctx->writer.put_record(__trec_trace::EventType::Setjmp,
                                   (jmpbuf) & ((1ULL << 48) - 1), pc);
    }
  }

  ALWAYS_INLINE USED void Longjmp(ThreadState *thr, uptr pc, uptr jmpbuf)
  {
    if (LIKELY(ctx->flags.output_trace))
    {
      thr->tctx->writer.put_record(__trec_trace::EventType::Longjmp,
                                   (jmpbuf) & ((1ULL << 48) - 1), pc);
    }
  }
  ALWAYS_INLINE USED void CondBranch(ThreadState *thr, uptr pc,
                                     __sanitizer::uptr cond,
                                     __trec_metadata::SourceAddressInfo sa,
                                     __sanitizer::u64 debugID)
  {
    if (LIKELY(ctx->flags.output_trace) && LIKELY(ctx->flags.record_branch) &&
        LIKELY(thr->ignore_interceptors == 0))
    {
      __trec_metadata::BranchMeta meta(sa.getAsUInt64(), debugID);
      thr->tctx->writer.put_record(__trec_trace::EventType::Branch, cond, pc,
                                   &meta, sizeof(meta));
    }
  }

  ALWAYS_INLINE USED void FuncParam(ThreadState *thr, u16 param_idx,
                                    __trec_metadata::SourceAddressInfo sa,
                                    uptr val, __sanitizer::u64 debugID)
  {
    if (LIKELY(ctx->flags.output_trace) &&
        LIKELY(ctx->flags.record_func_enter_exit) &&
        LIKELY(ctx->flags.record_func_param) &&
        LIKELY(thr->ignore_interceptors == 0))
    {
      thr->tctx->writer.pend_param(param_idx, sa, val, debugID);
    }
  }

  ALWAYS_INLINE USED void FuncExitParam(ThreadState *thr,
                                        __trec_metadata::SourceAddressInfo sa,
                                        uptr val, __sanitizer::u64 debugID)
  {
    if (LIKELY(ctx->flags.output_trace) &&
        LIKELY(ctx->flags.record_func_enter_exit) &&
        LIKELY(ctx->flags.record_func_param) &&
        LIKELY(thr->ignore_interceptors == 0))
    {
      thr->tctx->writer.pend_param(0, sa, val, debugID);
    }
  }

  ALWAYS_INLINE USED void MemoryAccess(
      ThreadState *thr, uptr pc, uptr addr, int kAccessSizeLog,
      bool kAccessIsWrite, bool kIsAtomic, bool isPtr, uptr val,
      __trec_metadata::SourceAddressInfo SAI_addr,
      __trec_metadata::SourceAddressInfo SAI_val, __sanitizer::u64 debugID)
  {
    if (LIKELY(ctx->flags.output_trace) &&
        LIKELY(thr->ignore_interceptors == 0))
    {
      if (kAccessIsWrite && LIKELY(ctx->flags.record_write))
      {
        __trec_trace::EventType type;
        if (kIsAtomic)
        {
          if (isPtr)
            type = __trec_trace::EventType::AtomicPtrWrite;
          else
            type = __trec_trace::EventType::AtomicPlainWrite;
        }
        else
        {
          if (isPtr)
            type = __trec_trace::EventType::PtrWrite;
          else
            type = __trec_trace::EventType::PlainWrite;
        }

        __trec_metadata::WriteMeta meta(val, SAI_addr, SAI_val, debugID);

        thr->tctx->writer.put_record(
            type,
            (((1ULL) << (kAccessSizeLog + 48)) | (addr & (((1ULL) << 48) - 1))),
            pc, &meta, sizeof(meta));
      }
      else if (!kAccessIsWrite && LIKELY(ctx->flags.record_read))
      {
        __trec_trace::EventType type;
        if (kIsAtomic)
        {
          if (isPtr)
            type = __trec_trace::EventType::AtomicPtrRead;
          else
            type = __trec_trace::EventType::AtomicPlainRead;
        }
        else
        {
          if (isPtr)
            type = __trec_trace::EventType::PtrRead;
          else
            type = __trec_trace::EventType::PlainRead;
        }
        __trec_metadata::ReadMeta meta(val, SAI_addr, debugID);
        thr->tctx->writer.put_record(
            type,
            (((1ULL) << (kAccessSizeLog + 48)) | (addr & (((1ULL) << 48) - 1))),
            pc, &meta, sizeof(meta));
      }
    }
  }

  ALWAYS_INLINE USED void RecordFuncEntry(ThreadState *thr,
                                          __sanitizer::u16 order,
                                          __sanitizer::u16 arg_cnt,
                                          __sanitizer::u64 debugID,
                                          __sanitizer::u64 pc)
  {
    if (LIKELY(ctx->flags.output_trace) &&
        LIKELY(ctx->flags.record_func_enter_exit) &&
        LIKELY(thr->ignore_interceptors == 0))
    {
      __trec_metadata::FuncMeta meta(debugID);
      thr->tctx->writer.put_record(__trec_trace::EventType::FuncEnter,
                                   (((__sanitizer::u64)order) << 16) | arg_cnt,
                                   pc, &meta, sizeof(meta));
    }
  }

  ALWAYS_INLINE USED void RecordFuncExit(ThreadState *thr,
                                         __sanitizer::u64 debugID,
                                         __sanitizer::u64 pc)
  {
    if (LIKELY(ctx->flags.output_trace) &&
        LIKELY(ctx->flags.record_func_enter_exit) &&
        LIKELY(thr->ignore_interceptors == 0))
    {
      __trec_metadata::FuncMeta meta(debugID);
      thr->tctx->writer.put_record(__trec_trace::EventType::FuncExit, 0, pc,
                                   &meta, sizeof(meta));
    }
  }

} // namespace __trec

#if !SANITIZER_GO
// Must be included in this file to make sure everything is inlined.
#include "trec_interface_inl.h"
#endif

#if !SANITIZER_GO
void __sanitizer::BufferedStackTrace::UnwindImpl(uptr pc, uptr bp,
                                                 void *context,
                                                 bool request_fast,
                                                 u32 max_depth)
{
  uptr top = 0;
  uptr bottom = 0;
  if (StackTrace::WillUseFastUnwind(request_fast))
  {
    GetThreadStackTopAndBottom(false, &top, &bottom);
    Unwind(max_depth, pc, bp, nullptr, top, bottom, true);
  }
  else
    Unwind(max_depth, pc, 0, context, 0, 0, false);
}
#endif // SANITIZER_GO
