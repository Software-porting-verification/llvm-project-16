//===-- trec_rtl.h ----------------------------------------------*- C++
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
// Main internal TRec header file.
//
// Ground rules:
//   - C++ run-time should not be used (static CTORs, RTTI, exceptions, static
//     function-scope locals)
//   - All functions/classes/etc reside in namespace __trec, except for
//   those
//     declared in trec_interface.h.
//   - Platform-specific files should be used instead of ifdefs (*).
//   - No system headers included in header files (*).
//   - Platform specific headres included only into platform-specific files (*).
//
//  (*) Except when inlining is critical for performance.
//===----------------------------------------------------------------------===//

#ifndef TREC_RTL_H
#define TREC_RTL_H

#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_asm.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_deadlock_detector_interface.h"
#include "sanitizer_common/sanitizer_libignore.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_suppressions.h"
#include "sanitizer_common/sanitizer_thread_registry.h"
#include "sanitizer_common/sanitizer_vector.h"
#include "trec_defs.h"
#include "trec_flags.h"
#include "trec_mman.h"
#include "trec_platform.h"
using namespace __sanitizer;

#if SANITIZER_WORDSIZE != 64 && !defined(__i386__) && !defined(__riscv)
#error "TraceRecorder is supported only on 64-bit platforms"
#endif

namespace __trec
{

#if !SANITIZER_GO
  struct MapUnmapCallback;
#if defined(__mips64) || defined(__aarch64__) || defined(__powerpc__) || \
    defined(__i386__)

  struct AP32
  {
    static const uptr kSpaceBeg = 0;
    static const u64 kSpaceSize = SANITIZER_MMAP_RANGE_SIZE;
    static const uptr kMetadataSize = 0;
    typedef __sanitizer::CompactSizeClassMap SizeClassMap;
    static const uptr kRegionSizeLog = 20;
    using AddressSpaceView = LocalAddressSpaceView;
    typedef __trec::MapUnmapCallback MapUnmapCallback;
    static const uptr kFlags = 0;
  };
  typedef SizeClassAllocator32<AP32> PrimaryAllocator;
#else
  struct AP64
  { // Allocator64 parameters. Deliberately using a short name.
#if defined(__riscv)
    static const uptr kSpaceBeg = ~(uptr)0;
    static const uptr kSpaceSize = 0x2000000000ULL; // 128G.
    typedef VeryDenseSizeClassMap SizeClassMap;
#else
    static const uptr kSpaceBeg = Mapping::kHeapMemBeg;
    static const uptr kSpaceSize = Mapping::kHeapMemEnd - Mapping::kHeapMemBeg;
    typedef DefaultSizeClassMap SizeClassMap;
#endif
    static const uptr kMetadataSize = 0;
    typedef __trec::MapUnmapCallback MapUnmapCallback;
    static const uptr kFlags = 0;
    using AddressSpaceView = LocalAddressSpaceView;
  };
  typedef SizeClassAllocator64<AP64> PrimaryAllocator;
#endif
  typedef CombinedAllocator<PrimaryAllocator> Allocator;
  typedef Allocator::AllocatorCache AllocatorCache;
  Allocator *allocator();
#endif

  struct ThreadSignalContext;

  // A Processor represents a physical thread, or a P for Go.
  // It is used to store internal resources like allocate cache, and does not
  // participate in race-detection logic (invisible to end user).
  // In C++ it is tied to an OS thread just like ThreadState, however ideally
  // it should be tied to a CPU (this way we will have fewer allocator caches).
  // In Go it is tied to a P, so there are significantly fewer Processor's than
  // ThreadState's (which are tied to Gs).
  // A ThreadState must be wired with a Processor to handle events.
  struct Processor
  {
    ThreadState *thr; // currently wired thread, or nullptr
#if !SANITIZER_GO
    AllocatorCache alloc_cache;
    InternalAllocatorCache internal_alloc_cache;
#endif
  };

#if !SANITIZER_GO
  // ScopedGlobalProcessor temporary setups a global processor for the current
  // thread, if it does not have one. Intended for interceptors that can run
  // at the very thread end, when we already destroyed the thread processor.
  struct ScopedGlobalProcessor
  {
    ScopedGlobalProcessor();
    ~ScopedGlobalProcessor();
  };
#endif

  // This struct is stored in TLS.
  struct ThreadState
  {
    // Technically `current` should be a separate THREADLOCAL variable;
    // but it is placed here in order to share cache line with previous fields.
    ThreadState *current;
    // This is a slow path flag. On fast path, fast_state.GetIgnoreBit() is read.
    // We do not distinguish beteween ignoring reads and writes
    // for better performance.
    int ignore_reads_and_writes;
    int ignore_sync;
    // Go does not support ignores.
#if !SANITIZER_GO
    int ignore_interceptors;
#endif
    const int tid;
    const int unique_id;
    bool is_inited;
    bool is_dead;
    bool is_freeing;
    bool is_vptr_access;
    ThreadContext *tctx;

    // Current wired Processor, or nullptr. Required to handle any events.
    Processor *proc1;
#if !SANITIZER_GO
    Processor *proc() { return proc1; }
#else
    Processor *proc();
#endif

    atomic_uintptr_t in_signal_handler;
    ThreadSignalContext *signal_ctx;

    // Set in regions of runtime that must be signal-safe and fork-safe.
    // If set, malloc must not be called.
    int nomalloc;

    explicit ThreadState(Context *ctx, int tid, int unique_id);
  };

#if !SANITIZER_GO
#if SANITIZER_APPLE || SANITIZER_ANDROID
  ThreadState *cur_thread();
  void set_cur_thread(ThreadState *thr);
  void cur_thread_finalize();
  inline void cur_thread_init() {}
#else
  __attribute__((tls_model(
      "initial-exec"))) extern THREADLOCAL char cur_thread_placeholder[];
  inline ThreadState *cur_thread()
  {
    return reinterpret_cast<ThreadState *>(cur_thread_placeholder)->current;
  }
  inline ThreadState *cur_thread_init()
  {
    ThreadState *thr = reinterpret_cast<ThreadState *>(cur_thread_placeholder);
    if (UNLIKELY(!thr->current))
      thr->current = thr;
    return thr;
  }
  inline void set_cur_thread(ThreadState *thr)
  {
    reinterpret_cast<ThreadState *>(cur_thread_placeholder)->current = thr;
  }
  inline void cur_thread_finalize() {}
#endif // SANITIZER_APPLE || SANITIZER_ANDROID
#endif // SANITIZER_GO
  class TrecMutexGuard
  {
    __sanitizer::Mutex &m;

  public:
    TrecMutexGuard(__sanitizer::Mutex &_m) : m(_m) { m.Lock(); }
    ~TrecMutexGuard() { m.Unlock(); }
  };
  class TraceWriter
  {
    __sanitizer::u16 id;
    char *trace_buffer = nullptr, *metadata_buffer = nullptr;
    __sanitizer::u64 trace_len = 0, metadata_len = 0;
    __trec_header::TraceHeader header;
    __sanitizer::Mutex mtx;
    DenseMap<__sanitizer::u16, __trec_metadata::FuncParamMeta> params;
    bool is_end;
    void put_trace(__trec_trace::Event &e);
    void put_metadata(void *msg, __sanitizer::u16 len);
    void flush_trace();
    void flush_metadata();
    void flush_header();

  public:
    TraceWriter(u16 tid);
    ~TraceWriter();
    void put_record(__trec_trace::EventType type, __sanitizer::u64 _oid,
                    __sanitizer::u64 _pc, void *meta = nullptr,
                    __sanitizer::u16 len = 0);

    void flush_all();
    void flush_module();
    bool state_restore();
    void reset();
    void init_cmd();
    void pend_param(__sanitizer::u16 idx, __trec_metadata::SourceAddressInfo sa,
                    __sanitizer::u64 val, __sanitizer::u64 debugID);
    const __trec_trace::Event *getLastEvent() const;
    void setEnd();
  };

  struct TrecThreadCreateArgs
  {
    __sanitizer::u64 arg_val, debugID, arg_debugID, pc;
  };
  class ThreadContext final : public ThreadContextBase
  {
  public:
    explicit ThreadContext(int tid);
    ~ThreadContext();
    ThreadState *thr;
    TrecThreadCreateArgs *createArgs = nullptr;
    TraceWriter writer;

    // Override superclass callbacks.
    void OnDead() override;
    void OnJoined(void *arg) override;
    void OnFinished() override;
    void OnStarted(void *arg) override;
    void OnCreated(void *arg) override;
    void OnReset() override;
    void OnDetached(void *arg) override;
  };

  class Context
  {
  public:
    Context();

    bool initialized;
    pid_t pid;
    pid_t ppid;
    atomic_uint64_t global_id;
    atomic_uint32_t forked_cnt;
    char *temp_dir_path;
    char trace_dir[TREC_DIR_PATH_LEN];
    __sanitizer::Mutex open_dir_mutex;

    ThreadRegistry *thread_registry;

    Flags flags;
    __sanitizer::Mutex mutex;
    bool thread_after_fork = false;

    void open_directory(const char *t);
    void CopyDir(const char *path, int Maintid);
    int CopyFile(const char *src_path, const char *dest_path);
    void InheritDir(const char *path, uptr _pid);
  };

  extern Context *ctx; // The one and the only global runtime context.

  ALWAYS_INLINE Flags *flags() { return &ctx->flags; }

  struct ScopedIgnoreInterceptors
  {
    ScopedIgnoreInterceptors()
    {
#if !SANITIZER_GO
      cur_thread()->ignore_interceptors++;
#endif
    }

    ~ScopedIgnoreInterceptors()
    {
#if !SANITIZER_GO
      cur_thread()->ignore_interceptors--;
#endif
    }
  };

  void InitializeInterceptors();

  void ForkBefore(ThreadState *thr, uptr pc);
  void ForkParentAfter(ThreadState *thr, uptr pc);
  void ForkChildAfter(ThreadState *thr, uptr pc);

#if defined(TREC_DEBUG_OUTPUT) && TREC_DEBUG_OUTPUT >= 1
#define DPrintf Printf
#else
#define DPrintf(...)
#endif

#if defined(TREC_DEBUG_OUTPUT) && TREC_DEBUG_OUTPUT >= 2
#define DPrintf2 Printf
#else
#define DPrintf2(...)
#endif

  void Initialize(ThreadState *thr);
  int Finalize(ThreadState *thr);

  void OnUserAlloc(ThreadState *thr, uptr pc, uptr p, uptr sz, bool write);
  void OnUserFree(ThreadState *thr, uptr pc, uptr p, bool write,
                  bool record_trace = false);

  void Setjmp(ThreadState *thr, uptr pc, uptr jmpbuf);
  void Longjmp(ThreadState *thr, uptr pc, uptr jmpbuf);

  void CondBranch(ThreadState *thr, uptr pc, uptr cond,
                  __trec_metadata::SourceAddressInfo sa,
                  __sanitizer::u64 debugID);
  void FuncParam(ThreadState *thr, u16 param_idx,
                 __trec_metadata::SourceAddressInfo sa, uptr val,
                 __sanitizer::u64 debugID);
  void RegisterThreadCreate(ThreadState *thr, u64 arg_val, u64 arg_debugID, u64 debugID);
  void FuncExitParam(ThreadState *thr, __trec_metadata::SourceAddressInfo sa,
                     uptr val, __sanitizer::u64 debugID);

  void MemoryAccess(ThreadState *thr, uptr pc, uptr addr, int kAccessSizeLog,
                    bool kAccessIsWrite, bool kIsAtomic, bool isPtr, uptr val,
                    __trec_metadata::SourceAddressInfo SAI_addr,
                    __trec_metadata::SourceAddressInfo SAI_val,
                    __sanitizer::u64 debugID);
  void MemoryAccessRange(ThreadState *thr, uptr pc, uptr addr, uptr size,
                         bool is_write,
                         __trec_metadata::SourceAddressInfo SAI = 0);

  void UnalignedMemoryAccess(ThreadState *thr, uptr pc, uptr addr, int size,
                             bool kAccessIsWrite, bool kIsAtomic, bool isPtr,
                             uptr val,
                             __trec_metadata::SourceAddressInfo SAI_addr,
                             __trec_metadata::SourceAddressInfo SAI_val,
                             __sanitizer::u64 debugID);

  const int kSizeLog1 = 0;
  const int kSizeLog2 = 1;
  const int kSizeLog4 = 2;
  const int kSizeLog8 = 3;

  void ALWAYS_INLINE MemoryRead(ThreadState *thr, uptr pc, uptr addr,
                                int kAccessSizeLog, bool isPtr, uptr val,
                                __trec_metadata::SourceAddressInfo SAI_addr,
                                __sanitizer::u64 debugID)
  {
    MemoryAccess(thr, pc, addr, kAccessSizeLog, false, false, isPtr, (uptr)val,
                 SAI_addr, 0, debugID);
  }

  void ALWAYS_INLINE MemoryWrite(ThreadState *thr, uptr pc, uptr addr,
                                 int kAccessSizeLog, bool isPtr, uptr val,
                                 __trec_metadata::SourceAddressInfo SAI_addr,
                                 __trec_metadata::SourceAddressInfo SAI_val,
                                 __sanitizer::u64 debugID)
  {
    MemoryAccess(thr, pc, addr, kAccessSizeLog, true, false, isPtr, val, SAI_addr,
                 SAI_val, debugID);
  }

  void ALWAYS_INLINE MemoryReadAtomic(ThreadState *thr, uptr pc, uptr addr,
                                      int kAccessSizeLog, bool isPtr, uptr val,
                                      __trec_metadata::SourceAddressInfo SAI_addr,
                                      __sanitizer::u64 debugID)
  {
    MemoryAccess(thr, pc, addr, kAccessSizeLog, false, true, isPtr, val, SAI_addr,
                 0, debugID);
  }

  void ALWAYS_INLINE MemoryWriteAtomic(
      ThreadState *thr, uptr pc, uptr addr, int kAccessSizeLog, bool isPtr,
      uptr val, __trec_metadata::SourceAddressInfo SAI_addr,
      __trec_metadata::SourceAddressInfo SAI_val, __sanitizer::u64 debugID)
  {
    MemoryAccess(thr, pc, addr, kAccessSizeLog, true, true, isPtr, val, SAI_addr,
                 SAI_val, debugID);
  }

  void RecordFuncEntry(ThreadState *thr, __sanitizer::u16 order,
                       __sanitizer::u16 arg_cnt, __sanitizer::u64 debugID,
                       __sanitizer::u64 pc);
  void RecordFuncExit(ThreadState *thr, __sanitizer::u64 debugID,
                      __sanitizer::u64 pc);

  int ThreadCreate(ThreadState *thr, uptr pc, uptr uid, bool detached);
  void ThreadStart(ThreadState *thr, int tid, tid_t os_id,
                   ThreadType thread_type);
  void ThreadFinish(ThreadState *thr);
  int ThreadConsumeTid(ThreadState *thr, uptr pc, uptr uid);
  void ThreadJoin(ThreadState *thr, uptr pc, int tid);
  void ThreadDetach(ThreadState *thr, uptr pc, int tid);
  void ThreadFinalize(ThreadState *thr);
  void ThreadSetName(ThreadState *thr, const char *name);
  int ThreadCount(ThreadState *thr);
  void ProcessPendingSignals(ThreadState *thr);
  void ThreadNotJoined(ThreadState *thr, uptr pc, int tid, uptr uid);

  Processor *ProcCreate();
  void ProcDestroy(Processor *proc);
  void ProcWire(Processor *proc, ThreadState *thr);
  void ProcUnwire(Processor *proc, ThreadState *thr);

  // Note: the parameter is called flagz, because flags is already taken
  // by the global function that returns flags.
  void MutexCreate(ThreadState *thr, uptr pc, uptr addr, u32 flagz = 0);
  void MutexDestroy(ThreadState *thr, uptr pc, uptr addr, u32 flagz = 0);
  void MutexPreLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz = 0);
  void MutexPostLock(ThreadState *thr, uptr pc, uptr addr,
                     __trec_metadata::SourceAddressInfo SAI, u32 flagz = 0,
                     int rec = 1);
  void MutexPostWriteLock(ThreadState *thr, uptr pc, uptr addr,
                          __trec_metadata::SourceAddressInfo SAI, u32 flagz = 0,
                          int rec = 1);
  int MutexUnlock(ThreadState *thr, uptr pc, uptr addr,
                  __trec_metadata::SourceAddressInfo SAI, u32 flagz = 0);
  void MutexPreReadLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz = 0);
  void MutexPostReadLock(ThreadState *thr, uptr pc, uptr addr,
                         __trec_metadata::SourceAddressInfo SAI, u32 flagz = 0);
  void MutexReadOrWriteUnlock(ThreadState *thr, uptr pc, uptr addr,
                              bool is_writer,
                              __trec_metadata::SourceAddressInfo sa);
  void MutexRepair(ThreadState *thr, uptr pc, uptr addr); // call on EOWNERDEAD
  void MutexInvalidAccess(ThreadState *thr, uptr pc, uptr addr);

  void ReleaseStoreAcquire(ThreadState *thr, uptr pc, uptr addr);
  void ReleaseStore(ThreadState *thr, uptr pc, uptr addr);
  void AfterSleep(ThreadState *thr, uptr pc);
  void CondWait(ThreadState *thr, uptr pc, uptr cond,
                __trec_metadata::SourceAddressInfo cond_SAI);
  void CondSignal(ThreadState *thr, uptr pc, uptr cond, bool is_broadcase,
                  __trec_metadata::SourceAddressInfo SAI);

  // These need to match __trec_switch_to_fiber_* flags defined in
  // trec_interface.h. See documentation there as well.
  enum FiberSwitchFlags
  {
    FiberSwitchFlagNoSync = 1 << 0, // __trec_switch_to_fiber_no_sync
  };

  ALWAYS_INLINE
  void LazyInitialize(ThreadState *thr)
  {
    // If we can use .preinit_array, assume that __tsan_init
    // called from .preinit_array initializes runtime before
    // any instrumented code except when tsan is used as a
    // shared library.
#if (!SANITIZER_CAN_USE_PREINIT_ARRAY || defined(SANITIZER_SHARED))
    if (UNLIKELY(!is_initialized))
      Initialize(thr);
#endif
  }

  void TrecFlushTraceOnDead();

} // namespace __trec

#endif // TREC_RTL_H
