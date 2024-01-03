//===-- trec_defs.h ---------------------------------------------*- C++ -*-===//
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

#ifndef TREC_DEFS_H
#define TREC_DEFS_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_mutex.h"
#ifndef TREC_BUFFER_SIZE
#define TREC_BUFFER_SIZE (1 << 28) // default buffer size: 256MB
#endif

#ifndef TREC_DIR_PATH_LEN
#define TREC_DIR_PATH_LEN 256
#endif

#ifndef TREC_HAS_128_BIT
#define TREC_HAS_128_BIT 0
#endif

namespace __trec
{

  const unsigned kMaxTidReuse = (1 << 22) - 1;
  const unsigned kMaxTid = (1 << 13) - 1;
  const __sanitizer::u16 kInvalidTid = kMaxTid + 1;

  template <typename T>
  T min(T a, T b)
  {
    return a < b ? a : b;
  }

  template <typename T>
  T max(T a, T b)
  {
    return a > b ? a : b;
  }

  struct Processor;
  struct ThreadState;
  class ThreadContext;
  class Context;

} // namespace __trec

namespace __trec_trace
{
  const __sanitizer::u64 TREC_TRACE_VER = 20231207UL;
  enum EventType : __sanitizer::u64
  {
    ThreadBegin,
    ThreadEnd,
    PlainRead,
    PlainWrite,
    PtrRead,
    PtrWrite,
    AtomicPlainRead,
    AtomicPlainWrite,
    AtomicPtrRead,
    AtomicPtrWrite,
    Branch,
    FuncEnter,
    FuncExit,
    ThreadCreate,
    ThreadJoin,
    MutexLock,
    ReaderLock,
    MutexUnlock,
    ReaderUnlock,
    MemAlloc,
    MemFree,
    MemRangeRead,
    MemRangeWrite,
    CondWait,
    CondSignal,
    CondBroadcast,
    Setjmp,
    Longjmp,
    None,
    EventTypeSize,
  };
  static_assert(EventType::EventTypeSize < 256,
                "ERROR: EventType::EventTypeSize >= 256");
  struct Event
  {
    EventType type : 6;
    __sanitizer::u64 tid : 10;
    __sanitizer::u64 gid : 48;

    /*
     * highest bit -> lowest bit
     * ThreadBegin/ThreadEnd:
     *              (not used) : 48
     *              tid:16
     * Read/Write:  size : 16
                    dest address : 48
     * CondBranch:  cond: 64
     * FuncEnter:   (not used) : 32
                    order : 16;
                    arg_cnt : 16;
     * FuncExit:    0
     * ThreadCreate/ThreadJoin:
     *              (not used) : 48
     *              tid:16
     * MutexLock/MutexUnlock/ReaderLock/ReaderUnlock:
                    (not used) : 16
                    lock address : 48
     * MemAlloc/MemFree:
                    size : 16
                    address : 48
     * MemRangeRead/MemRangeWrite:
                    size : 16
                    address : 48
     * CondWait/CondSignal/CondBroadcast:
                    (not used) : 16
                    cond address : 48
     * Setjmp/Longjmp:
                    (not used) : 16
                    jmp_buf address : 48
     * None:        0
     */
    __sanitizer::u64 oid;
    __sanitizer::u64 meta_size : 10;
    // x86_64 only supports 52-bit VMA (48-bit in most cases)
    // use the extra highest bits to distinguish kernel and user space
    __sanitizer::u64 pc : 54;
    Event(EventType _type, __sanitizer::u64 _tid, __sanitizer::u64 _gid,
          __sanitizer::u64 _oid, __sanitizer::u64 _meta_size,
          __sanitizer::u64 _pc)
        : type(_type),
          tid(_tid),
          gid(_gid),
          oid(_oid),
          meta_size(_meta_size),
          pc(_pc) {}
  };
  static_assert(sizeof(Event) == 24, "ERROR: sizeof(Event) != 24");
} // namespace __trec_trace

namespace __trec_metadata
{
  const char TREC_METADATA_VER[] = "20231207";
  struct SourceAddressInfo
  {
    __sanitizer::u64 isDirect : 1;
    __sanitizer::u64 isRealAddr : 1;
    __sanitizer::u64 offset : 14;
    __sanitizer::u64 addr : 48;
    SourceAddressInfo(__sanitizer::u16 _Direct, __sanitizer::u16 _Real,
                      __sanitizer::u16 offset, __sanitizer::u64 _addr)
        : isDirect((__sanitizer::u64)_Direct),
          isRealAddr((__sanitizer::u64)_Real),
          offset((__sanitizer::u64)offset),
          addr(_addr) {}
    SourceAddressInfo(__sanitizer::u64 sa)
        : isDirect((sa >> 63) & 1),
          isRealAddr((sa >> 62) & 1),
          offset((sa >> 48) & 0x3fff),
          addr(sa & ((1ULL << 48) - 1)) {}
    __sanitizer::u64 getAsUInt64() const
    {
      return (((__sanitizer::u64)((isDirect << 1) | isRealAddr)) << 62) |
             ((__sanitizer::u64)offset << 48) | (addr);
    }
  };
  static_assert(sizeof(SourceAddressInfo) == 8,
                "ERROR: sizeof(SourceAddressInfo)!=8");

  struct ReadMeta
  {
    SourceAddressInfo sa;
    __sanitizer::u64 val;
    __sanitizer::u64 debug_id;
    ReadMeta(__sanitizer::u64 v, SourceAddressInfo s, __sanitizer::u64 debug)
        : sa(s), val(v), debug_id(debug) {}
  };
  static_assert(sizeof(ReadMeta) == 24, "ERROR: sizeof(ReadMeta)!=24");

  struct WriteMeta
  {
    SourceAddressInfo sa_addr, sa_val;
    __sanitizer::u64 val;
    __sanitizer::u64 debug_id;
    WriteMeta(__sanitizer::u64 v, SourceAddressInfo as, SourceAddressInfo vs,
              __sanitizer::u64 debug)
        : sa_addr(as), sa_val(vs), val(v), debug_id(debug) {}
  };
  static_assert(sizeof(WriteMeta) == 32, "ERROR: sizeof(WriteMeta)!=32");

  struct BranchMeta
  {
    SourceAddressInfo sa;
    __sanitizer::u64 debug_id;
    BranchMeta(SourceAddressInfo s, __sanitizer::u64 debug)
        : sa(s), debug_id(debug) {}
  };
  static_assert(sizeof(BranchMeta) == 16, "ERROR: sizeof(BranchMeta)!=16");

  struct FuncMeta
  {
    __sanitizer::u64 debug_id;
    FuncMeta(__sanitizer::u64 debug) : debug_id(debug) {}
  };
  static_assert(sizeof(FuncMeta) == 8, "ERROR: sizeof(FuncEnterMeta)!=8");

  struct FuncParamMeta
  {
    SourceAddressInfo sa;
    __sanitizer::u64 val;
    __sanitizer::u64 debug_id;
    FuncParamMeta(SourceAddressInfo s, __sanitizer::u64 v, __sanitizer::u64 debug)
        : sa(s), val(v), debug_id(debug) {}
  };

  static_assert(sizeof(FuncParamMeta) == 24, "ERROR: sizeof(FuncParamMeta)!=24");

  struct MemFreeMeta : SourceAddressInfo
  {
    using SourceAddressInfo::SourceAddressInfo;
  };
  static_assert(sizeof(MemFreeMeta) == 8, "ERROR: sizeof(MemFreeMeta) != 8");

  struct MutexMeta : SourceAddressInfo
  {
    using SourceAddressInfo::SourceAddressInfo;
  };
  static_assert(sizeof(MutexMeta) == 8, "ERROR: sizeof(MutexMeta) != 8");

  struct CondMeta : SourceAddressInfo
  {
    using SourceAddressInfo::SourceAddressInfo;
  };
  static_assert(sizeof(CondMeta) == 8, "ERROR: sizeof(CondMeta) != 8");

  struct MemRangeMeta : SourceAddressInfo
  {
    using SourceAddressInfo::SourceAddressInfo;
  };

  static_assert(sizeof(MemRangeMeta) == 8, "ERROR: sizeof(MemRangeMeta) != 8");

} // namespace __trec_metadata

namespace __trec_header
{
  const char TREC_HEADER_VER[] = "20231207";
  enum RecordType : __sanitizer::u32
  {
    // trace information
    EventTypeSize = __trec_trace::EventType::EventTypeSize,
    TotalEventCnt,
    MetadataFileLen,

    RecordTypeCnt,
  };

  struct TraceHeader
  {
    __sanitizer::u64 state[RecordType::RecordTypeCnt];
    char cmd[1024];
    char version[9];
    TraceHeader()
    {
      __sanitizer::internal_memset(cmd, 0, sizeof(cmd));
      __sanitizer::internal_strlcpy(version, TREC_HEADER_VER, sizeof(version));
      StateReset();
    }
    void StateInc(RecordType type) { state[type] += 1; }
    void StateInc(__trec_trace::EventType type) { state[type] += 1; }
    void StateReset() { __sanitizer::internal_memset(state, 0, sizeof(state)); }
  };
} // namespace __trec_header
#endif // TREC_DEFS_H
