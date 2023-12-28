//===-- trec_rtl_thread.cpp
//-----------------------------------------------===//
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

#include <assert.h>
#include <errno.h>
#include <sys/fcntl.h>

#include "sanitizer_common/sanitizer_placement_new.h"
#include "trec_mman.h"
#include "trec_platform.h"
#include "trec_rtl.h"

namespace __trec {

TraceWriter::TraceWriter(u16 tid)
    : id(tid),
      trace_buffer(nullptr),
      metadata_buffer(nullptr),
      trace_len(0),
      metadata_len(0),
      is_end(false) {
  params.init(32);
}

TraceWriter::~TraceWriter() {
  if (ctx->flags.output_trace)
    flush_all();
  if (trace_buffer)
    internal_free(trace_buffer);
  if (metadata_buffer)
    internal_free(metadata_buffer);
}

void TraceWriter::put_record(__trec_trace::EventType type, __sanitizer::u64 oid,
                             __sanitizer::u64 pc, void *meta,
                             __sanitizer::u16 len) {
  if (is_end)
    return;
  if (type == __trec_trace::EventType::FuncEnter) {
    assert(meta && len);
    __sanitizer::u16 total_len = 0;
    params.forEach(
        [&](__sanitizer::detail::DenseMapPair<
            __sanitizer::u16, __trec_metadata::FuncParamMeta> &pair) {
          if (pair.first >= 1 && pair.first <= (oid & 0xffff)) {
            total_len += (sizeof(pair.first) + sizeof(pair.second));
            put_metadata(&pair.first, sizeof(pair.first));
            put_metadata(&pair.second, sizeof(pair.second));
          }
          return true;
        });
    put_metadata(meta, len);
    total_len += len;
    __trec_trace::Event e(
        type, cur_thread()->tid,
        atomic_fetch_add(&ctx->global_id, 1, memory_order_relaxed), oid,
        total_len, pc);
    put_trace(e);
  } else if (type == __trec_trace::EventType::FuncExit) {
    assert(meta && len);
    __sanitizer::u16 total_len = 0;
    if (params.count(0)) {
      auto pair = params.find(0);
      put_metadata(&pair->second, sizeof(pair->second));
      total_len += sizeof(pair->second);
    }
    put_metadata(meta, len);
    total_len += len;
    __trec_trace::Event e(
        type, cur_thread()->tid,
        atomic_fetch_add(&ctx->global_id, 1, memory_order_relaxed), oid,
        total_len, pc);
    put_trace(e);
  } else {
    if (meta && len)
      put_metadata(meta, len);
    __trec_trace::Event e(
        type, cur_thread()->tid,
        atomic_fetch_add(&ctx->global_id, 1, memory_order_relaxed), oid, len,
        pc);
    put_trace(e);
  }
  params.clear();
}

void TraceWriter::put_trace(__trec_trace::Event &e) {
  if (UNLIKELY(trace_len + sizeof(__trec_trace::Event) >= TREC_BUFFER_SIZE))
    flush_all();

  {
    TrecMutexGuard guard(mtx);
    if (UNLIKELY(trace_buffer == nullptr)) {
      trace_buffer =
          (char *)internal_alloc(MBlockShadowStack, TREC_BUFFER_SIZE);
      trace_len = 0;
    }

    internal_memcpy(trace_buffer + trace_len, &e, sizeof(__trec_trace::Event));
    trace_len += sizeof(__trec_trace::Event);
    header.StateInc(__trec_header::RecordType::TotalEventCnt);
    header.StateInc(e.type);
  }
}

void TraceWriter::put_metadata(void *msg, __sanitizer::u16 len) {
  if (UNLIKELY(metadata_len + len >= TREC_BUFFER_SIZE)) {
    flush_all();
  }
  {
    TrecMutexGuard guard(mtx);
    if (UNLIKELY(metadata_buffer == nullptr)) {
      metadata_buffer =
          (char *)internal_alloc(MBlockShadowStack, TREC_BUFFER_SIZE);
      metadata_len = 0;
    }

    internal_memcpy(metadata_buffer + metadata_len, msg, len);
    metadata_len += len;
    header.state[__trec_header::RecordType::MetadataFileLen] += len;
  }
}

void TraceWriter::flush_module() {
  char modulepath[TREC_DIR_PATH_LEN];
  char write_buff[2 * TREC_DIR_PATH_LEN];
  internal_snprintf(modulepath, TREC_DIR_PATH_LEN - 1,
                    "%s/trec_%lu/header/modules_%d.txt", ctx->trace_dir,
                    internal_getpid(), id);
  int fd_module_file =
      internal_open(modulepath, O_CREAT | O_WRONLY | O_TRUNC, 0700);
  MemoryMappingLayout memory_mapping(false);
  InternalMmapVector<LoadedModule> modules(/*initial_capacity*/ 64);
  memory_mapping.DumpListOfModules(&modules);
  Sort(modules.begin(), modules.size(),
       [](const LoadedModule &a, const LoadedModule &b) {
         return a.base_address() < b.base_address();
       });
  for (auto &item : modules) {
    if (item.full_name() && item.base_address() && item.max_address() &&
        internal_strstr(item.full_name(), "(deleted)") == nullptr) {
      internal_memset(write_buff, 0, sizeof(write_buff));
      int bufflen = internal_snprintf(write_buff, 2 * TREC_DIR_PATH_LEN - 1,
                                      "%s %lx-%lx\n", item.full_name(),
                                      item.base_address(), item.max_address());
      uptr need_write_bytes = bufflen;
      char *buff_pos = (char *)write_buff;
      while (need_write_bytes > 0) {
        uptr write_bytes =
            internal_write(fd_module_file, buff_pos, need_write_bytes);
        if (write_bytes == (uptr)-1 && errno != EINTR) {
          Report("Failed to flush module info in %s, errno=%u\n", modulepath,
                 errno);
          Die();
        } else {
          need_write_bytes -= write_bytes;
          buff_pos += write_bytes;
        }
      }
    }
  }
  internal_close(fd_module_file);
}

void TraceWriter::flush_all() {
  if (is_end)
    return;
  {
    TrecMutexGuard guard(mtx);
    flush_trace();
    flush_metadata();
    flush_header();
  }
}

void TraceWriter::flush_trace() {
  if (trace_buffer == nullptr || trace_len == 0)
    return;
  char filepath[TREC_DIR_PATH_LEN];

  internal_snprintf(filepath, TREC_DIR_PATH_LEN - 1, "%s/trec_%lu/trace/%d.bin",
                    ctx->trace_dir, internal_getpid(), id);
  int fd_trace = internal_open(filepath, O_CREAT | O_WRONLY | O_APPEND, 0700);

  if (UNLIKELY(fd_trace < 0)) {
    Report("Failed to open trace file at %s\n", filepath);
    Die();
  }
  char *buff_pos = (char *)trace_buffer;
  while (trace_len > 0) {
    uptr write_bytes = internal_write(fd_trace, buff_pos, trace_len);
    if (write_bytes == (uptr)-1 && errno != EINTR) {
      Report("Failed to flush trace info in %s, errno=%u\n", filepath, errno);
      Die();
    } else {
      trace_len -= write_bytes;
      buff_pos += write_bytes;
    }
  }

  internal_close(fd_trace);
}

void TraceWriter::flush_metadata() {
  if (metadata_buffer == nullptr || metadata_len == 0)
    return;
  char filepath[TREC_DIR_PATH_LEN];

  internal_snprintf(filepath, TREC_DIR_PATH_LEN - 1,
                    "%s/trec_%lu/metadata/%d.bin", ctx->trace_dir,
                    internal_getpid(), id);
  int fd_metadata =
      internal_open(filepath, O_CREAT | O_WRONLY | O_APPEND, 0700);

  if (UNLIKELY(fd_metadata < 0)) {
    Report("Failed to open metadata file at %s\n", filepath);
    Die();
  }
  char *buff_pos = (char *)metadata_buffer;
  while (metadata_len > 0) {
    uptr write_bytes = internal_write(fd_metadata, buff_pos, metadata_len);
    if (write_bytes == (uptr)-1 && errno != EINTR) {
      Report("Failed to flush metadata info in %s, errno=%u\n", filepath,
             errno);
      Die();
    } else {
      metadata_len -= write_bytes;
      buff_pos += write_bytes;
    }
  }

  internal_close(fd_metadata);
}

void TraceWriter::flush_header() {
  char filepath[TREC_DIR_PATH_LEN];

  internal_snprintf(filepath, TREC_DIR_PATH_LEN - 1,
                    "%s/trec_%lu/header/%d.bin", ctx->trace_dir,
                    internal_getpid(), id);

  int fd_header = internal_open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0700);

  if (UNLIKELY(fd_header < 0)) {
    Report("Failed to open header file\n");
    Die();
  } else {
    uptr need_write_bytes = sizeof(header);
    char *buff_pos = (char *)&header;
    while (need_write_bytes > 0) {
      uptr write_bytes = internal_write(fd_header, buff_pos, need_write_bytes);
      if (write_bytes == (uptr)-1 && errno != EINTR) {
        Report("Failed to flush header in %s, errno=%u\n", filepath, errno);
        Die();
      } else {
        need_write_bytes -= write_bytes;
        buff_pos += write_bytes;
      }
    }
  }

  internal_close(fd_header);
}

bool TraceWriter::state_restore() {
  TrecMutexGuard guard(mtx);
  struct stat _st = {0};
  char path[2 * TREC_DIR_PATH_LEN];
  internal_snprintf(path, 2 * TREC_DIR_PATH_LEN - 1,
                    "%s/trec_%lu/header/%u.bin", ctx->trace_dir,
                    internal_getpid(), id);
  uptr IS_EXIST = __sanitizer::internal_stat(path, &_st);
  if (IS_EXIST == 0 && _st.st_size > 0) {
    int header_fd = internal_open(path, O_RDONLY);
    if (header_fd < 0) {
      Report("Restore header from %s failed\n", path);
      return false;
    } else {
      internal_read(header_fd, &header, sizeof(header));
      return true;
    }
  }
  return false;
}

void TraceWriter::reset() {
  TrecMutexGuard guard(mtx);
  if (trace_buffer)
    internal_free(trace_buffer);
  trace_buffer = nullptr;
  trace_len = 0;
  if (metadata_buffer)
    internal_free(metadata_buffer);
  metadata_buffer = nullptr;
  metadata_len = 0;
  params.clear();
}

void TraceWriter::init_cmd() {
  TrecMutexGuard guard(mtx);
  char **cmds = GetArgv();
  int cmd_len = 0;
  for (int i = 0; cmds[i]; i++) {
    if (i != 0) {
      header.cmd[cmd_len++] = ' ';
    }
    cmd_len += internal_strlcpy(header.cmd + cmd_len, cmds[i],
                                sizeof(header.cmd) - 1 - cmd_len);
  }
}

void TraceWriter::pend_param(__sanitizer::u16 idx,
                             __trec_metadata::SourceAddressInfo sa,
                             __sanitizer::u64 val, __sanitizer::u64 debugID) {
  if (is_end)
    return;
  __trec_metadata::FuncParamMeta meta(sa, val, debugID);
  params.insert(__sanitizer::detail::DenseMapPair<
                __sanitizer::u16, __trec_metadata::FuncParamMeta>(idx, meta));
}

const __trec_trace::Event *TraceWriter::getLastEvent() const {
  if (trace_buffer == nullptr || trace_len < sizeof(__trec_trace::Event))
    return nullptr;
  return (const __trec_trace::Event *)(trace_buffer + trace_len -
                                       sizeof(__trec_trace::Event));
}

void TraceWriter::setEnd() { is_end = true; }

// ThreadContext implementation.

ThreadContext::ThreadContext(int tid)
    : ThreadContextBase(tid), thr(), writer(tid) {}

#if !SANITIZER_GO
ThreadContext::~ThreadContext() {}
#endif

void ThreadContext::OnDead() {}

void ThreadContext::OnJoined(void *arg) {}

struct OnCreatedArgs {
  ThreadState *thr;
  uptr pc;
};

void ThreadContext::OnCreated(void *arg) {}

void ThreadContext::OnReset() {}

void ThreadContext::OnDetached(void *arg) {}

struct OnStartedArgs {
  ThreadState *thr;
};

void ThreadContext::OnStarted(void *arg) {
  OnStartedArgs *args = static_cast<OnStartedArgs *>(arg);
  thr = args->thr;
  new (thr) ThreadState(ctx, tid, unique_id);
  thr->is_inited = true;
  DPrintf("#%d: ThreadStart\n", tid);
}

void ThreadContext::OnFinished() {
#if !SANITIZER_GO
  PlatformCleanUpThreadState(thr);
#endif
  thr->~ThreadState();
  thr = 0;
}

void ThreadFinalize(ThreadState *thr) {
  if (LIKELY(ctx->flags.output_trace)) {
    thr->tctx->writer.put_record(__trec_trace::EventType::ThreadEnd,
                                 thr->tid & 0xffff, 0);
  }
}

int ThreadCount(ThreadState *thr) {
  uptr result;
  ctx->thread_registry->GetNumberOfThreads(0, 0, &result);
  return (int)result;
}

int ThreadCreate(ThreadState *thr, uptr pc, uptr uid, bool detached) {
  OnCreatedArgs args = {thr, pc};
  u32 parent_tid = thr ? thr->tid : kInvalidTid;  // No parent for GCD workers.
  int tid =
      ctx->thread_registry->CreateThread(uid, detached, parent_tid, &args);
  DPrintf("#%d: ThreadCreate tid=%d uid=%zu\n", parent_tid, tid, uid);
  if (tid == 0) {
    if (ctx->flags.output_trace) {
      const char *trace_dir_env = GetEnv("TREC_TRACE_DIR");
      if (trace_dir_env == nullptr) {
        Report("TREC_TRACE_DIR has not been set!\n");
        Die();
      } else
        internal_strncpy(ctx->trace_dir, trace_dir_env,
                         internal_strlen(trace_dir_env));
      ctx->open_directory(ctx->trace_dir);
    }
    atomic_store(&ctx->global_id, 0, memory_order_relaxed);
    atomic_store(&ctx->forked_cnt, 0, memory_order_relaxed);
  } else if (LIKELY(thr != nullptr && thr->tctx != nullptr) &&
             LIKELY(ctx->flags.output_trace)) {
    thr->tctx->writer.put_record(__trec_trace::EventType::ThreadCreate,
                                 tid & 0xffff, pc);
  }
  return tid;
}

void ThreadStart(ThreadState *thr, int tid, tid_t os_id,
                 ThreadType thread_type) {
  ThreadRegistry *tr = ctx->thread_registry;
  OnStartedArgs args = {thr};
  tr->StartThread(tid, os_id, thread_type, &args);

  tr->Lock();
  thr->tctx = (ThreadContext *)tr->GetThreadLocked(tid);
  tr->Unlock();

  // we should put the trace after it thr->tctx has been initialized
  if (LIKELY(ctx->flags.output_trace)) {
    thr->tctx->writer.flush_module();
    thr->tctx->writer.reset();

    thr->tctx->writer.put_record(
        __trec_trace::EventType::None, __trec_trace::TREC_TRACE_VER, 0,
        (void *)__trec_metadata::TREC_METADATA_VER,
        internal_strlen(__trec_metadata::TREC_METADATA_VER) + 1);
    thr->tctx->writer.init_cmd();
    thr->tctx->writer.put_record(__trec_trace::EventType::ThreadBegin, thr->tid,
                                 0);
  }
}

void ThreadFinish(ThreadState *thr) {
  if (LIKELY(ctx->flags.output_trace)) {
    thr->tctx->writer.put_record(__trec_trace::EventType::ThreadEnd, thr->tid,
                                 0);
    thr->tctx->writer.flush_all();
  }
  thr->tctx->writer.reset();
  thr->is_dead = true;
  ctx->thread_registry->FinishThread(thr->tid);
}

struct ConsumeThreadContext {
  uptr uid;
  ThreadContextBase *tctx;
};

int ThreadConsumeTid(ThreadState *thr, uptr pc, uptr uid) {
  int tid = ctx->thread_registry->ConsumeThreadUserId(uid);
  DPrintf("#%d: ThreadTid uid=%zu tid=%d\n", thr->tid, uid, tid);
  return tid;
}

void ThreadJoin(ThreadState *thr, uptr pc, int tid) {
  CHECK_GT(tid, 0);
  CHECK_LT(tid, kMaxTid);
  DPrintf("#%d: ThreadJoin tid=%d\n", thr->tid, tid);
  thr->tctx->writer.put_record(__trec_trace::EventType::ThreadJoin,
                               tid & 0xffff, pc);

  ctx->thread_registry->JoinThread(tid, thr);
}

void ThreadDetach(ThreadState *thr, uptr pc, int tid) {
  CHECK_GT(tid, 0);
  CHECK_LT(tid, kMaxTid);
  ctx->thread_registry->DetachThread(tid, thr);
}

void ThreadNotJoined(ThreadState *thr, uptr pc, int tid, uptr uid) {
  CHECK_GT(tid, 0);
  CHECK_LT(tid, kMaxTid);
  ctx->thread_registry->SetThreadUserId(tid, uid);
}

void ThreadSetName(ThreadState *thr, const char *name) {
  ctx->thread_registry->SetThreadName(thr->tid, name);
}

void MemoryAccessRange(ThreadState *thr, uptr pc, uptr addr, uptr size,
                       bool is_write, __trec_metadata::SourceAddressInfo SAI) {
  if (LIKELY(ctx->flags.output_trace) && ctx->flags.record_range &&
      LIKELY(cur_thread()->ignore_interceptors == 0) && SAI.getAsUInt64()) {
    __trec_metadata::MemRangeMeta meta(SAI.getAsUInt64());
    thr->tctx->writer.put_record(is_write
                                     ? __trec_trace::EventType::MemRangeWrite
                                     : __trec_trace::EventType::MemRangeRead,
                                 (((__sanitizer::u64)size & 0xffff) << 48) |
                                     (addr & ((((1ULL) << 48) - 1))),
                                 pc, &meta, sizeof(meta));
  }

  return;
}

}  // namespace __trec
