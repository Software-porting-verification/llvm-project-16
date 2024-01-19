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
#include <sys/file.h>

#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_symbolizer.h"
#include "trec_mman.h"
#include "trec_platform.h"
#include "trec_rtl.h"

namespace __trec
{
  int query_callback(void *ret, int argc, char **argv, char **azColName)
  {
    assert(argc == 1);
    *(int *)ret = (int)internal_atoll(argv[0]);
    return 0;
  }

  int SqliteDebugWriter::insertName(const char *table, const char *name)
  {
    char buf[4096];
    __sanitizer::internal_snprintf(buf, 2047, "INSERT INTO %s VALUES (NULL, '%s');", table, name);
    char *errmsg;
    int status = sqlite3_exec(db, buf, nullptr, nullptr, &errmsg);
    if (status != SQLITE_OK)
    {
      Report("query error(%d): %s\n", status, errmsg);
      Die();
    };
    sqlite3_free(errmsg);
    return queryMaxID(table);
  }

  int SqliteDebugWriter::insertDebugInfo(int nameA, int nameB, int line,
                                         int col)
  {
    char buf[4096];
    __sanitizer::internal_snprintf(buf, 2047, "INSERT INTO DEBUGINFO VALUES (NULL, %d, %d, %d, %d);",
                                   nameA, nameB, line, col);
    char *errmsg;
    int status = sqlite3_exec(db, buf, nullptr, nullptr, &errmsg);
    if (status != SQLITE_OK)
    {
      Report("query error(%d): %s\n", status, errmsg);
      Die();
    };
    sqlite3_free(errmsg);
    return queryMaxID("DEBUGINFO");
  }

  int SqliteDebugWriter::queryMaxID(const char *table)
  {
    char *errmsg;
    char buf[4096];
    int ID = -1;
    __sanitizer::internal_snprintf(buf, 4095, "select seq from sqlite_sequence where name='%s';",
                                   table);
    int status = sqlite3_exec(db, buf, query_callback, &ID, &errmsg);
    if (status != SQLITE_OK)
    {
      Report("query error(%d): %s\n", status, errmsg);
      Die();
    };
    sqlite3_free(errmsg);
    if (ID == -1)
    {
      Report("query error: cannot query last inserted ID for table %s\n", table);
      Die();
    }
    return ID;
  }

  int SqliteDebugWriter::queryFileID(const char *name)
  {
    return queryID("DEBUGFILENAME", name);
  }

  int SqliteDebugWriter::queryVarID(const char *name)
  {
    return queryID("DEBUGVARNAME", name);
  }

  int SqliteDebugWriter::queryID(const char *table, const char *name)
  {
    if (internal_strcmp(name, "") == 0)
      return 1;
    char *errmsg;
    char buf[4096];
    int ID = -1;
    __sanitizer::internal_snprintf(buf, 4095, "SELECT ID from %s where NAME='%s';", table, name);
    int status = sqlite3_exec(db, buf, query_callback, &ID, &errmsg);
    if (status != SQLITE_OK)
    {
      Report("query error(%d): %s\n", status, errmsg);
      Die();
    };
    sqlite3_free(errmsg);
    return ID;
  }

  int SqliteDebugWriter::queryDebugInfoID(int nameA, int nameB, int line,
                                          int col)
  {
    char *errmsg;
    char buf[4096];
    int ID = -1;
    __sanitizer::internal_snprintf(
        buf, 4095,
        "SELECT ID from DEBUGINFO where NAMEIDA=%d AND NAMEIDB=%d AND "
        "LINE=%d AND COL=%d;",
        nameA, nameB, line, col);
    int status = sqlite3_exec(db, buf, query_callback, &ID, &errmsg);
    if (status != SQLITE_OK)
    {
      Report("query error(%d): %s\n", status, errmsg);
      Die();
    };
    sqlite3_free(errmsg);
    return ID;
  }

  __sanitizer::u64 SqliteDebugWriter::ReformID(int ID)
  {
    assert(DBID >= 1);
    assert(ID >= 1);
    return (((__sanitizer::u64)DBID & ((1ULL << 16) - 1)) << 48) |
           ((__sanitizer::u64)ID & ((1ULL << 48) - 1));
  }

  SqliteDebugWriter::SqliteDebugWriter() : db(nullptr), DBID(-1), isValid(false)
  {
    ScopedIgnoreInterceptors ignore;
    const char *DatabaseDir = GetEnv("TREC_DATABASE_DIR");
    if (DatabaseDir == nullptr)
    {
      Report("ENV 'TREC_DATABASE_DIR' has not been set\n");
      Die();
    }
    __sanitizer::internal_snprintf(DBDirPath, 2047, "%s", DatabaseDir);
    int pid = __sanitizer::internal_getpid();
    char buf[2048];
    __sanitizer::internal_snprintf(buf, 2047, "%s/%s", DBDirPath, "manager.db");
    int status;
    char *errmsg;

    // open sqlite database
    status = sqlite3_open(buf, &db);
    if (status)
    {
      Report("Open manager databased %s failed(%d): %s\n", buf,
             status, sqlite3_errmsg(db));
      Die();
    }

    // acquire flock
    int database_fd = internal_open(buf, O_RDONLY);

    if ((status = flock(database_fd, LOCK_EX)) != 0)
    {
      Report("ERROR: acquire flock for manager database %s failed(%d)\n",
             buf, status);
      Die();
    }

    status = sqlite3_exec(db,
                          "CREATE TABLE MANAGER (ID INTEGER PRIMARY KEY "
                          "AUTOINCREMENT, PID INTEGER);",
                          nullptr, nullptr, &errmsg);
    if (status != SQLITE_OK &&
        !(status == SQLITE_ERROR &&
          __sanitizer::internal_strcmp(errmsg, "table MANAGER already exists") == 0))
    {
      Report("create table error(%d): %s\n", status, errmsg);
      Die();
    };
    sqlite3_free(errmsg);

    bool isCreated = false;
    char buffer[256];
    __sanitizer::internal_snprintf(buffer, sizeof(buffer), "SELECT ID from MANAGER where PID=%d;", pid);
    status = sqlite3_exec(db, buffer, query_callback, &DBID, &errmsg);
    if (status != SQLITE_OK)
    {
      Report("query manager table error(%d): %s\n", status, errmsg);
      Die();
    };
    while (DBID == -1)
    {
      __sanitizer::internal_snprintf(buffer, sizeof(buffer),
                                     "SELECT ID from MANAGER where PID IS NULL;");
      status = sqlite3_exec(db, buffer, query_callback, &DBID, &errmsg);
      if (status != SQLITE_OK)
      {
        Report("query manager table error(%d): %s\n", status, errmsg);
        Die();
      };
      sqlite3_free(errmsg);
      if (DBID == -1)
      {
        // no empty entry
        isCreated = true;
        __sanitizer::internal_snprintf(buffer, sizeof(buffer),
                                       "INSERT INTO MANAGER VALUES (NULL, NULL);");
        while ((status = sqlite3_exec(db, buffer, nullptr, nullptr, &errmsg)) ==
               SQLITE_BUSY)
          sqlite3_free(errmsg);
        sqlite3_free(errmsg);
        if (status != SQLITE_OK)
        {
          Report("insert manager table error(%d): %s\n", status, errmsg);
          Die();
        };
        sqlite3_free(errmsg);
      }
    }
    __sanitizer::internal_snprintf(buffer, sizeof(buffer), "UPDATE MANAGER SET PID=%d where ID=%d;",
                                   pid, DBID);
    status = sqlite3_exec(db, buffer, nullptr, nullptr, &errmsg);
    if (status != SQLITE_OK)
    {
      Report("update manager table error(%d): %s\n", status, errmsg);
      Die();
    };
    sqlite3_free(errmsg);

    // release flock
    if ((status = flock(database_fd, LOCK_UN)) != 0)
    {
      Report("ERROR: release flock failed\n");
      Die();
    }
    internal_close(database_fd);

    // close manager database
    sqlite3_close(db);

    __sanitizer::internal_snprintf(buffer, sizeof(buffer), "%s/debuginfo%d.db", DBDirPath,
                                   DBID);
    sqlite3_open(buffer, &db);
    if (status)
    {
      Report("open %s file failed(%d): %s\n", buffer, status, sqlite3_errmsg(db));
      Die();
    }

    // speedup querying
    status =
        sqlite3_exec(db, "PRAGMA synchronous=OFF;", nullptr, nullptr, nullptr);
    if (status != SQLITE_OK)
    {
      Report("trun off synchronous mode failed: %s\n", sqlite3_errmsg(db));
      Die();
    }

    if (isCreated)
    {
      status = sqlite3_exec(db,
                            "CREATE TABLE DEBUGINFO ("
                            "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                            "NAMEIDA INTEGER NOT NULL,"
                            "NAMEIDB INTEGER NOT NULL,"
                            "LINE SMALLINT NOT NULL,"
                            "COL SMALLINT NOT NULL);"
                            "CREATE TABLE DEBUGVARNAME ("
                            "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                            "NAME CHAR(256));"
                            "CREATE TABLE DEBUGFILENAME ("
                            "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                            "NAME CHAR(2048));"
                            "INSERT INTO DEBUGVARNAME VALUES (NULL, '');"
                            "INSERT INTO DEBUGFILENAME VALUES (NULL, '');",
                            nullptr, nullptr, &errmsg);
      if (status)
      {
        Report("create subtables failed %d:%s\n", status, sqlite3_errmsg(db));
        Die();
      }
      sqlite3_free(errmsg);
    }
  }
  SqliteDebugWriter::~SqliteDebugWriter()
  {
    ScopedIgnoreInterceptors ignore;
    sqlite3_close(db);

    char buf[2048];
    __sanitizer::internal_snprintf(buf, 2047, "%s/%s", DBDirPath, "manager.db");
    int status;
    char *errmsg;
    int database_fd = internal_open(buf, O_RDONLY);
    if ((status = flock(database_fd, LOCK_EX)) != 0)
    {
      Report("ERROR: acquire flock failed\n");
      Die();
    }
    status = sqlite3_open(buf, &db);
    if (status)
    {
      Report("Open manager databased %s failed(%d): %s\n", buf,
             status, sqlite3_errmsg(db));
      Die();
    }
    char buffer[256];
    __sanitizer::internal_snprintf(buffer, sizeof(buffer), "UPDATE MANAGER SET PID=NULL where ID=%d;",
                                   DBID);
    status = sqlite3_exec(db, buffer, nullptr, nullptr, &errmsg);
    if (status != SQLITE_OK)
    {
      Report("update manager table error(%d): %s\n", status, errmsg);
      Die();
    };
    sqlite3_free(errmsg);

    sqlite3_close(db);
    if ((status = flock(database_fd, LOCK_UN)) != 0)
    {
      Report("ERROR: release flock failed\n");
      Die();
    }
    internal_close(database_fd);
  }
  int SqliteDebugWriter::getFileID(const char *name)
  {
    ScopedIgnoreInterceptors ignore;
    int ID = queryFileID(name);
    if (ID == -1)
    {
      ID = insertFileName(name);
    }
    return ID;
  }
  int SqliteDebugWriter::getVarID(const char *name)
  {
    ScopedIgnoreInterceptors ignore;
    int ID = queryVarID(name);
    if (ID == -1)
    {
      ID = insertVarName(name);
    }
    return ID;
  }
  int SqliteDebugWriter::getDebugInfoID(int nameA, int nameB, int line, int col)
  {
    ScopedIgnoreInterceptors ignore;
    int ID = queryDebugInfoID(nameA, nameB, line, col);
    if (ID == -1)
      ID = insertDebugInfo(nameA, nameB, line, col);
    return ID;
  }
  int SqliteDebugWriter::insertFileName(const char *name)
  {
    return insertName("DEBUGFILENAME", name);
  }
  int SqliteDebugWriter::insertVarName(const char *name)
  {
    return insertName("DEBUGVARNAME", name);
  }

  TraceWriter::TraceWriter(u16 tid)
      : id(tid),
        trace_buffer(nullptr),
        metadata_buffer(nullptr),
        trace_len(0),
        metadata_len(0),
        is_end(false)
  {
    params.init(32);
  }

  TraceWriter::~TraceWriter()
  {
    if (ctx->flags.output_trace)
      flush_all();
    if (trace_buffer)
      internal_free(trace_buffer);
    if (metadata_buffer)
      internal_free(metadata_buffer);
  }

  void TraceWriter::put_record(__trec_trace::EventType type, __sanitizer::u64 oid,
                               __sanitizer::u64 pc, void *meta,
                               __sanitizer::u16 len)
  {
    if (is_end)
      return;

    if (type == __trec_trace::EventType::FuncEnter)
    {
      assert(meta && len);
      __sanitizer::u16 total_len = 0;
      params.forEach(
          [&](__sanitizer::detail::DenseMapPair<
              __sanitizer::u16, __trec_metadata::FuncParamMeta> &pair)
          {
            if (pair.first >= 1 && pair.first <= (oid & 0xffff))
            {
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
    }
    else if (type == __trec_trace::EventType::FuncExit)
    {
      assert(meta && len);
      __sanitizer::u16 total_len = 0;
      if (params.count(0))
      {
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
    }
    else
    {
      if (meta && len)
        put_metadata(meta, len);
      __trec_trace::Event e(
          type, cur_thread()->tid,
          atomic_fetch_add(&ctx->global_id, 1, memory_order_relaxed), oid, len,
          pc);
      put_trace(e);
    }
    params.clear();
    unsetNeedSymbolize();
    if (type == __trec_trace::EventType::FuncEnter && metadata_buffer && metadata_len >= sizeof(__trec_metadata::FuncMeta))
    {
      __trec_metadata::FuncMeta *meta = (__trec_metadata::FuncMeta *)(metadata_buffer + metadata_len - sizeof(__trec_metadata::FuncMeta));
      if (meta->debug_id == 0)
      {
        setNeedSymbolize();
      }
    }
  }

  void TraceWriter::put_trace(__trec_trace::Event &e)
  {
    if (UNLIKELY(trace_len + sizeof(__trec_trace::Event) >= TREC_BUFFER_SIZE))
      flush_all();

    {
      TrecMutexGuard guard(mtx);
      if (UNLIKELY(trace_buffer == nullptr))
      {
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

  void TraceWriter::put_metadata(void *msg, __sanitizer::u16 len)
  {
    if (UNLIKELY(metadata_len + len >= TREC_BUFFER_SIZE))
    {
      flush_all();
    }
    {
      TrecMutexGuard guard(mtx);
      if (UNLIKELY(metadata_buffer == nullptr))
      {
        metadata_buffer =
            (char *)internal_alloc(MBlockShadowStack, TREC_BUFFER_SIZE);
        metadata_len = 0;
      }

      internal_memcpy(metadata_buffer + metadata_len, msg, len);
      metadata_len += len;
      header.state[__trec_header::RecordType::MetadataFileLen] += len;
    }
  }

  void TraceWriter::flush_module()
  {
    char modulepath[TREC_DIR_PATH_LEN];
    char write_buff[2 * TREC_DIR_PATH_LEN];
    __sanitizer::internal_snprintf(modulepath, TREC_DIR_PATH_LEN - 1,
                                   "%s/trec_%lu/header/modules_%d.txt", ctx->trace_dir,
                                   internal_getpid(), id);
    int fd_module_file =
        internal_open(modulepath, O_CREAT | O_WRONLY | O_TRUNC, 0700);
    MemoryMappingLayout memory_mapping(false);
    InternalMmapVector<LoadedModule> modules(/*initial_capacity*/ 64);
    memory_mapping.DumpListOfModules(&modules);
    Sort(modules.begin(), modules.size(),
         [](const LoadedModule &a, const LoadedModule &b)
         {
           return a.base_address() < b.base_address();
         });
    for (auto &item : modules)
    {
      if (item.full_name() && item.base_address() && item.max_address() &&
          internal_strstr(item.full_name(), "(deleted)") == nullptr)
      {
        internal_memset(write_buff, 0, sizeof(write_buff));
        int bufflen = __sanitizer::internal_snprintf(write_buff, 2 * TREC_DIR_PATH_LEN - 1,
                                                     "%s %lx-%lx\n", item.full_name(),
                                                     item.base_address(), item.max_address());
        uptr need_write_bytes = bufflen;
        char *buff_pos = (char *)write_buff;
        while (need_write_bytes > 0)
        {
          uptr write_bytes =
              internal_write(fd_module_file, buff_pos, need_write_bytes);
          if (write_bytes == (uptr)-1 && errno != EINTR)
          {
            Report("Failed to flush module info in %s, errno=%u\n", modulepath,
                   errno);
            Die();
          }
          else
          {
            need_write_bytes -= write_bytes;
            buff_pos += write_bytes;
          }
        }
      }
    }
    internal_close(fd_module_file);
  }

  void TraceWriter::flush_all()
  {
    if (is_end)
      return;
    {
      TrecMutexGuard guard(mtx);
      flush_trace();
      flush_metadata();
      flush_header();
    }
  }

  void TraceWriter::flush_trace()
  {
    if (trace_buffer == nullptr || trace_len == 0)
      return;
    char filepath[TREC_DIR_PATH_LEN];

    __sanitizer::internal_snprintf(filepath, TREC_DIR_PATH_LEN - 1, "%s/trec_%lu/trace/%d.bin",
                                   ctx->trace_dir, internal_getpid(), id);
    int fd_trace = internal_open(filepath, O_CREAT | O_WRONLY | O_APPEND, 0700);

    if (UNLIKELY(fd_trace < 0))
    {
      Report("Failed to open trace file at %s\n", filepath);
      Die();
    }
    char *buff_pos = (char *)trace_buffer;
    while (trace_len > 0)
    {
      uptr write_bytes = internal_write(fd_trace, buff_pos, trace_len);
      if (write_bytes == (uptr)-1 && errno != EINTR)
      {
        Report("Failed to flush trace info in %s, errno=%u\n", filepath, errno);
        Die();
      }
      else
      {
        trace_len -= write_bytes;
        buff_pos += write_bytes;
      }
    }

    internal_close(fd_trace);
  }

  void TraceWriter::flush_metadata()
  {
    if (metadata_buffer == nullptr || metadata_len == 0)
      return;
    char filepath[TREC_DIR_PATH_LEN];

    __sanitizer::internal_snprintf(filepath, TREC_DIR_PATH_LEN - 1,
                                   "%s/trec_%lu/metadata/%d.bin", ctx->trace_dir,
                                   internal_getpid(), id);
    int fd_metadata =
        internal_open(filepath, O_CREAT | O_WRONLY | O_APPEND, 0700);

    if (UNLIKELY(fd_metadata < 0))
    {
      Report("Failed to open metadata file at %s\n", filepath);
      Die();
    }
    char *buff_pos = (char *)metadata_buffer;
    while (metadata_len > 0)
    {
      uptr write_bytes = internal_write(fd_metadata, buff_pos, metadata_len);
      if (write_bytes == (uptr)-1 && errno != EINTR)
      {
        Report("Failed to flush metadata info in %s, errno=%u\n", filepath,
               errno);
        Die();
      }
      else
      {
        metadata_len -= write_bytes;
        buff_pos += write_bytes;
      }
    }

    internal_close(fd_metadata);
  }

  void TraceWriter::flush_header()
  {
    char filepath[TREC_DIR_PATH_LEN];

    __sanitizer::internal_snprintf(filepath, TREC_DIR_PATH_LEN - 1,
                                   "%s/trec_%lu/header/%d.bin", ctx->trace_dir,
                                   internal_getpid(), id);

    int fd_header = internal_open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0700);

    if (UNLIKELY(fd_header < 0))
    {
      Report("Failed to open header file\n");
      Die();
    }
    else
    {
      uptr need_write_bytes = sizeof(header);
      char *buff_pos = (char *)&header;
      while (need_write_bytes > 0)
      {
        uptr write_bytes = internal_write(fd_header, buff_pos, need_write_bytes);
        if (write_bytes == (uptr)-1 && errno != EINTR)
        {
          Report("Failed to flush header in %s, errno=%u\n", filepath, errno);
          Die();
        }
        else
        {
          need_write_bytes -= write_bytes;
          buff_pos += write_bytes;
        }
      }
    }

    internal_close(fd_header);
  }

  bool TraceWriter::state_restore()
  {
    TrecMutexGuard guard(mtx);
    struct stat _st = {0};
    char path[2 * TREC_DIR_PATH_LEN];
    __sanitizer::internal_snprintf(path, 2 * TREC_DIR_PATH_LEN - 1,
                                   "%s/trec_%lu/header/%u.bin", ctx->trace_dir,
                                   internal_getpid(), id);
    uptr IS_EXIST = __sanitizer::internal_stat(path, &_st);
    if (IS_EXIST == 0 && _st.st_size > 0)
    {
      int header_fd = internal_open(path, O_RDONLY);
      if (header_fd < 0)
      {
        Report("Restore header from %s failed\n", path);
        return false;
      }
      else
      {
        internal_read(header_fd, &header, sizeof(header));
        return true;
      }
    }
    return false;
  }

  void TraceWriter::reset()
  {
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

  void TraceWriter::init_cmd()
  {
    TrecMutexGuard guard(mtx);
    char **cmds = GetArgv();
    int cmd_len = 0;
    for (int i = 0; cmds[i]; i++)
    {
      if (i != 0)
      {
        header.cmd[cmd_len++] = ' ';
      }
      cmd_len += internal_strlcpy(header.cmd + cmd_len, cmds[i],
                                  sizeof(header.cmd) - 1 - cmd_len);
    }
  }

  void TraceWriter::pend_param(__sanitizer::u16 idx,
                               __trec_metadata::SourceAddressInfo sa,
                               __sanitizer::u64 val, __sanitizer::u64 debugID)
  {
    if (is_end)
      return;
    __trec_metadata::FuncParamMeta meta(sa, val, debugID);
    params.insert(__sanitizer::detail::DenseMapPair<
                  __sanitizer::u16, __trec_metadata::FuncParamMeta>(idx, meta));
  }

  const __trec_trace::Event *TraceWriter::getLastEvent() const
  {
    if (trace_buffer == nullptr || trace_len < sizeof(__trec_trace::Event))
      return nullptr;
    return (const __trec_trace::Event *)(trace_buffer + trace_len -
                                         sizeof(__trec_trace::Event));
  }

  void TraceWriter::setEnd() { is_end = true; }

  void TraceWriter::registerSymbolizeInfo(const __sanitizer::SymbolizedStack *frame)
  {
    if (ctx->flags.symbolize_at_runtime && metadata_buffer && metadata_len >= sizeof(__trec_metadata::FuncMeta))
    {

      __trec_metadata::FuncMeta *meta = (__trec_metadata::FuncMeta *)(metadata_buffer + metadata_len - sizeof(__trec_metadata::FuncMeta));
      if (meta->debug_id == 0)
      {
        ScopedIgnoreInterceptors ignore;
        ctx->sqlite_mutex.Lock();
        auto sqlite_writer = ctx->getOrInitSqliteWriter();
        if (sqlite_writer)
        {
          int nameA = sqlite_writer->getVarID(frame->info.function ? frame->info.function : "");
          int nameB = sqlite_writer->getFileID(frame->info.file ? frame->info.file : "");
          int line = frame->info.line;
          auto debugID = sqlite_writer->ReformID(sqlite_writer->getDebugInfoID(nameA, nameB, line, 0));
          meta->debug_id = debugID;
        }
        ctx->sqlite_mutex.Unlock();
      }
    }
  }

  // ThreadContext implementation.

  ThreadContext::ThreadContext(int tid)
      : ThreadContextBase(tid), thr(), writer(tid) {}

#if !SANITIZER_GO
  ThreadContext::~ThreadContext() {}
#endif

  void ThreadContext::OnDead() {}

  void ThreadContext::OnJoined(void *arg) {}

  struct OnCreatedArgs
  {
    ThreadState *thr;
    uptr pc;
  };

  void ThreadContext::OnCreated(void *arg) {}

  void ThreadContext::OnReset() {}

  void ThreadContext::OnDetached(void *arg) {}

  struct OnStartedArgs
  {
    ThreadState *thr;
  };

  void ThreadContext::OnStarted(void *arg)
  {
    OnStartedArgs *args = static_cast<OnStartedArgs *>(arg);
    thr = args->thr;
    new (thr) ThreadState(ctx, tid, unique_id);
    thr->is_inited = true;
    DPrintf("#%d: ThreadStart\n", tid);
  }

  void ThreadContext::OnFinished()
  {
#if !SANITIZER_GO
    PlatformCleanUpThreadState(thr);
#endif
    thr->~ThreadState();
    thr = 0;
  }

  void ThreadFinalize(ThreadState *thr)
  {
    if (LIKELY(ctx->flags.output_trace))
    {
      thr->tctx->writer.put_record(__trec_trace::EventType::ThreadEnd,
                                   thr->tid & 0xffff, 0);
    }
  }

  int ThreadCount(ThreadState *thr)
  {
    uptr result;
    ctx->thread_registry->GetNumberOfThreads(0, 0, &result);
    return (int)result;
  }

  int ThreadCreate(ThreadState *thr, uptr pc, uptr uid, bool detached)
  {
    OnCreatedArgs args = {thr, pc};
    u32 parent_tid = thr ? thr->tid : kInvalidTid; // No parent for GCD workers.
    int tid =
        ctx->thread_registry->CreateThread(uid, detached, parent_tid, &args);
    DPrintf("#%d: ThreadCreate tid=%d uid=%zu\n", parent_tid, tid, uid);
    if (tid == 0)
    {
      if (ctx->flags.output_trace)
      {
        const char *trace_dir_env = GetEnv("TREC_TRACE_DIR");
        if (trace_dir_env == nullptr)
        {
          Report("TREC_TRACE_DIR has not been set!\n");
          Die();
        }
        else
          internal_strncpy(ctx->trace_dir, trace_dir_env,
                           internal_strlen(trace_dir_env));
        ctx->open_directory(ctx->trace_dir);
      }
      atomic_store(&ctx->global_id, 0, memory_order_relaxed);
      atomic_store(&ctx->forked_cnt, 0, memory_order_relaxed);
    }
    else if (LIKELY(thr != nullptr && thr->tctx != nullptr) &&
             LIKELY(ctx->flags.output_trace))
    {
      thr->tctx->writer.put_record(__trec_trace::EventType::ThreadCreate,
                                   tid & 0xffff, pc);
    }
    return tid;
  }

  void ThreadStart(ThreadState *thr, int tid, tid_t os_id,
                   ThreadType thread_type)
  {
    ThreadRegistry *tr = ctx->thread_registry;
    OnStartedArgs args = {thr};
    tr->StartThread(tid, os_id, thread_type, &args);

    tr->Lock();
    thr->tctx = (ThreadContext *)tr->GetThreadLocked(tid);
    tr->Unlock();

    // we should put the trace after it thr->tctx has been initialized
    if (LIKELY(ctx->flags.output_trace))
    {
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

  void ThreadFinish(ThreadState *thr)
  {
    if (LIKELY(ctx->flags.output_trace))
    {
      thr->tctx->writer.put_record(__trec_trace::EventType::ThreadEnd, thr->tid,
                                   0);
      thr->tctx->writer.flush_all();
    }
    thr->tctx->writer.reset();
    thr->is_dead = true;
    ctx->thread_registry->FinishThread(thr->tid);
  }

  struct ConsumeThreadContext
  {
    uptr uid;
    ThreadContextBase *tctx;
  };

  int ThreadConsumeTid(ThreadState *thr, uptr pc, uptr uid)
  {
    int tid = ctx->thread_registry->ConsumeThreadUserId(uid);
    DPrintf("#%d: ThreadTid uid=%zu tid=%d\n", thr->tid, uid, tid);
    return tid;
  }

  void ThreadJoin(ThreadState *thr, uptr pc, int tid)
  {
    CHECK_GT(tid, 0);
    CHECK_LT(tid, kMaxTid);
    DPrintf("#%d: ThreadJoin tid=%d\n", thr->tid, tid);
    thr->tctx->writer.put_record(__trec_trace::EventType::ThreadJoin,
                                 tid & 0xffff, pc);

    ctx->thread_registry->JoinThread(tid, thr);
  }

  void ThreadDetach(ThreadState *thr, uptr pc, int tid)
  {
    CHECK_GT(tid, 0);
    CHECK_LT(tid, kMaxTid);
    ctx->thread_registry->DetachThread(tid, thr);
  }

  void ThreadNotJoined(ThreadState *thr, uptr pc, int tid, uptr uid)
  {
    CHECK_GT(tid, 0);
    CHECK_LT(tid, kMaxTid);
    ctx->thread_registry->SetThreadUserId(tid, uid);
  }

  void ThreadSetName(ThreadState *thr, const char *name)
  {
    ctx->thread_registry->SetThreadName(thr->tid, name);
  }

  void MemoryAccessRange(ThreadState *thr, uptr pc, uptr addr, uptr size,
                         bool is_write, __trec_metadata::SourceAddressInfo SAI)
  {
    if (LIKELY(ctx->flags.output_trace) && ctx->flags.record_range &&
        LIKELY(cur_thread()->ignore_interceptors == 0) && SAI.getAsUInt64())
    {
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

} // namespace __trec
