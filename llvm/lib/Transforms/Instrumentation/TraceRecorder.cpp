//===-- TraceRecorder.cpp - race detector -------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of TraceRecorder, a race detector.
//
// The tool is under development, for the details about previous versions see
// http://code.google.com/p/data-race-test
//
// The instrumentation phase is quite simple:
//   - Insert calls to run-time library before every memory access.
//      - Optimizations may apply to avoid instrumenting some of the accesses.
//   - Insert calls at function entry/exit.
// The rest is handled by the run-time library.
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Instrumentation/TraceRecorder.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/InitializePasses.h"
#include "llvm/ProfileData/InstrProf.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/EscapeEnumerator.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <fcntl.h>
#include <filesystem>
#include <sqlite3.h>
#include <sys/file.h>
#include <unistd.h>

using namespace llvm;

#define DEBUG_TYPE "trec"

static cl::opt<bool> ClInstrumentMemoryAccesses(
    "trec-instrument-memory-accesses", cl::init(true),
    cl::desc("Instrument memory accesses"), cl::Hidden);
static cl::opt<bool> ClForceInstrumentAllMemoryAccesses(
    "trec-force-instrument-all-memory-accesses", cl::init(false),
    cl::desc("Force to instrument all memory accesses"), cl::Hidden);
static cl::opt<bool>
    ClInstrumentFuncEntryExit("trec-instrument-func-entry-exit", cl::init(true),
                              cl::desc("Instrument function entry and exit"),
                              cl::Hidden);
static cl::opt<bool> ClInstrumentAtomics("trec-instrument-atomics",
                                         cl::init(true),
                                         cl::desc("Instrument atomics"),
                                         cl::Hidden);
static cl::opt<bool> ClInstrumentMemIntrinsics(
    "trec-instrument-memintrinsics", cl::init(true),
    cl::desc("Instrument memintrinsics (memset/memcpy/memmove)"), cl::Hidden);
static cl::opt<bool> ClInstrumentBranch(
    "trec-instrument-branch", cl::init(true),
    cl::desc("Instrument branch points (indirectcalls/invoke calls/conditional "
             "branches/switches)"),
    cl::Hidden);
static cl::opt<bool>
    ClInstrumentFuncParam("trec-instrument-function-parameters", cl::init(true),
                          cl::desc("Instrument function parameters"),
                          cl::Hidden);

STATISTIC(NumInstrumentedReads, "Number of instrumented reads");
STATISTIC(NumInstrumentedWrites, "Number of instrumented writes");
STATISTIC(NumAllReads, "Number of all reads");
STATISTIC(NumAllWrites, "Number of all writes");
STATISTIC(NumOmittedReadsBeforeWrite,
          "Number of reads ignored due to following writes");
STATISTIC(NumAccessesWithBadSize, "Number of accesses with bad size");
STATISTIC(NumInstrumentedVtableWrites, "Number of vtable ptr writes");
STATISTIC(NumInstrumentedVtableReads, "Number of vtable ptr reads");
STATISTIC(NumOmittedReadsFromConstantGlobals,
          "Number of reads from constant globals");
STATISTIC(NumOmittedReadsFromVtable, "Number of vtable reads");
STATISTIC(NumOmittedNonCaptured, "Number of accesses ignored due to capturing");

const char kTrecModuleCtorName[] = "trec.module_ctor";
const char kTrecInitName[] = "__trec_init";

namespace
{

  class SqliteDebugWriter
  {
    sqlite3 *db;
    int DBID;
    std::filesystem::path DBDirPath;
    std::map<std::string, uint32_t> KnownFileNames, KnownVarNames;
    void insertName(sqlite3_stmt *stmt);
    int insertDebugInfo(int nameA, int nameB, int line, int col);
    int insertFileName(const char *name);
    int insertVarName(const char *name);
    int queryMaxID(const char *table);
    int queryFileID(const char *name);
    int queryVarID(const char *name);
    int queryID(sqlite3_stmt *stmt, const char *name);
    int queryDebugInfoID(int nameA, int nameB, int line, int col);
    sqlite3_stmt *insertFileNameStmt, *insertVarNameStmt, *insertDebugStmt, *queryMaxIDStmt, *queryFileNameStmt, *queryVarNameStmt, *queryDebugStmt, *beginStmt, *commitStmt;

  public:
    SqliteDebugWriter();
    ~SqliteDebugWriter();
    int getFileID(const char *name);
    int getVarID(const char *name);
    int getDebugInfoID(int nameA, int nameB, int line, int col);
    uint64_t ReformID(int ID);
    void commitSQL();

    void beginSQL();
  };

  class SqliteDebugWriterWrapper
  {
    SqliteDebugWriter *ptr;

  public:
    SqliteDebugWriterWrapper() = default;
    ~SqliteDebugWriterWrapper()
    {
      if (ptr)
        delete ptr;
    }
    SqliteDebugWriter *getOrInitDebuger()
    {
      if (ptr == nullptr)
      {
        ptr = new SqliteDebugWriter();
      }
      return ptr;
    }
  };

  /// TraceRecorder: instrument the code in module to record traces.
  ///
  /// Instantiating TraceRecorder inserts the trec runtime library API
  /// function declarations into the module if they don't exist already.
  /// Instantiating ensures the __trec_init function is in the list of global
  /// constructors for the module.
  struct TraceRecorder
  {
    TraceRecorder()
    {
      // Sanity check options and warn user.
    }
    ~TraceRecorder()
    {
      if (getenv("TREC_COMPILE_STAT"))
      {
        printf("loads shrinking: %lu/%lu (%.4lf)\t",
               NumInstrumentedReads.getValue(), NumAllReads.getValue(),
               NumInstrumentedReads.getValue() * 100.0 / NumAllReads.getValue());
        printf("stores shrinking: %lu/%lu (%.4lf)\t",
               NumInstrumentedWrites.getValue(), NumAllWrites.getValue(),
               NumInstrumentedWrites.getValue() * 100.0 /
                   NumAllWrites.getValue());
        printf(
            "total shrinking: %lu/%lu (%.4lf)\n",
            (NumInstrumentedReads.getValue() + NumInstrumentedWrites.getValue()),
            NumAllReads.getValue() + NumAllWrites.getValue(),
            (NumInstrumentedReads.getValue() + NumInstrumentedWrites.getValue()) *
                100.0 / (NumAllReads.getValue() + NumAllWrites.getValue()));
      }
    }

    bool sanitizeFunction(Function &F, const TargetLibraryInfo &TLI);

  private:
    SmallDenseMap<Value *, unsigned int> VarOrders;
    std::map<unsigned int, bool> outsideVars;
    unsigned int VarOrderCounter;
    std::set<Instruction *> SeperatedExits;

    // Internal Instruction wrapper that contains more information about the
    // Instruction from prior analysis.
    struct InstructionInfo
    {
      // Instrumentation emitted for this instruction is for a compounded set of
      // read and write operations in the same basic block.
      static constexpr unsigned kCompoundRW = (1U << 0);

      explicit InstructionInfo(Instruction *Inst) : Inst(Inst) {}

      Instruction *Inst;
      unsigned Flags = 0;
    };
    static SqliteDebugWriterWrapper debuger;
    std::set<Instruction *> StoresToBeInstrumented, LoadsToBeInstrumented;
    std::map<Value *, std::vector<StoreInst *>> AddrAllStores;
    void initialize(Module &M);
    bool instrumentLoadStore(const InstructionInfo &II, const DataLayout &DL);
    bool instrumentAtomic(Instruction *I, const DataLayout &DL);
    bool instrumentBranch(Instruction *I, const DataLayout &DL);
    bool instrumentMemIntrinsic(Instruction *I);
    bool instrumentReturn(Instruction *I);
    bool instrumentFunctionCall(Instruction *I);
    int getMemoryAccessFuncIndex(Type *OrigTy, Value *Addr, const DataLayout &DL);
    class ValSourceInfo
    {
      Value *Addr;  // null if not found in variables
      uint16_t Idx; // index in function call parameters/call return values, start
                    // from 1. 0 if not found in parameters/ret values

      APInt offset;
      bool isDirect, isRealAddr, isValid;

    public:
      ValSourceInfo()
          : Addr(nullptr), Idx(0), offset(14, 0, true), isDirect(false),
            isRealAddr(false), isValid(false) {}
      void setAddr(Value *A, APInt o, bool D)
      {
        Addr = A;
        offset = o;
        isDirect = D;
        isRealAddr = true;
        isValid = true;
      }
      void setIdx(uint16_t i, APInt o, bool D)
      {
        assert(i != 0);
        Idx = i;
        offset = o;
        isDirect = D;
        isRealAddr = false;
        isValid = true;
      }
      Value *Reform(IRBuilder<> &IRB)
      {
        assert(isValid);
        if (isValid)
        {
          if (isRealAddr)
          {
            if (Addr->getType()->isIntegerTy() ||
                Addr->getType()->isPointerTy())
            {
              Value *Addr48Bit = IRB.CreateAnd(
                  IRB.CreateBitOrPointerCast(Addr, IRB.getInt64Ty()),
                  ((1ULL << 48) - 1));
              Value *LabelAndOffset16Bit =
                  IRB.getInt64(((((uint64_t)(isDirect << 1 | isRealAddr)) << 14) |
                                ((*offset.getRawData()) & 0x3fff))
                               << 48);
              return IRB.CreateOr(Addr48Bit, LabelAndOffset16Bit);
            }
          }
          else
          {
            // get from parameters/local function call returns
            Value *Idx48Bit = IRB.getInt64(((uint64_t)Idx) & ((1ULL << 48) - 1));
            Value *LabelAndOffset16Bit = IRB.getInt64(
                ((((((uint64_t)isDirect) << 1 | ((uint64_t)isRealAddr))) << 14) |
                 ((*offset.getRawData()) & 0x3fff))
                << 48);
            return IRB.CreateOr(Idx48Bit, LabelAndOffset16Bit);
          }
        }
        return IRB.getInt64(0);
      }
      bool isNull() { return !isValid; }
      auto getisDirect() const { return isDirect; }
      auto getisRealAddr() const { return isRealAddr; }
      auto getIdx() const { return Idx; }
    };

    // return the source of Val
    // should always be a:
    // 1) global variable
    // 2) function parameter
    // 3) function call return value
    ValSourceInfo getSource(Value *Val, Function *F);
    std::vector<StoreInst *> getAllStoresToAddr(Value *Addr, Function *F);
    bool isReachable(Instruction *From, Instruction *To);
    Value *
    StripCastsAndAccumulateConstantBinaryOffsets(Value *SrcValue, APInt &offset,
                                                 const llvm::DataLayout &DL);
    inline std::string concatFileName(std::filesystem::path dir,
                                      std::filesystem::path file)
    {
      return (dir / file).string();
    }

    Type *IntptrTy;
    FunctionCallee TrecFuncEntry;
    FunctionCallee TrecFuncExit;
    FunctionCallee TrecThreadCreate;
    // Accesses sizes are powers of two: 1, 2, 4, 8.
    static const size_t kNumberOfAccessSizes = 4;
    FunctionCallee TrecRead[kNumberOfAccessSizes];
    FunctionCallee TrecWrite[kNumberOfAccessSizes];
    FunctionCallee TrecUnalignedRead[kNumberOfAccessSizes];
    FunctionCallee TrecUnalignedWrite[kNumberOfAccessSizes];
    FunctionCallee TrecAtomicLoad[kNumberOfAccessSizes];
    FunctionCallee TrecAtomicStore[kNumberOfAccessSizes];
    FunctionCallee TrecAtomicRMW[AtomicRMWInst::LAST_BINOP + 1]
                                [kNumberOfAccessSizes];
    FunctionCallee TrecAtomicCAS[kNumberOfAccessSizes];
    FunctionCallee TrecAtomicThreadFence;
    FunctionCallee TrecAtomicSignalFence;
    FunctionCallee MemmoveFn, MemcpyFn, MemsetFn;
    FunctionCallee TrecBranch;
    FunctionCallee TrecFuncParam;
    FunctionCallee TrecFuncExitParam;
  };
  SqliteDebugWriterWrapper TraceRecorder::debuger;
  void insertModuleCtor(Module &M)
  {
    getOrCreateSanitizerCtorAndInitFunctions(
        M, kTrecModuleCtorName, kTrecInitName, /*InitArgTypes=*/{},
        /*InitArgs=*/{},
        // This callback is invoked when the functions are created the first
        // time. Hook them into the global ctors list in that case:
        [&](Function *Ctor, FunctionCallee)
        { appendToGlobalCtors(M, Ctor, 0); });
  }

  int query_callback(void *ret, int argc, char **argv, char **azColName)
  {
    assert(argc == 1);
    *(int *)ret = atoi(argv[0]);
    return 0;
  }

  void SqliteDebugWriter::insertName(sqlite3_stmt *stmt)
  {

    int status = sqlite3_step(stmt);
    if (status != SQLITE_DONE)
    {
      printf("insert error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
  }

  int SqliteDebugWriter::insertDebugInfo(int nameA, int nameB, int line,
                                         int col)
  {
    sqlite3_reset(insertDebugStmt);
    int status = sqlite3_bind_int(insertDebugStmt, 1, nameA);
    if (status != SQLITE_OK)
    {
      printf("bind 1st param to insertDebugInfo statement error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    status = sqlite3_bind_int(insertDebugStmt, 2, nameB);
    if (status != SQLITE_OK)
    {
      printf("bind 2nd param to insertDebugInfo statement error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    status = sqlite3_bind_int(insertDebugStmt, 3, line);
    if (status != SQLITE_OK)
    {
      printf("bind 3rd param to insertDebugInfo statement error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    status = sqlite3_bind_int(insertDebugStmt, 4, col);
    if (status != SQLITE_OK)
    {
      printf("bind 4th param to insertDebugInfo statement error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };

    status = sqlite3_step(insertDebugStmt);
    if (status != SQLITE_DONE)
    {
      printf("insert debug error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    return queryMaxID("DEBUGINFO");
  }

  int SqliteDebugWriter::queryMaxID(const char *table)
  {
    int ID = -1;
    sqlite3_reset(queryMaxIDStmt);
    int status = sqlite3_bind_text(queryMaxIDStmt, 1, table, -1, nullptr);
    if (status != SQLITE_OK)
    {
      printf("bind param to queryMaxIDStmt statement error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    status = sqlite3_step(queryMaxIDStmt);
    if (status != SQLITE_ROW)
    {
      printf("query maxID error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    ID = atoi((const char *)sqlite3_column_text(queryMaxIDStmt, 0));
    if (ID == -1)
    {
      printf("query error: cannot query last inserted ID for table %s\n", table);
      exit(1);
    }
    return ID;
  }

  int SqliteDebugWriter::queryFileID(const char *name)
  {
    return queryID(queryFileNameStmt, name);
  }

  int SqliteDebugWriter::queryVarID(const char *name)
  {
    return queryID(queryVarNameStmt, name);
  }

  int SqliteDebugWriter::queryID(sqlite3_stmt *stmt, const char *name)
  {
    if (strcmp(name, "") == 0)
      return 1;
    int ID = -1;
    sqlite3_reset(stmt);
    int status = sqlite3_bind_text(stmt, 1, name, -1, nullptr);
    if (status != SQLITE_OK)
    {
      printf("bind param to query statement error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    status = sqlite3_step(stmt);
    if (status == SQLITE_ROW)
    {
      ID = atoi((const char *)sqlite3_column_text(stmt, 0));
    }
    else if (status != SQLITE_DONE)
    {
      printf("query ID error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };

    return ID;
  }

  int SqliteDebugWriter::queryDebugInfoID(int nameA, int nameB, int line,
                                          int col)
  {
    int ID = -1;
    sqlite3_reset(queryDebugStmt);
    int status = sqlite3_bind_int(queryDebugStmt, 1, nameA);
    if (status != SQLITE_OK)
    {
      printf("bind 1st param to queryDebugStmt statement error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    status = sqlite3_bind_int(queryDebugStmt, 2, nameB);
    if (status != SQLITE_OK)
    {
      printf("bind 2nd param to queryDebugStmt statement error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    status = sqlite3_bind_int(queryDebugStmt, 3, line);
    if (status != SQLITE_OK)
    {
      printf("bind 3rd param to queryDebugStmt statement error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    status = sqlite3_bind_int(queryDebugStmt, 4, col);
    if (status != SQLITE_OK)
    {
      printf("bind 4th param to queryDebugStmt statement error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    status = sqlite3_step(queryDebugStmt);
    if (status == SQLITE_ROW)
    {
      ID = atoi((const char *)sqlite3_column_text(queryDebugStmt, 0));
    }
    else if (status != SQLITE_DONE)
    {
      printf("query debug error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };

    return ID;
  }

  void SqliteDebugWriter::commitSQL()
  {
    int status;
    while ((status = sqlite3_step(commitStmt)) ==
           SQLITE_BUSY)
      ;
    if (status != SQLITE_DONE)
    {
      printf("commit sqlite error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
  }

  void SqliteDebugWriter::beginSQL()
  {
    int status = sqlite3_step(beginStmt);
    if (status != SQLITE_DONE)
    {
      printf("begin sqlite error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
  }

  uint64_t SqliteDebugWriter::ReformID(int ID)
  {
    assert(DBID >= 1);
    assert(ID >= 1);
    return (((uint64_t)DBID & ((1ULL << 16) - 1)) << 48) |
           ((uint64_t)ID & ((1ULL << 48) - 1));
  }

  SqliteDebugWriter::SqliteDebugWriter() : db(nullptr), DBID(-1), insertFileNameStmt(nullptr), insertVarNameStmt(nullptr), insertDebugStmt(nullptr), queryMaxIDStmt(nullptr), queryFileNameStmt(nullptr), queryVarNameStmt(nullptr), queryDebugStmt(nullptr), beginStmt(nullptr), commitStmt(nullptr)
  {
    char *DatabaseDir = getenv("TREC_DATABASE_DIR");
    if (DatabaseDir == nullptr)
    {
      printf("ERROR: ENV variable `TREC_DATABASE_DIR` has not been set!\n");
      exit(-1);
    }
    DBDirPath = std::filesystem::path(DatabaseDir);
    int pid = getpid();
    std::filesystem::path managerDBPath =
        DBDirPath / std::filesystem::path("manager.db");
    int status;
    // open sqlite database
    status = sqlite3_open(managerDBPath.c_str(), &db);
    if (status)
    {
      printf("Open manager databased %s failed(%d): %s\n", managerDBPath.c_str(),
             status, sqlite3_errmsg(db));
      exit(status);
    }

    // acquire flock
    int database_fd = open(managerDBPath.c_str(), O_RDONLY);
    if ((status = flock(database_fd, LOCK_EX)) != 0)
    {
      printf("ERROR: acquire flock for manager database %s failed(%d)\n",
             managerDBPath.c_str(), status);
      exit(status);
    }

    status = sqlite3_exec(db,
                          "CREATE TABLE MANAGER (ID INTEGER PRIMARY KEY "
                          "AUTOINCREMENT, PID INTEGER);",
                          nullptr, nullptr, nullptr);
    if (status != SQLITE_OK &&
        !(status == SQLITE_ERROR &&
          strcmp(sqlite3_errmsg(db), "table MANAGER already exists") == 0))
    {
      printf("create table error(%d)\n", status);
      exit(status);
    };

    bool isCreated = false;
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "SELECT ID from MANAGER where PID=%d;", pid);
    status = sqlite3_exec(db, buffer, query_callback, &DBID, nullptr);
    if (status != SQLITE_OK)
    {
      printf("query manager table error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };
    while (DBID == -1)
    {
      snprintf(buffer, sizeof(buffer),
               "SELECT ID from MANAGER where PID IS NULL;");
      status = sqlite3_exec(db, buffer, query_callback, &DBID, nullptr);
      if (status != SQLITE_OK)
      {
        printf("query manager table error(%d): %s\n", status, sqlite3_errmsg(db));
        exit(status);
      };
      if (DBID == -1)
      {
        // no empty entry
        isCreated = true;
        snprintf(buffer, sizeof(buffer),
                 "INSERT INTO MANAGER VALUES (NULL, NULL);");
        while ((status = sqlite3_exec(db, buffer, nullptr, nullptr, nullptr)) ==
               SQLITE_BUSY)
          ;
        if (status != SQLITE_OK)
        {
          printf("insert manager table error(%d): %s\n", status, sqlite3_errmsg(db));
          exit(status);
        };
      }
    }
    snprintf(buffer, sizeof(buffer), "UPDATE MANAGER SET PID=%d where ID=%d;",
             pid, DBID);
    status = sqlite3_exec(db, buffer, nullptr, nullptr, nullptr);
    if (status != SQLITE_OK)
    {
      printf("update manager table error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };

    // release flock
    if ((status = flock(database_fd, LOCK_UN)) != 0)
    {
      printf("ERROR: release flock failed\n");
      exit(status);
    }
    close(database_fd);

    // close manager database
    sqlite3_close(db);

    snprintf(buffer, sizeof(buffer), "%s/debuginfo%d.db", DBDirPath.c_str(),
             DBID);
    sqlite3_open(buffer, &db);
    if (status)
    {
      printf("open %s file failed(%d): %s\n", buffer, status, sqlite3_errmsg(db));
      exit(status);
    }

    // speedup querying
    status =
        sqlite3_exec(db, "PRAGMA synchronous=OFF;", nullptr, nullptr, nullptr);
    if (status != SQLITE_OK)
    {
      printf("trun off synchronous mode failed: %s\n", sqlite3_errmsg(db));
      exit(status);
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
                            nullptr, nullptr, nullptr);
      if (status)
      {
        printf("create subtables failed %d: %s\n", status, sqlite3_errmsg(db));
        exit(status);
      }
    }

    // initialize statments
    {
      status = sqlite3_prepare_v2(db, "INSERT INTO DEBUGVARNAME VALUES (NULL, ?);", -1, &insertVarNameStmt, nullptr);
      if (status != SQLITE_OK)
      {
        printf("prepare sqlite statement '%s' failed: %s\n", "INSERT INTO DEBUGVARNAME VALUES (NULL, ?);", sqlite3_errmsg(db));
        exit(status);
      }
      status = sqlite3_prepare_v2(db, "INSERT INTO DEBUGFILENAME VALUES (NULL, ?);", -1, &insertFileNameStmt, nullptr);
      if (status != SQLITE_OK)
      {
        printf("prepare sqlite statement '%s' failed: %s\n", "INSERT INTO DEBUGFILENAME VALUES (NULL, ?);", sqlite3_errmsg(db));
        exit(status);
      }
      status = sqlite3_prepare_v2(db, "INSERT INTO DEBUGINFO VALUES (NULL, ?, ?, ?, ?);", -1, &insertDebugStmt, nullptr);
      if (status != SQLITE_OK)
      {
        printf("prepare sqlite statement '%s' failed: %s\n", "INSERT INTO DEBUGINFO VALUES (NULL, ?, ?, ?, ?);", sqlite3_errmsg(db));
        exit(status);
      }
      status = sqlite3_prepare_v2(db, "select seq from sqlite_sequence where name=?;", -1, &queryMaxIDStmt, nullptr);
      if (status != SQLITE_OK)
      {
        printf("prepare sqlite statement '%s' failed: %s\n", "select seq from sqlite_sequence where name=?;", sqlite3_errmsg(db));
        exit(status);
      }
      status = sqlite3_prepare_v2(db, "SELECT ID from DEBUGFILENAME where NAME=?;", -1, &queryFileNameStmt, nullptr);
      if (status != SQLITE_OK)
      {
        printf("prepare sqlite statement '%s' failed: %s\n", "SELECT ID from DEBUGFILENAME where NAME=?;", sqlite3_errmsg(db));
        exit(status);
      }
      status = sqlite3_prepare_v2(db, "SELECT ID from DEBUGVARNAME where NAME=?;", -1, &queryVarNameStmt, nullptr);
      if (status != SQLITE_OK)
      {
        printf("prepare sqlite statement '%s' failed: %s\n", "SELECT ID from DEBUGVARNAME where NAME=?;", sqlite3_errmsg(db));
        exit(status);
      }
      status = sqlite3_prepare_v2(db, "SELECT ID from DEBUGINFO where NAMEIDA=? AND NAMEIDB=? AND "
                                      "LINE=? AND COL=?;",
                                  -1, &queryDebugStmt, nullptr);
      if (status != SQLITE_OK)
      {
        printf("prepare sqlite statement '%s' failed: %s\n", "SELECT ID from DEBUGINFO where NAMEIDA=? AND NAMEIDB=? AND "
                                                             "LINE=? AND COL=?;",
               sqlite3_errmsg(db));
        exit(status);
      }
      status = sqlite3_prepare_v2(db, "BEGIN;", -1, &beginStmt, nullptr);
      if (status != SQLITE_OK)
      {
        printf("prepare sqlite statement '%s' failed: %s\n", "BEGIN;", sqlite3_errmsg(db));
        exit(status);
      }
      status = sqlite3_prepare_v2(db, "COMMIT;", -1, &commitStmt, nullptr);
      if (status != SQLITE_OK)
      {
        printf("prepare sqlite statement '%s' failed: %s\n", "COMMIT;", sqlite3_errmsg(db));
        exit(status);
      }
    }
  }
  SqliteDebugWriter::~SqliteDebugWriter()
  {
    if (insertFileNameStmt)
      sqlite3_finalize(insertFileNameStmt);
    if (insertVarNameStmt)
      sqlite3_finalize(insertVarNameStmt);
    if (insertDebugStmt)
      sqlite3_finalize(insertDebugStmt);
    if (queryMaxIDStmt)
      sqlite3_finalize(queryMaxIDStmt);
    if (queryFileNameStmt)
      sqlite3_finalize(queryFileNameStmt);
    if (queryVarNameStmt)
      sqlite3_finalize(queryVarNameStmt);
    if (queryDebugStmt)
      sqlite3_finalize(queryDebugStmt);
    if (beginStmt)
      sqlite3_finalize(beginStmt);
    if (commitStmt)
      sqlite3_finalize(commitStmt);
    sqlite3_close(db);

    std::filesystem::path managerDBPath =
        DBDirPath / std::filesystem::path("manager.db");
    int status;
    int database_fd = open(managerDBPath.c_str(), O_RDONLY);
    if ((status = flock(database_fd, LOCK_EX)) != 0)
    {
      printf("ERROR: acquire flock failed\n");
      exit(status);
    }
    status = sqlite3_open(managerDBPath.c_str(), &db);
    if (status)
    {
      printf("Open manager databased %s failed(%d): %s\n", managerDBPath.c_str(),
             status, sqlite3_errmsg(db));
      exit(status);
    }
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "UPDATE MANAGER SET PID=NULL where ID=%d;",
             DBID);
    status = sqlite3_exec(db, buffer, nullptr, nullptr, nullptr);
    if (status != SQLITE_OK)
    {
      printf("update manager table error(%d): %s\n", status, sqlite3_errmsg(db));
      exit(status);
    };

    sqlite3_close(db);
    if ((status = flock(database_fd, LOCK_UN)) != 0)
    {
      printf("ERROR: release flock failed\n");
      exit(status);
    }
    close(database_fd);
  }
  int SqliteDebugWriter::getFileID(const char *name)
  {
    if (!KnownFileNames.count(name))
    {
      int ID = queryFileID(name);
      if (ID == -1)
      {
        ID = insertFileName(name);
      }
      KnownFileNames[name] = ID;
    }
    return KnownFileNames.at(name);
  }
  int SqliteDebugWriter::getVarID(const char *name)
  {
    if (!KnownVarNames.count(name))
    {
      int ID = queryVarID(name);
      if (ID == -1)
      {
        ID = insertVarName(name);
      }
      KnownVarNames[name] = ID;
    }
    return KnownVarNames.at(name);
  }
  int SqliteDebugWriter::getDebugInfoID(int nameA, int nameB, int line, int col)
  {
    int ID = queryDebugInfoID(nameA, nameB, line, col);
    if (ID == -1)
      ID = insertDebugInfo(nameA, nameB, line, col);
    return ID;
  }
  int SqliteDebugWriter::insertFileName(const char *name)
  {
    sqlite3_reset(insertFileNameStmt);
    int status = sqlite3_bind_text(insertFileNameStmt, 1, name, -1, nullptr);
    if (status != SQLITE_OK)
    {
      printf("bind text to insertFileNameStmt failed: %s", sqlite3_errmsg(db));
      exit(status);
    }
    insertName(insertFileNameStmt);
    return queryMaxID("DEBUGFILENAME");
  }
  int SqliteDebugWriter::insertVarName(const char *name)
  {
    sqlite3_reset(insertVarNameStmt);
    int status = sqlite3_bind_text(insertVarNameStmt, 1, name, -1, nullptr);
    if (status != SQLITE_OK)
    {
      printf("bind text to insertVarNameStmt failed: %s", sqlite3_errmsg(db));
      exit(status);
    }
    insertName(insertVarNameStmt);
    return queryMaxID("DEBUGVARNAME");
  }
} // namespace

PreservedAnalyses TraceRecorderPass::run(Function &F,
                                         FunctionAnalysisManager &FAM)
{
  TraceRecorder TRec;
  if (TRec.sanitizeFunction(F, FAM.getResult<TargetLibraryAnalysis>(F)))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

PreservedAnalyses ModuleTraceRecorderPass::run(Module &M,
                                               ModuleAnalysisManager &MAM)
{
  insertModuleCtor(M);
  return PreservedAnalyses::none();
}

void TraceRecorder::initialize(Module &M)
{
  const DataLayout &DL = M.getDataLayout();
  IntptrTy = DL.getIntPtrType(M.getContext());
  IRBuilder<> IRB(M.getContext());
  AttributeList Attr;
  Attr = Attr.addFnAttribute(M.getContext(), Attribute::NoUnwind);
  // Initialize the callbacks.
  TrecFuncEntry = M.getOrInsertFunction("__trec_func_entry", Attr,
                                        IRB.getVoidTy(), IRB.getInt16Ty(),
                                        IRB.getInt16Ty(), IRB.getInt64Ty(), IRB.getInt8PtrTy());
  TrecFuncExit = M.getOrInsertFunction("__trec_func_exit", Attr,
                                       IRB.getVoidTy(), IRB.getInt64Ty());
  TrecThreadCreate =
      M.getOrInsertFunction("__trec_thread_create", Attr, IRB.getVoidTy(),
                            IRB.getInt8PtrTy(), IRB.getInt64Ty());
  IntegerType *OrdTy = IRB.getInt32Ty();
  for (size_t i = 0; i < kNumberOfAccessSizes; ++i)
  {
    const unsigned ByteSize = 1U << i;
    const unsigned BitSize = ByteSize * 8;
    std::string ByteSizeStr = utostr(ByteSize);
    std::string BitSizeStr = utostr(BitSize);
    SmallString<32> ReadName("__trec_read" + ByteSizeStr);
    TrecRead[i] = M.getOrInsertFunction(
        ReadName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(), IRB.getInt1Ty(),
        IRB.getInt8PtrTy(), IRB.getInt64Ty(), IRB.getInt64Ty());
    SmallString<32> WriteName("__trec_write" + ByteSizeStr);
    TrecWrite[i] = M.getOrInsertFunction(WriteName, Attr, IRB.getVoidTy(),
                                         IRB.getInt8PtrTy(), IRB.getInt1Ty(),
                                         IRB.getInt8PtrTy(), IRB.getInt64Ty(),
                                         IRB.getInt64Ty(), IRB.getInt64Ty());
    SmallString<64> UnalignedReadName("__trec_unaligned_read" + ByteSizeStr);
    TrecUnalignedRead[i] = M.getOrInsertFunction(
        UnalignedReadName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(),
        IRB.getInt1Ty(), IRB.getInt8PtrTy(), IRB.getInt64Ty(),
        IRB.getInt64Ty());

    SmallString<64> UnalignedWriteName("__trec_unaligned_write" + ByteSizeStr);
    TrecUnalignedWrite[i] = M.getOrInsertFunction(
        UnalignedWriteName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(),
        IRB.getInt1Ty(), IRB.getInt8PtrTy(), IRB.getInt64Ty(), IRB.getInt64Ty(),
        IRB.getInt64Ty());

    Type *Ty = Type::getIntNTy(M.getContext(), BitSize);
    Type *PtrTy = Ty->getPointerTo();
    Type *BoolTy = Type::getInt1Ty(M.getContext());
    Type *debugTy = Type::getInt64Ty(M.getContext());
    SmallString<32> AtomicLoadName("__trec_atomic" + BitSizeStr + "_load");
    TrecAtomicLoad[i] = M.getOrInsertFunction(AtomicLoadName, Attr, Ty, PtrTy,
                                              OrdTy, BoolTy, debugTy);

    SmallString<32> AtomicStoreName("__trec_atomic" + BitSizeStr + "_store");
    TrecAtomicStore[i] =
        M.getOrInsertFunction(AtomicStoreName, Attr, IRB.getVoidTy(), PtrTy, Ty,
                              OrdTy, BoolTy, debugTy);

    for (unsigned Op = AtomicRMWInst::FIRST_BINOP;
         Op <= AtomicRMWInst::LAST_BINOP; ++Op)
    {
      TrecAtomicRMW[Op][i] = nullptr;
      const char *NamePart = nullptr;
      if (Op == AtomicRMWInst::Xchg)
        NamePart = "_exchange";
      else if (Op == AtomicRMWInst::Add)
        NamePart = "_fetch_add";
      else if (Op == AtomicRMWInst::Sub)
        NamePart = "_fetch_sub";
      else if (Op == AtomicRMWInst::And)
        NamePart = "_fetch_and";
      else if (Op == AtomicRMWInst::Or)
        NamePart = "_fetch_or";
      else if (Op == AtomicRMWInst::Xor)
        NamePart = "_fetch_xor";
      else if (Op == AtomicRMWInst::Nand)
        NamePart = "_fetch_nand";
      else
        continue;
      SmallString<32> RMWName("__trec_atomic" + itostr(BitSize) + NamePart);
      TrecAtomicRMW[Op][i] = M.getOrInsertFunction(RMWName, Attr, Ty, PtrTy, Ty,
                                                   OrdTy, BoolTy, debugTy);
    }

    SmallString<32> AtomicCASName("__trec_atomic" + BitSizeStr +
                                  "_compare_exchange_val");
    TrecAtomicCAS[i] = M.getOrInsertFunction(AtomicCASName, Attr, Ty, PtrTy, Ty,
                                             Ty, OrdTy, OrdTy, BoolTy, debugTy);
  }
  TrecAtomicThreadFence = M.getOrInsertFunction("__trec_atomic_thread_fence",
                                                Attr, IRB.getVoidTy(), OrdTy);
  TrecAtomicSignalFence = M.getOrInsertFunction("__trec_atomic_signal_fence",
                                                Attr, IRB.getVoidTy(), OrdTy);

  MemmoveFn =
      M.getOrInsertFunction("memmove", Attr, IRB.getInt8PtrTy(),
                            IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IntptrTy);
  MemcpyFn =
      M.getOrInsertFunction("memcpy", Attr, IRB.getInt8PtrTy(),
                            IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IntptrTy);
  MemsetFn =
      M.getOrInsertFunction("memset", Attr, IRB.getInt8PtrTy(),
                            IRB.getInt8PtrTy(), IRB.getInt32Ty(), IntptrTy);
  TrecBranch = M.getOrInsertFunction("__trec_branch", Attr, IRB.getVoidTy(),
                                     IRB.getInt8PtrTy(), IRB.getInt64Ty(),
                                     IRB.getInt64Ty());
  TrecFuncParam = M.getOrInsertFunction(
      "__trec_func_param", Attr, IRB.getVoidTy(), IRB.getInt16Ty(),
      IRB.getInt64Ty(), IRB.getInt8PtrTy(), IRB.getInt64Ty());
  TrecFuncExitParam = M.getOrInsertFunction(
      "__trec_func_exit_param", Attr, IRB.getVoidTy(), IRB.getInt64Ty(),
      IRB.getInt8PtrTy(), IRB.getInt64Ty());
}

static bool isVtableAccess(Instruction *I)
{
  if (MDNode *Tag = I->getMetadata(LLVMContext::MD_tbaa))
    return Tag->isTBAAVtableAccess();
  return false;
}

static bool isAtomic(Instruction *I)
{
  // TODO: Ask TTI whether synchronization scope is between threads.
  if (LoadInst *LI = dyn_cast<LoadInst>(I))
    return LI->isAtomic() && LI->getSyncScopeID() != SyncScope::SingleThread;
  if (StoreInst *SI = dyn_cast<StoreInst>(I))
    return SI->isAtomic() && SI->getSyncScopeID() != SyncScope::SingleThread;
  if (isa<AtomicRMWInst>(I))
    return true;
  if (isa<AtomicCmpXchgInst>(I))
    return true;
  if (isa<FenceInst>(I))
    return true;
  return false;
}

bool TraceRecorder::sanitizeFunction(Function &F,
                                     const TargetLibraryInfo &TLI)
{
  // This is required to prevent instrumenting call to __trec_init from
  // within the module constructor.
  if (F.getName() == kTrecModuleCtorName)
    return false;
  // If we cannot find the source file, then this function may not be written by
  // user.
  // Do not instrument it.
  if (F.getSubprogram() == nullptr || F.getSubprogram()->getFile() == nullptr)
    return false;

  debuger.getOrInitDebuger()->beginSQL();
  initialize(*F.getParent());
  VarOrders.clear();
  VarOrderCounter = 1;
  int arg_size = F.arg_size();
  for (int idx = 0; idx < arg_size; idx++)
  {
    VarOrders[F.getArg(idx)] = VarOrderCounter;
    outsideVars[VarOrderCounter] = true;
    VarOrderCounter += 1;
  }
  StoresToBeInstrumented.clear();
  LoadsToBeInstrumented.clear();
  AddrAllStores.clear();
  SeperatedExits.clear();
  SmallVector<Instruction *> AtomicAccesses;
  SmallVector<Instruction *> MemIntrinCalls;
  SmallVector<Instruction *> Branches;
  SmallVector<Instruction *> FuncCalls;
  SmallVector<Instruction *> Returns;

  bool Res = false;
  const DataLayout &DL = F.getParent()->getDataLayout();

  // We must instrument atomic and mem-intrinsic instructions first.
  // The later on __trec_func_entry/__trec_func_exit needs to instrument them.
  for (auto &BB : F)
  {
    for (auto &Inst : BB)
    {
      if (isAtomic(&Inst))
        AtomicAccesses.push_back(&Inst);
      if (isa<MemSetInst>(Inst) || isa<MemCpyInst>(Inst) ||
          isa<MemMoveInst>(Inst))
        MemIntrinCalls.push_back(&Inst);
    }
  }
  if (ClInstrumentAtomics)
    for (auto Inst : AtomicAccesses)
    {
      Res |= instrumentAtomic(Inst, DL);
    }
  if (ClInstrumentMemIntrinsics)
    for (auto Inst : MemIntrinCalls)
    {
      Res |= instrumentMemIntrinsic(Inst);
    }

  // Traverse all instructions, collect loads/stores/calls/branches.
  for (auto &BB : F)
  {
    for (auto &Inst : BB)
    {
      if (isa<LoadInst>(Inst))
      {
        LoadInst *LI = dyn_cast<LoadInst>(&Inst);
        if (ClForceInstrumentAllMemoryAccesses)
          LoadsToBeInstrumented.insert(LI);
        NumAllReads++;
      }
      else if (isa<StoreInst>(Inst))
      {
        StoreInst *SI = dyn_cast<StoreInst>(&Inst);
        if (isa<GlobalVariable>(SI->getPointerOperand()) ||
            ClForceInstrumentAllMemoryAccesses)
          StoresToBeInstrumented.insert(SI);
        NumAllWrites++;
      }
      else if (isa<CallInst>(Inst) || isa<InvokeInst>(Inst))
      {
        FuncCalls.push_back(&Inst);

        // Although these are also branches, we do not instrument them because
        // we cannot get to know the exact conditional variable that causes the
        // branch choosing (as the branch choosing may be caused by exceptions
        // inside the called function, which cannot be seen at this point).

        // if (isa<InvokeInst>(Inst) ||
        //     dyn_cast<CallBase>(&Inst)->getCalledFunction() == nullptr) {
        //   Branches.push_back(&Inst);
        // }

        if (CallInst *CI = dyn_cast<CallInst>(&Inst))
        {
          maybeMarkSanitizerLibraryCallNoBuiltin(CI, &TLI);
        }
      }
      else if (isa<BranchInst>(Inst) &&
               dyn_cast<BranchInst>(&Inst)->isConditional())
      {
        Branches.push_back(&Inst); // conditional branch
      }
      else if (isa<SwitchInst>(Inst))
      {
        Branches.push_back(&Inst); // switch
      }
      else if (isa<IndirectBrInst>(Inst))
      {
        Branches.push_back(&Inst);
      }
      else if (isa<ReturnInst>(Inst))
      {
        Returns.push_back(&Inst); // function return
      }
    }
  }

  // branches must be instrumented before function entries/exits
  if (ClInstrumentFuncParam)
  {
    for (auto Inst : FuncCalls)
    {
      Res |= instrumentFunctionCall(Inst);
    }
    for (auto Inst : Returns)
    {
      Res |= instrumentReturn(Inst);
    }
  }
  if (ClInstrumentBranch)
    for (auto Inst : Branches)
    {
      Res |= instrumentBranch(Inst, DL);
    }

  // deal with cpp name mangling
  // getName() may return the name after mangling.
  // use getSubprogram()->getName() if possible
  StringRef FuncName = F.getName();
  int line = 0;
  if (F.getSubprogram())
  {
    FuncName = F.getSubprogram()->getName();
    line = F.getSubprogram()->getLine();
  }

  // The main function has no parent function.
  // So explicitly record its entry and exit(s).
  // For the main function, we cannot figure out where its parameters come from.
  // So we only record __trec_func_entry and __trec_func_exit.
  if (FuncName == "main")
  {
    IRBuilder<> IRB(&*F.getEntryBlock().getFirstInsertionPt());
    std::string CurrentFileName = "";
    if (F.getSubprogram()->getFile())
    {
      CurrentFileName =
          concatFileName(F.getSubprogram()->getFile()->getDirectory().str(),
                         F.getSubprogram()->getFile()->getFilename().str());
    }
    int nameA = debuger.getOrInitDebuger()->getVarID(FuncName.str().c_str());
    int nameB = debuger.getOrInitDebuger()->getFileID(CurrentFileName.c_str());
    int col = 0;
    uint64_t debugID =
        debuger.getOrInitDebuger()->ReformID(debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col));

    IRB.CreateCall(TrecFuncEntry, {IRB.getInt16(1), IRB.getInt16(F.arg_size()),
                                   IRB.getInt64(debugID), IRB.CreateBitOrPointerCast(IRB.getInt64(0), IRB.getInt8PtrTy())});
    EscapeEnumerator EE(F);
    while (IRBuilder<> *AtExit = EE.Next())
    {
      AtExit->CreateCall(TrecFuncExit, {AtExit->getInt64(debugID)});
    }
    Res |= true;
  }

  if (ClInstrumentMemoryAccesses)
  {
    std::set<Instruction *> instrumentedStores, instrumentedLoads;
    while (instrumentedStores != StoresToBeInstrumented ||
           instrumentedLoads != LoadsToBeInstrumented)
    {
      for (auto item : StoresToBeInstrumented)
      {
        if (!instrumentedStores.count(item))
        {
          Res |= instrumentLoadStore(InstructionInfo(item), DL);
          instrumentedStores.insert(item);
        }
      }
      for (auto item : LoadsToBeInstrumented)
      {
        if (!instrumentedLoads.count(item))
        {
          Res |= instrumentLoadStore(InstructionInfo(item), DL);
          instrumentedLoads.insert(item);
        }
      }
    }
  }
  debuger.getOrInitDebuger()->commitSQL();
  return Res;
}

bool TraceRecorder::instrumentBranch(Instruction *I, const DataLayout &DL)
{
  if (I->getDebugLoc().isImplicitCode())
    return false;
  IRBuilder<> IRB(I);
  bool Res = false;
  Function *F = I->getParent()->getParent();
  if (isa<BranchInst>(I))
  {
    BranchInst *Br = dyn_cast<BranchInst>(I);
    Value *cond = Br->getCondition();
    int nameA = debuger.getOrInitDebuger()->getVarID(cond->getName().str().c_str());
    int nameB = 0;
    int line = Br->getDebugLoc().getLine();
    int col = Br->getDebugLoc().getCol();
    uint64_t debugID =
        debuger.getOrInitDebuger()->ReformID(debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col));
    ValSourceInfo VSI = getSource(cond, F);
    IRB.CreateCall(TrecBranch,
                   {IRB.CreateBitOrPointerCast(cond, IRB.getInt8PtrTy()),
                    VSI.Reform(IRB), IRB.getInt64(debugID)});
    Res |= true;
  }
  else if (isa<SwitchInst>(I))
  {
    SwitchInst *sw = dyn_cast<SwitchInst>(I);
    Value *cond = sw->getCondition();
    int nameA = debuger.getOrInitDebuger()->getVarID(cond->getName().str().c_str());
    int nameB = 0;
    int line = sw->getDebugLoc().getLine();
    int col = sw->getDebugLoc().getCol();
    uint64_t debugID =
        debuger.getOrInitDebuger()->ReformID(debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col));
    ValSourceInfo VSI = getSource(cond, F);
    IRB.CreateCall(TrecBranch,
                   {IRB.CreateBitOrPointerCast(cond, IRB.getInt8PtrTy()),
                    VSI.Reform(IRB), IRB.getInt64(debugID)});
    Res |= true;
  }
  else if (isa<IndirectBrInst>(I))
  {
    IndirectBrInst *IBr = dyn_cast<IndirectBrInst>(I);
    Value *cond = IBr->getAddress();
    int nameA = debuger.getOrInitDebuger()->getVarID(cond->getName().str().c_str());
    int nameB = 0;
    int line = IBr->getDebugLoc().getLine();
    int col = IBr->getDebugLoc().getCol();
    uint64_t debugID =
        debuger.getOrInitDebuger()->ReformID(debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col));
    ValSourceInfo VSI = getSource(cond, F);
    IRB.CreateCall(TrecBranch,
                   {IRB.CreateBitOrPointerCast(cond, IRB.getInt8PtrTy()),
                    VSI.Reform(IRB), IRB.getInt64(debugID)});
    Res |= true;
  }
  return Res;
}

bool TraceRecorder::instrumentReturn(Instruction *I)
{
  IRBuilder<> IRB(I);
  ValSourceInfo VSI_val;
  Value *RetVal = dyn_cast<ReturnInst>(I)->getReturnValue();
  bool res = false;
  if (RetVal)
  {
    auto stores = getAllStoresToAddr(RetVal, I->getParent()->getParent());
    for (auto &store : stores)
    {
      StoresToBeInstrumented.emplace(store);
    }
    auto VSI_val = getSource(RetVal, I->getParent()->getParent());
    VSI_val.Reform(IRB);
    Value *RetValInst = nullptr;
    if (RetVal->getType()->isPointerTy() || RetVal->getType()->isIntegerTy())
      RetValInst = IRB.CreateBitOrPointerCast(RetVal, IRB.getInt8PtrTy());
    else
      RetValInst = IRB.CreateIntToPtr(IRB.getInt64(0), IRB.getInt8PtrTy());
    if (RetValInst)
    {
      int nameA = debuger.getOrInitDebuger()->getVarID(RetVal->getName().str().c_str());
      int nameB = 0;
      int line = I->getDebugLoc().getLine();
      int col = I->getDebugLoc().getCol();
      uint64_t debugID =
          debuger.getOrInitDebuger()->ReformID(debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col));
      IRB.CreateCall(TrecFuncExitParam,
                     {VSI_val.Reform(IRB), RetValInst, IRB.getInt64(debugID)});
      res = true;
    }
  }
  return res;
}

bool TraceRecorder::instrumentFunctionCall(Instruction *I)
{
  IRBuilder<> IRB(I);
  CallBase *CI = dyn_cast<CallBase>(I);
  if ((CI->getCalledFunction() && CI->getCalledFunction()->getName().startswith("llvm.")) ||
      I->getDebugLoc().isImplicitCode())
    return false;
  unsigned int order = 0;
  if (!CI->getFunctionType()->getReturnType()->isVoidTy())
  {
    if (!VarOrders.count(I))
    {
      VarOrders[I] = VarOrderCounter;
      outsideVars[VarOrderCounter] = true;
      VarOrderCounter += 1;
    }
    order = VarOrders.at(I);
  }
  unsigned int arg_size = CI->arg_size();
  Function *F = I->getParent()->getParent();
  for (unsigned int i = 0; i < arg_size; i++)
  {
    if (!VarOrders.count(CI->getArgOperand(i)))
    {
      VarOrders[CI->getArgOperand(i)] = VarOrderCounter;
      outsideVars[VarOrderCounter] = true;
      VarOrderCounter += 1;
    }
    auto stores = getAllStoresToAddr(CI->getArgOperand(i), F);
    for (auto &store : stores)
    {
      StoresToBeInstrumented.emplace(store);
    }
    ValSourceInfo VSI = getSource(CI->getArgOperand(i), F);
    if (!VSI.isNull())
    {
      Value *ValInst;
      if (CI->getArgOperand(i)->getType()->isIntegerTy() ||
          CI->getArgOperand(i)->getType()->isPointerTy())
        ValInst = IRB.CreateBitOrPointerCast(CI->getArgOperand(i),
                                             IRB.getInt8PtrTy());
      else
        ValInst = IRB.CreateIntToPtr(IRB.getInt64(0), IRB.getInt8PtrTy());
      std::string varname = CI->getArgOperand(i)->getName().str();
      if (isa<Function>(CI->getArgOperand(i)))
      {
        Function *created = dyn_cast<Function>(CI->getArgOperand(i));
        if (created->getSubprogram())
        {
          varname = created->getSubprogram()->getName();
        }
      }
      int nameA = debuger.getOrInitDebuger()->getVarID(varname.c_str());
      int nameB = 0;
      int line = I->getDebugLoc().getLine();
      int col = I->getDebugLoc().getCol();
      uint64_t debugID =
          debuger.getOrInitDebuger()->ReformID(debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col));
      IRB.CreateCall(TrecFuncParam, {IRB.getInt16(i + 1), VSI.Reform(IRB),
                                     ValInst, IRB.getInt64(debugID)});
    }
  }
  Function *CalledF = CI->getCalledFunction();
  StringRef CalledFName = CalledF ? CalledF->getName() : "";
  std::string CurrentFileName = "";
  if (CalledF)
  {
    if (CalledF->getSubprogram())
    {
      CalledFName = CalledF->getSubprogram()->getName();
      if (CalledF->getSubprogram() && CalledF->getSubprogram()->getFile())
      {
        CurrentFileName = concatFileName(
            CalledF->getSubprogram()->getFile()->getDirectory().str(),
            CalledF->getSubprogram()->getFile()->getFilename().str());
      }
    }
  }

  int nameA = debuger.getOrInitDebuger()->getVarID(CalledFName.str().c_str());
  int nameB = debuger.getOrInitDebuger()->getFileID(CurrentFileName.c_str());
  int line = (CalledF && CalledF->getSubprogram()) ? CalledF->getSubprogram()->getLine() : 0;
  int col = 0;
  uint64_t debugID = 0;
  if (nameA != 1 || nameB != 1)
    debugID = debuger.getOrInitDebuger()->ReformID(debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col));
  IRB.CreateCall(TrecFuncEntry, {IRB.getInt16(order), IRB.getInt16(arg_size),
                                 IRB.getInt64(debugID), IRB.CreateBitOrPointerCast(CI->getCalledOperand(), IRB.getInt8PtrTy())});
  if (CalledFName == "pthread_create")
  {
    std::string createdFuncName = "", createdFileName = "";
    int createdLine = 0, createdCol = 0;
    if (isa<Function>(CI->getArgOperand(2)))
    {
      Function *created = dyn_cast<Function>(CI->getArgOperand(2));
      createdFuncName = created->getName();
      if (created->getSubprogram())
      {
        createdFuncName = created->getSubprogram()->getName();
        if (created->getSubprogram()->getFile())
        {
          createdFileName = concatFileName(
              created->getSubprogram()->getFile()->getDirectory().str(),
              created->getSubprogram()->getFile()->getFilename().str());
        }
        createdLine = created->getSubprogram()->getLine();
      }
    }
    int creatednameA = debuger.getOrInitDebuger()->getVarID(createdFuncName.c_str());
    int creatednameB = debuger.getOrInitDebuger()->getFileID(createdFileName.c_str());
    uint64_t createdDebugID = 0;
    if (creatednameA != 1 || creatednameB != 1)
      createdDebugID = debuger.getOrInitDebuger()->ReformID(debuger.getOrInitDebuger()->getDebugInfoID(
          creatednameA, creatednameB, createdLine, createdCol));

    int argnameA =
        debuger.getOrInitDebuger()->getVarID(CI->getArgOperand(3)->getName().str().c_str());
    int argnameB = 0;
    uint64_t argDebugID =
        debuger.getOrInitDebuger()->ReformID(debuger.getOrInitDebuger()->getDebugInfoID(argnameA, argnameB, line, col));
    IRB.CreateCall(
        TrecThreadCreate,
        {IRB.CreateBitOrPointerCast(CI->getArgOperand(3), IRB.getInt8PtrTy()),
         IRB.getInt64(argDebugID), IRB.getInt64(createdDebugID)});
  }
  if (I->getNextNode())
  {
    IRBuilder<> IRB2(I->getNextNode());
    auto exitInst = IRB2.CreateCall(TrecFuncExit, {IRB.getInt64(debugID)});
    exitInst->setDebugLoc(I->getDebugLoc());
  }
  else
  {
    for (auto b = succ_begin(I->getParent()), e = succ_end(I->getParent());
         b != e; b++)
    {
      if (!SeperatedExits.count(&*((*b)->getFirstInsertionPt())))
      {
        IRBuilder<> IRB2(&*((*b)->getFirstInsertionPt()));
        auto exitInst = IRB2.CreateCall(TrecFuncExit, {IRB.getInt64(debugID)});
        exitInst->setDebugLoc(I->getDebugLoc());
        SeperatedExits.insert(exitInst);
      }
      else
      {
        IRBuilder<> IRB2(&*((*b)->getFirstInsertionPt()));
        CallInst *exitInst =
            dyn_cast<CallInst>(&*((*b)->getFirstInsertionPt()));
        auto prev_debug = dyn_cast<ConstantInt>(exitInst->getArgOperand(0));
        if (*prev_debug->getValue().getRawData() != debugID)
          exitInst->setArgOperand(0, IRB2.getInt64(0));
      }
    }
  }
  return true;
}

bool TraceRecorder::instrumentLoadStore(const InstructionInfo &II,
                                        const DataLayout &DL)
{
  const bool IsWrite = isa<StoreInst>(*II.Inst);
  Value *Addr = IsWrite ? cast<StoreInst>(II.Inst)->getPointerOperand()
                        : cast<LoadInst>(II.Inst)->getPointerOperand();
  // swifterror memory addresses are mem2reg promoted by instruction
  // selection. As such they cannot have regular uses like an instrumentation
  // function and it makes no sense to track them as memory.
  if (Addr->isSwiftError())
    return false;
  Type *OrigTy = getLoadStoreType(II.Inst);
  int Idx = getMemoryAccessFuncIndex(OrigTy, Addr, DL);
  if (Idx < 0 || Idx >= 4)
    return false;
  // never instrument vtable update/read operations
  if (isVtableAccess(II.Inst) || II.Inst->getDebugLoc().isImplicitCode())
  {
    return false;
  }

  const uint64_t Alignment = IsWrite
                                 ? cast<StoreInst>(II.Inst)->getAlign().value()
                                 : cast<LoadInst>(II.Inst)->getAlign().value();
  const bool isPtrTy = isa<PointerType>(OrigTy);
  const uint32_t TypeSize = DL.getTypeStoreSizeInBits(OrigTy);
  FunctionCallee OnAccessFunc = nullptr;
  if (Alignment == 0 || Alignment >= 8 || (Alignment % (TypeSize / 8)) == 0)
  {
    OnAccessFunc = IsWrite ? TrecWrite[Idx] : TrecRead[Idx];
  }
  else
  {
    OnAccessFunc = IsWrite ? TrecUnalignedWrite[Idx] : TrecUnalignedRead[Idx];
  }

  ValSourceInfo VSI_addr = getSource(Addr, II.Inst->getParent()->getParent());

  if (IsWrite)
  {
    IRBuilder<> IRB(II.Inst);
    Value *StoredValue = cast<StoreInst>(II.Inst)->getValueOperand();
    if (StoredValue->getType()->isIntOrPtrTy())
    {
      int nameA = debuger.getOrInitDebuger()->getVarID(Addr->getName().str().c_str());
      int nameB = debuger.getOrInitDebuger()->getVarID(StoredValue->getName().str().c_str());
      int line = II.Inst->getDebugLoc().getLine();
      int col = II.Inst->getDebugLoc().getCol();
      uint64_t debugID =
          debuger.getOrInitDebuger()->ReformID(debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col));
      ValSourceInfo VSI_val =
          getSource(StoredValue, II.Inst->getParent()->getParent());
      StoredValue = IRB.CreateBitOrPointerCast(StoredValue, IRB.getInt8PtrTy());
      auto newInst = IRB.CreateCall(
          OnAccessFunc,
          {IRB.CreatePointerCast(Addr, IRB.getInt8PtrTy()),
           IRB.getInt1(isPtrTy), StoredValue, VSI_addr.Reform(IRB),
           VSI_val.Reform(IRB), IRB.getInt64(debugID)});
      newInst->setDebugLoc(II.Inst->getDebugLoc());

      NumInstrumentedWrites++;
    }
  }
  else
  {
    // read inst should not be the last inst in a BB, thus no need to check
    // for nullptr
    IRBuilder<> IRB(II.Inst->getNextNode());
    Value *LoadedValue = II.Inst;
    if (LoadedValue->getType()->isIntOrPtrTy())
    {
      int nameA = debuger.getOrInitDebuger()->getVarID(Addr->getName().str().c_str());
      int nameB = debuger.getOrInitDebuger()->getVarID(LoadedValue->getName().str().c_str());
      int line = II.Inst->getDebugLoc().getLine();
      int col = II.Inst->getDebugLoc().getCol();
      uint64_t debugID =
          debuger.getOrInitDebuger()->ReformID(debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col));
      LoadedValue = IRB.CreateBitOrPointerCast(LoadedValue, IRB.getInt8PtrTy());
      auto newInst = IRB.CreateCall(
          OnAccessFunc, {IRB.CreatePointerCast(Addr, IRB.getInt8PtrTy()),
                         IRB.getInt1(isPtrTy), LoadedValue,
                         VSI_addr.Reform(IRB), IRB.getInt64(debugID)});
      newInst->setDebugLoc(II.Inst->getDebugLoc());
      NumInstrumentedReads++;
    }
  }
  return true;
}

TraceRecorder::ValSourceInfo TraceRecorder::getSource(Value *Val, Function *F)
{
  ValSourceInfo VSI;

  Value *SrcValue = Val;
  APInt offset = APInt(14, 0);
  bool Res;
  do
  {
    Res = false;
    APInt Off(64, 0);
    Value *NewSrcValue, *LastNewSrcValue;
    for (NewSrcValue = SrcValue, LastNewSrcValue = nullptr;
         NewSrcValue != LastNewSrcValue; LastNewSrcValue = NewSrcValue)
    {
      NewSrcValue = NewSrcValue->stripPointerCastsForAliasAnalysis();
      NewSrcValue = NewSrcValue->stripPointerCastsAndAliases();
      NewSrcValue = NewSrcValue->stripAndAccumulateConstantOffsets(
          F->getParent()->getDataLayout(), Off, true);
      NewSrcValue = StripCastsAndAccumulateConstantBinaryOffsets(
          NewSrcValue, Off, F->getParent()->getDataLayout());
    }
    Res |= (SrcValue != NewSrcValue);
    SrcValue = NewSrcValue;
    offset += Off.trunc(14);
    if (isa<GlobalVariable>(SrcValue))
    {
      VSI.setAddr(SrcValue, offset, true);
      break;
    }
    else if (!isa<LoadInst>(SrcValue))
    {
      if (!VarOrders.count(SrcValue))
      {
        VarOrders[SrcValue] = VarOrderCounter;
        outsideVars[VarOrderCounter] = false;
        VarOrderCounter += 1;
      }
      VSI.setIdx(VarOrders.at(SrcValue), offset, true);
      break;
    }
    else
    {
      // LoadInst
      LoadInst *LI = dyn_cast<LoadInst>(SrcValue);
      Value *Addr = LI->getPointerOperand();
      if (isa<GlobalVariable>(Addr))
      {
        VSI.setAddr(Addr, offset, false);
        break;
      }
      else
      {
        auto stores = getAllStoresToAddr(Addr, F);
        std::vector<StoreInst *> reachableStore;
        std::copy_if(stores.begin(), stores.end(),
                     std::back_inserter(reachableStore),
                     [&](StoreInst *s)
                     { return isReachable(s, LI); });
        if (reachableStore.size() == 0)
        {
          // cannot find a reachable store

          // check if the load address comes from an outside parameter
          auto addrSource = getSource(Addr, F);
          if (!addrSource.isNull())
          {
            if (addrSource.getisDirect() && !addrSource.getisRealAddr() &&
                !outsideVars.at(addrSource.getIdx()))
            {
              if (!VarOrders.count(SrcValue))
              {
                VarOrders[SrcValue] = VarOrderCounter;
                outsideVars[VarOrderCounter] = false;
                VarOrderCounter += 1;
              }
              VSI.setIdx(VarOrders.at(SrcValue), offset, true);
            }
            else
            {
              VSI.setAddr(Addr, offset, false);
            }
          }
          else
          {
            if (!VarOrders.count(SrcValue))
            {

              VarOrders[SrcValue] = VarOrderCounter;
              outsideVars[VarOrderCounter] = false;
              VarOrderCounter += 1;
            }
            VSI.setIdx(VarOrders.at(SrcValue), offset, true);
          }
          break;
        }
        else if (reachableStore.size() == 1)
        {
          // find the only store
          // continue searching
          StoreInst *S = reachableStore.at(0);
          if (!isReachable(LI, S))
          {
            SrcValue = S->getValueOperand();
            Res |= true;
          }
          else
          {
            StoresToBeInstrumented.insert(S);
            VSI.setAddr(Addr, offset, false);
            break;
          }
        }
        else
        {
          // find multiple stores
          // instrument this address
          for (auto item : reachableStore)
            StoresToBeInstrumented.insert(item);
          VSI.setAddr(Addr, offset, false);
          break;
        }
      }
    }
  } while (Res);

  return VSI;
}

std::vector<StoreInst *> TraceRecorder::getAllStoresToAddr(Value *Addr,
                                                           Function *F)
{
  if (!AddrAllStores.count(Addr))
  {
    std::vector<StoreInst *> res;
    for (auto u : Addr->users())
    {
      if (isa<Instruction>(u) &&
          dyn_cast<Instruction>(u)->getParent()->getParent() == F)
      {
        Instruction *I = dyn_cast<Instruction>(u);
        if (isa<StoreInst>(I) &&
            dyn_cast<StoreInst>(I)->getPointerOperand() == Addr)
        {
          res.push_back(dyn_cast<StoreInst>(I));
        }
      }
    }
    AddrAllStores[Addr] = res;
  }
  return AddrAllStores.at(Addr);
}

bool TraceRecorder::isReachable(Instruction *From, Instruction *To)
{
  assert(From && To);
  assert(isa<StoreInst>(From));
  assert(isa<LoadInst>(To));
  Instruction *cur = To;
  while (cur = cur->getPrevNonDebugInstruction(), cur)
  {
    // previous instruction in the same basic block
    if (From == cur)
      return true;
  }
  BasicBlock *BBFrom = From->getParent();
  std::set<BasicBlock *> Visited;
  std::queue<BasicBlock *> ToVisit;
  ToVisit.push(To->getParent());
  Visited.insert(To->getParent());
  while (!ToVisit.empty())
  {
    BasicBlock *BBcur = ToVisit.front();
    ToVisit.pop();
    for (auto it = pred_begin(BBcur), et = pred_end(BBcur); it != et; ++it)
    {
      BasicBlock *predecessor = *it;
      if (!Visited.count(predecessor))
      {
        if (predecessor == BBFrom)
          return true;
        Visited.insert(predecessor);
        ToVisit.push(predecessor);
      }
    }
  }
  return false;
}

Value *TraceRecorder::StripCastsAndAccumulateConstantBinaryOffsets(
    Value *SrcValue, APInt &offset, const llvm::DataLayout &DL)
{
  assert(offset.getBitWidth() == 64);
  while (isa<CastInst>(SrcValue) || isa<BinaryOperator>(SrcValue) ||
         isa<ICmpInst>(SrcValue))
  {
    if (isa<CastInst>(SrcValue))
    {
      SrcValue = dyn_cast<CastInst>(SrcValue)->getOperand(0);
    }
    else if (isa<BinaryOperator>(SrcValue))
    {
      BinaryOperator *I = dyn_cast<BinaryOperator>(SrcValue);
      if (!isa<Constant>(I->getOperand(0)) &&
          !isa<Constant>(I->getOperand(1)))
      {
        break;
      }
      else if (isa<Constant>(I->getOperand(0)) &&
               isa<Constant>(I->getOperand(1)))
      {
        break;
      }
      else
      {
        if (I->getOpcode() == Instruction::BinaryOps::Add &&
            (isa<ConstantInt>(I->getOperand(0)) ||
             isa<ConstantInt>(I->getOperand(1))))
        {
          ConstantInt *cons = isa<ConstantInt>(I->getOperand(1))
                                  ? dyn_cast<ConstantInt>(I->getOperand(1))
                                  : dyn_cast<ConstantInt>(I->getOperand(0));
          offset += cons->getValue().getRawData()[0];
          SrcValue = I->getOperand(isa<ConstantInt>(I->getOperand(1)) ? 0 : 1);
        }
        else if (I->getOpcode() == Instruction::BinaryOps::Sub &&
                 isa<ConstantInt>(I->getOperand(1)))
        {
          ConstantInt *cons = dyn_cast<ConstantInt>(I->getOperand(1));
          offset -= cons->getValue().getRawData()[0];
          SrcValue = I->getOperand(0);
        }
        else if (isa<Constant>(I->getOperand(0)))
          SrcValue = I->getOperand(1);
        else if (isa<Constant>(I->getOperand(1)))
          SrcValue = I->getOperand(0);
        else
        {
          break;
        }
      }
    }
    else if (isa<ICmpInst>(SrcValue))
    {
      ICmpInst *I = dyn_cast<ICmpInst>(SrcValue);
      if (!isa<Constant>(I->getOperand(0)) &&
          !isa<Constant>(I->getOperand(1)))
      {
        break;
      }
      else if (isa<Constant>(I->getOperand(0)) &&
               isa<Constant>(I->getOperand(1)))
      {
        break;
      }
      else
      {
        if (isa<Constant>(I->getOperand(0)))
          SrcValue = I->getOperand(1);
        else if (isa<Constant>(I->getOperand(1)))
          SrcValue = I->getOperand(0);
        else
          break;
      }
    }
  }
  return SrcValue;
}

static ConstantInt *createOrdering(IRBuilder<> *IRB, AtomicOrdering ord)
{
  uint32_t v = 0;
  switch (ord)
  {
  case AtomicOrdering::NotAtomic:
    llvm_unreachable("unexpected atomic ordering!");
  case AtomicOrdering::Unordered:
    LLVM_FALLTHROUGH;
  case AtomicOrdering::Monotonic:
    v = 0;
    break;
  // Not specified yet:
  // case AtomicOrdering::Consume:                v = 1; break;
  case AtomicOrdering::Acquire:
    v = 2;
    break;
  case AtomicOrdering::Release:
    v = 3;
    break;
  case AtomicOrdering::AcquireRelease:
    v = 4;
    break;
  case AtomicOrdering::SequentiallyConsistent:
    v = 5;
    break;
  }
  return IRB->getInt32(v);
}

// If a memset intrinsic gets inlined by the code gen, we will miss races on
// it. So, we either need to ensure the intrinsic is not inlined, or
// instrument it. We do not instrument memset/memmove/memcpy intrinsics (too
// complicated), instead we simply replace them with regular function calls,
// which are then intercepted by the run-time. Since trec is running after
// everyone else, the calls should not be replaced back with intrinsics. If
// that becomes wrong at some point, we will need to call e.g. __trec_memset
// to avoid the intrinsics.
bool TraceRecorder::instrumentMemIntrinsic(Instruction *I)
{
  IRBuilder<> IRB(I);
  if (MemSetInst *M = dyn_cast<MemSetInst>(I))
  {
    CallInst *NewInst = IRB.CreateCall(
        MemsetFn,
        {IRB.CreatePointerCast(M->getArgOperand(0), IRB.getInt8PtrTy()),
         IRB.CreateIntCast(M->getArgOperand(1), IRB.getInt32Ty(), false),
         IRB.CreateIntCast(M->getArgOperand(2), IntptrTy, false)});
    NewInst->setDebugLoc(M->getDebugLoc());
    I->eraseFromParent();
  }
  else if (MemTransferInst *M = dyn_cast<MemTransferInst>(I))
  {
    CallInst *NewInst = IRB.CreateCall(
        isa<MemCpyInst>(M) ? MemcpyFn : MemmoveFn,
        {IRB.CreatePointerCast(M->getArgOperand(0), IRB.getInt8PtrTy()),
         IRB.CreatePointerCast(M->getArgOperand(1), IRB.getInt8PtrTy()),
         IRB.CreateIntCast(M->getArgOperand(2), IntptrTy, false)});
    NewInst->setDebugLoc(M->getDebugLoc());
    I->eraseFromParent();
  }
  return false;
}

// Both llvm and TraceRecorder atomic operations are based on C++11/C1x
// standards.  For background see C++11 standard.  A slightly older, publicly
// available draft of the standard (not entirely up-to-date, but close enough
// for casual browsing) is available here:
// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2011/n3242.pdf
// The following page contains more background information:
// http://www.hpl.hp.com/personal/Hans_Boehm/c++mm/

bool TraceRecorder::instrumentAtomic(Instruction *I, const DataLayout &DL)
{
  IRBuilder<> IRB(I);
  if (LoadInst *LI = dyn_cast<LoadInst>(I))
  {
    Value *Addr = LI->getPointerOperand();
    Type *OrigTy = LI->getType();
    int Idx = getMemoryAccessFuncIndex(OrigTy, Addr, DL);
    if (Idx < 0 || Idx > 4)
      return false;
    const unsigned ByteSize = 1U << Idx;
    const unsigned BitSize = ByteSize * 8;
    Type *Ty = Type::getIntNTy(IRB.getContext(), BitSize);
    Type *PtrTy = Ty->getPointerTo();
    int nameA = debuger.getOrInitDebuger()->getVarID(Addr->getName().str().c_str());
    int nameB = debuger.getOrInitDebuger()->getVarID(LI->getName().str().c_str());
    int line = LI->getDebugLoc().getLine();
    int col = LI->getDebugLoc().getCol();
    Value *Args[] = {IRB.CreatePointerCast(Addr, PtrTy),
                     createOrdering(&IRB, LI->getOrdering()),
                     IRB.getInt1(OrigTy->isPointerTy()),
                     IRB.getInt64(debuger.getOrInitDebuger()->ReformID(
                         debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col)))};

    CallInst *C = IRB.CreateCall(TrecAtomicLoad[Idx], Args);
    C->setDebugLoc(LI->getDebugLoc());
    Value *Cast = IRB.CreateBitOrPointerCast(C, OrigTy);
    I->replaceAllUsesWith(Cast);
  }
  else if (StoreInst *SI = dyn_cast<StoreInst>(I))
  {
    Value *Addr = SI->getPointerOperand();
    int Idx =
        getMemoryAccessFuncIndex(SI->getValueOperand()->getType(), Addr, DL);
    if (Idx < 0 || Idx > 4)
      return false;
    const unsigned ByteSize = 1U << Idx;
    const unsigned BitSize = ByteSize * 8;
    Type *Ty = Type::getIntNTy(IRB.getContext(), BitSize);
    Type *PtrTy = Ty->getPointerTo();
    Type *OrigTy = SI->getValueOperand()->getType();
    int nameA = debuger.getOrInitDebuger()->getVarID(Addr->getName().str().c_str());
    int nameB = debuger.getOrInitDebuger()->getVarID(SI->getName().str().c_str());
    int line = SI->getDebugLoc().getLine();
    int col = SI->getDebugLoc().getCol();
    Value *Args[] = {IRB.CreatePointerCast(Addr, PtrTy),
                     IRB.CreateBitOrPointerCast(SI->getValueOperand(), Ty),
                     createOrdering(&IRB, SI->getOrdering()),
                     IRB.getInt1(OrigTy->isPointerTy()),
                     IRB.getInt64(debuger.getOrInitDebuger()->ReformID(
                         debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col)))};
    CallInst *C = CallInst::Create(TrecAtomicStore[Idx], Args);
    C->setDebugLoc(SI->getDebugLoc());
    ReplaceInstWithInst(I, C);
  }
  else if (AtomicRMWInst *RMWI = dyn_cast<AtomicRMWInst>(I))
  {
    Value *Addr = RMWI->getPointerOperand();
    int Idx =
        getMemoryAccessFuncIndex(RMWI->getValOperand()->getType(), Addr, DL);
    if (Idx < 0)
      return false;
    FunctionCallee F = TrecAtomicRMW[RMWI->getOperation()][Idx];
    if (!F)
      return false;
    const unsigned ByteSize = 1U << Idx;
    const unsigned BitSize = ByteSize * 8;
    Type *Ty = Type::getIntNTy(IRB.getContext(), BitSize);
    Type *PtrTy = Ty->getPointerTo();
    Type *OrigTy = RMWI->getValOperand()->getType();
    int nameA = debuger.getOrInitDebuger()->getVarID(Addr->getName().str().c_str());
    int nameB = debuger.getOrInitDebuger()->getVarID(RMWI->getName().str().c_str());
    int line = RMWI->getDebugLoc().getLine();
    int col = RMWI->getDebugLoc().getCol();
    Value *Args[] = {IRB.CreatePointerCast(Addr, PtrTy),
                     IRB.CreateIntCast(RMWI->getValOperand(), Ty, false),
                     createOrdering(&IRB, RMWI->getOrdering()),
                     IRB.getInt1(OrigTy->isPointerTy()),
                     IRB.getInt64(debuger.getOrInitDebuger()->ReformID(
                         debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col)))};
    CallInst *C = CallInst::Create(F, Args);
    C->setDebugLoc(RMWI->getDebugLoc());
    ReplaceInstWithInst(I, C);
  }
  else if (AtomicCmpXchgInst *CASI = dyn_cast<AtomicCmpXchgInst>(I))
  {
    Value *Addr = CASI->getPointerOperand();
    int Idx =
        getMemoryAccessFuncIndex(CASI->getNewValOperand()->getType(), Addr, DL);
    if (Idx < 0)
      return false;
    const unsigned ByteSize = 1U << Idx;
    const unsigned BitSize = ByteSize * 8;
    Type *Ty = Type::getIntNTy(IRB.getContext(), BitSize);
    Type *PtrTy = Ty->getPointerTo();
    Type *OrigTy = CASI->getNewValOperand()->getType();
    Value *CmpOperand =
        IRB.CreateBitOrPointerCast(CASI->getCompareOperand(), Ty);
    Value *NewOperand =
        IRB.CreateBitOrPointerCast(CASI->getNewValOperand(), Ty);
    int nameA = debuger.getOrInitDebuger()->getVarID(Addr->getName().str().c_str());
    int nameB = debuger.getOrInitDebuger()->getVarID(NewOperand->getName().str().c_str());
    int line = CASI->getDebugLoc().getLine();
    int col = CASI->getDebugLoc().getCol();
    Value *Args[] = {IRB.CreatePointerCast(Addr, PtrTy),
                     CmpOperand,
                     NewOperand,
                     createOrdering(&IRB, CASI->getSuccessOrdering()),
                     createOrdering(&IRB, CASI->getFailureOrdering()),
                     IRB.getInt1(OrigTy->isPointerTy()),
                     IRB.getInt64(debuger.getOrInitDebuger()->ReformID(
                         debuger.getOrInitDebuger()->getDebugInfoID(nameA, nameB, line, col)))};
    CallInst *C = IRB.CreateCall(TrecAtomicCAS[Idx], Args);
    C->setDebugLoc(CASI->getDebugLoc());
    Value *Success = IRB.CreateICmpEQ(C, CmpOperand);
    Value *OldVal = C;
    Type *OrigOldValTy = CASI->getNewValOperand()->getType();
    if (Ty != OrigOldValTy)
    {
      // The value is a pointer, so we need to cast the return value.
      OldVal = IRB.CreateIntToPtr(C, OrigOldValTy);
    }

    Value *Res =
        IRB.CreateInsertValue(UndefValue::get(CASI->getType()), OldVal, 0);
    Res = IRB.CreateInsertValue(Res, Success, 1);

    I->replaceAllUsesWith(Res);
    I->eraseFromParent();
  }
  else if (FenceInst *FI = dyn_cast<FenceInst>(I))
  {
    Value *Args[] = {createOrdering(&IRB, FI->getOrdering())};
    FunctionCallee F = FI->getSyncScopeID() == SyncScope::SingleThread
                           ? TrecAtomicSignalFence
                           : TrecAtomicThreadFence;
    CallInst *C = CallInst::Create(F, Args);
    C->setDebugLoc(FI->getDebugLoc());
    ReplaceInstWithInst(I, C);
  }
  return true;
}

int TraceRecorder::getMemoryAccessFuncIndex(Type *OrigTy, Value *Addr,
                                            const DataLayout &DL)
{
  assert(OrigTy->isSized());
  uint32_t TypeSize = DL.getTypeStoreSizeInBits(OrigTy);
  if (TypeSize != 8 && TypeSize != 16 && TypeSize != 32 && TypeSize != 64)
  {
    NumAccessesWithBadSize++;
    // Ignore all unusual sizes.
    return -1;
  }
  size_t Idx = llvm::countr_zero(TypeSize / 8);
  assert(Idx < kNumberOfAccessSizes);
  return Idx;
}
