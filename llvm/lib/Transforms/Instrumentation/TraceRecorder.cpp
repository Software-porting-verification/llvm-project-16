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
#include "llvm/ADT/Optional.h"
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
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/EscapeEnumerator.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <fcntl.h>
#include <sqlite3.h>
#include <sys/file.h>
#include <unistd.h>

using namespace llvm;

#define DEBUG_TYPE "trec"

static cl::opt<bool>
    ClInstrumentFuncEntryExit("trec-instrument-func-entry-exit", cl::init(true),
                              cl::desc("Instrument function entry and exit"),
                              cl::Hidden);
static cl::opt<bool>
    ClTrecAddDebugInfo("trec-add-debug-info", cl::init(true),
                       cl::desc("Instrument to record debug information"),
                       cl::Hidden);
const char kTrecModuleCtorName[] = "trec.module_ctor";
const char kTrecInitName[] = "__trec_init";

namespace {
std::map<std::string, Value *> TraceRecorderModuleVarNames;
static enum Mode { Eagle, Verification, Unknown } mode;

int manager_query_callback(void *ret, int argc, char **argv, char **azColName) {
  assert(argc == 1);
  *(int *)ret = atoi(argv[0]);
  return 0;
}

/// TraceRecorder: instrument the code in module to record traces.
///
/// Instantiating TraceRecorder inserts the trec runtime library API
/// function declarations into the module if they don't exist already.
/// Instantiating ensures the __trec_init function is in the list of global
/// constructors for the module.
struct TraceRecorder {
  TraceRecorder(std::map<std::string, Value *> &VN) : VarNames(VN) {
    // Sanity check options and warn user.

    char *DatabaseDir = getenv("TREC_DATABASE_DIR");
    if (DatabaseDir == nullptr) {
      printf("ERROR: ENV variable `TREC_DATABASE_DIR` has not been set!\n");
      exit(-1);
    }
    int pid = getpid();
    char buffer[200];
    snprintf(buffer, 200, "%s/manager.db", DatabaseDir);
    int status;
    char *errmsg;
    status = sqlite3_open(buffer, &db);
    if (status) {
      printf("Open manager databased failed(%d): %s\n", status,
             sqlite3_errmsg(db));
      exit(status);
    }
    int database_fd = open(buffer, O_RDONLY);
    if ((status = flock(database_fd, LOCK_EX)) != 0) {
      printf("ERROR: acquire flock failed\n");
      exit(status);
    }
    status = sqlite3_exec(
        db,
        "CREATE TABLE MANAGER (ID INTEGER PRIMARY KEY, PID INTEGER UNIQUE);",
        nullptr, nullptr, &errmsg);
    if (status != SQLITE_OK && status != SQLITE_INTERNAL &&
        strcmp(errmsg, "table MANAGER already exists")) {
      printf("create table error(%d): %s\n", status, errmsg);
      exit(status);
    };
    sqlite3_free(errmsg);

    bool isCreated = false;
    snprintf(buffer, 200, "SELECT ID from MANAGER where PID=%d;", pid);
    status = sqlite3_exec(db, buffer, manager_query_callback, &DBID, &errmsg);
    if (status != SQLITE_OK) {
      printf("query manager table error(%d): %s\n", status, errmsg);
      exit(status);
    };
    while (DBID == -1) {
      snprintf(buffer, 200, "SELECT ID from MANAGER where PID IS NULL;");
      status = sqlite3_exec(db, buffer, manager_query_callback, &DBID, &errmsg);
      if (status != SQLITE_OK) {
        printf("query manager table error(%d): %s\n", status, errmsg);
        exit(status);
      };
      if (DBID == -1) {
        // no line
        isCreated = true;
        snprintf(buffer, 200, "INSERT INTO MANAGER VALUES (NULL, NULL);");
        while ((status = sqlite3_exec(db, buffer, nullptr, nullptr, &errmsg)) ==
               SQLITE_BUSY)
          ;
        if (status != SQLITE_OK && status != SQLITE_CONSTRAINT) {
          printf("insert manager table error(%d): %s\n", status, errmsg);
          exit(status);
        };
      }
    }
    snprintf(buffer, 200, "UPDATE MANAGER SET PID=%d where ID=%d;", pid, DBID);
    status = sqlite3_exec(db, buffer, nullptr, nullptr, &errmsg);
    if (status != SQLITE_OK) {
      printf("update manager table error(%d): %s\n", status, errmsg);
      exit(status);
    };

    if ((status = flock(database_fd, LOCK_UN)) != 0) {
      printf("ERROR: release flock failed\n");
      exit(status);
    }
    close(database_fd);
    sqlite3_close(db);
    snprintf(buffer, 200, "%s/debuginfo%d.db", DatabaseDir, DBID);
    sqlite3_open(buffer, &db);
    if (status) {
      printf("open %s file failed(%d): %s\n", buffer, status,
             sqlite3_errmsg(db));
      exit(status);
    }
    if (isCreated) {
      status = sqlite3_exec(
          db,
          "CREATE TABLE DEBUGINFO (ID INTEGER PRIMARY KEY, NAMEIDA INTEGER NOT "
          "NULL, NAMEIDB INTEGER NOT NULL, LINE SMALLINT NOT NULL, COL "
          "SMALLINT NOT NULL); CREATE TABLE DEBUGVARNAME (ID INTEGER PRIMARY "
          "KEY, NAME CHAR(512) UNIQUE); CREATE TABLE DEBUGFILENAME (ID "
          "INTEGER "
          "PRIMARY "
          "KEY, NAME CHAR(1024) UNIQUE);",
          nullptr, nullptr, &errmsg);
      if (status) {
        printf("create subtables failed %d:%s\n", status, sqlite3_errmsg(db));
        exit(status);
      }
    }
    if (getenv("TREC_COMPILE_MODE") == nullptr)
      mode = Mode::Unknown;
    else if (strcmp(getenv("TREC_COMPILE_MODE"), "eagle") == 0)
      mode = Mode::Eagle;
    else if (strcmp(getenv("TREC_COMPILE_MODE"), "verification") == 0)
      mode = Mode::Verification;
    else
      mode = Mode::Unknown;
    if (mode == Mode::Unknown) {
      printf("Error: Unknown TraceRecorder mode: ENV variable "
             "`TREC_COMPILE_MODE` has "
             "not been set!\n");
      exit(-1);
    }
  }
  ~TraceRecorder() {
    sqlite3_close(db);
    char buffer[200];
    char *DatabaseDir = getenv("TREC_DATABASE_DIR");
    if (DatabaseDir == nullptr) {
      printf("ERROR: ENV variable `TREC_DATABASE_DIR` has not been set!\n");
      exit(-1);
    }
    snprintf(buffer, 200, "%s/manager.db", DatabaseDir);
    int status;
    char *errmsg;
    status = sqlite3_open(buffer, &db);
    if (status) {
      printf("Open manager databased failed(%d): %s\n", status,
             sqlite3_errmsg(db));
      exit(status);
    }
    int database_fd = open(buffer, O_RDONLY);
    if ((status = flock(database_fd, LOCK_EX)) != 0) {
      printf("ERROR: acquire flock failed\n");
      exit(status);
    }
    snprintf(buffer, 200, "UPDATE MANAGER SET PID=NULL where ID=%d;", DBID);
    status = sqlite3_exec(db, buffer, nullptr, nullptr, &errmsg);
    if (status != SQLITE_OK) {
      printf("update manager table error(%d): %s\n", status, errmsg);
      exit(status);
    };

    if ((status = flock(database_fd, LOCK_UN)) != 0) {
      printf("ERROR: release flock failed\n");
      exit(status);
    }
    sqlite3_close(db);
  }

  bool sanitizeFunction(Function &F, const TargetLibraryInfo &TLI);
  void CopyBlocksInfo(Function &F, SmallVector<BasicBlock *> &CopyBlocks);
  std::map<std::string, Value *> &VarNames;
  int getID(const char *table_name, const char *name);

private:
  void initialize(Module &M);
  void insertFuncNames(Instruction *I, std::string &sql,
                       std::set<std::string> &Names);
  bool instrumentFunctionCall(Instruction *I);
  inline std::string concatFileName(std::string dir, std::string file) {
    return dir + "/" + file;
  }
  sqlite3 *db;
  int DBID = -1;
  std::map<std::string, uint32_t> KnownNames;

  FunctionCallee TrecFuncEntry;
  FunctionCallee TrecFuncExit;
  FunctionCallee TrecInstDebugInfo;
  FunctionCallee TrecBBLEntry;
  FunctionCallee IsTrecBBL;
};

void insertModuleCtor(Module &M) {
  getOrCreateSanitizerCtorAndInitFunctions(
      M, kTrecModuleCtorName, kTrecInitName, /*InitArgTypes=*/{},
      /*InitArgs=*/{},
      // This callback is invoked when the functions are created the first
      // time. Hook them into the global ctors list in that case:
      [&](Function *Ctor, FunctionCallee) { appendToGlobalCtors(M, Ctor, 0); });
}
} // namespace

PreservedAnalyses TraceRecorderPass::run(Function &F,
                                         FunctionAnalysisManager &FAM) {
  TraceRecorder TRec(TraceRecorderModuleVarNames);
  if (TRec.sanitizeFunction(F, FAM.getResult<TargetLibraryAnalysis>(F)))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

PreservedAnalyses ModuleTraceRecorderPass::run(Module &M,
                                               ModuleAnalysisManager &MAM) {
  insertModuleCtor(M);
  TraceRecorderModuleVarNames.clear();
  return PreservedAnalyses::none();
}

void TraceRecorder::initialize(Module &M) {
  const DataLayout &DL = M.getDataLayout();
  IRBuilder<> IRB(M.getContext());
  AttributeList Attr;
  Attr = Attr.addFnAttribute(M.getContext(), Attribute::NoUnwind);
  // Initialize the callbacks.
  TrecFuncEntry =
      M.getOrInsertFunction("__trec_func_entry", Attr, IRB.getVoidTy());

  TrecFuncExit =
      M.getOrInsertFunction("__trec_func_exit", Attr, IRB.getVoidTy());

  TrecInstDebugInfo = M.getOrInsertFunction(
      "__trec_inst_debug_info", Attr, IRB.getVoidTy(), IRB.getInt64Ty(),
      IRB.getInt32Ty(), IRB.getInt16Ty(), IRB.getInt64Ty(), IRB.getInt32Ty(),
      IRB.getInt32Ty());
  TrecBBLEntry =
      M.getOrInsertFunction("__trec_bbl_entry", Attr, IRB.getVoidTy());

  IsTrecBBL = M.getOrInsertFunction("__is_trec_bbl", Attr, IRB.getInt1Ty());
}

bool TraceRecorder::sanitizeFunction(Function &F,
                                     const TargetLibraryInfo &TLI) {
  // This is required to prevent instrumenting call to __trec_init from
  // within the module constructor.
  if (F.getName() == kTrecModuleCtorName)
    return false;
  // If we cannot find the source file, then this function must not be written
  // by user. Do not instrument it.
  if (F.getSubprogram() == nullptr || F.getSubprogram()->getFile() == nullptr)
    return false;

  // Some cases that we do not instrument

  // Naked functions can not have prologue/epilogue
  // (__trec_func_entry/__trec_func_exit) generated, so don't
  // instrument them at all.
  if (F.hasFnAttribute(Attribute::Naked))
    return false;

  initialize(*F.getParent());
  SmallVector<Instruction *> FuncCalls;
  bool Res = false;
  const DataLayout &DL = F.getParent()->getDataLayout();
  SmallVector<BasicBlock *> CopyBlocks;
  // Clone all the basic blocks and store them in a vector
  CopyBlocksInfo(F, CopyBlocks);

  for (auto &BB : F) {
    for (auto &Inst : BB) {
      if (isa<CallInst>(Inst) || isa<InvokeInst>(Inst) ||
          isa<CallBrInst>(Inst)) {
        FuncCalls.push_back(&Inst);
      }
    }
  }

  std::string sql = "";
  std::set<std::string> Names;
  for (auto &Inst : FuncCalls) {
    insertFuncNames(Inst, sql, Names);
  }

  char *errmsg;
  int status = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errmsg);
  if (status != SQLITE_OK) {
    printf("insert error(%d): %s\n", status, errmsg);
    exit(status);
  };
  sqlite3_free(errmsg);

  for (auto &Inst : FuncCalls) {
    instrumentFunctionCall(Inst);
  }

  BasicBlock *entry = &F.getEntryBlock();
  BasicBlock *newBlock =
      BasicBlock::Create((F.getParent()->getContext()), "newblock", &F, entry);
  IRBuilder<> BuildIR(F.getContext());
  BuildIR.SetInsertPoint(newBlock, newBlock->getFirstInsertionPt());
  auto *Cond = BuildIR.CreateCall(IsTrecBBL, {});
  BuildIR.CreateCondBr(Cond, CopyBlocks.front(), entry);

  int FileID = getID("DEBUGFILENAME", ""), FuncID = getID("DEBUGVARNAME", "");
  FileID = ((DBID & 0xff) << 24) | (FileID & ((1 << 24) - 1));
  FuncID = ((DBID & 0xff) << 24) | (FuncID & ((1 << 24) - 1));
  for (auto BB : CopyBlocks) {
    Instruction *I = BB->getFirstNonPHI();
    IRBuilder<> IRB(I);
    int32_t line = I->getDebugLoc().get() ? I->getDebugLoc().getLine() : 0;
    int16_t col = I->getDebugLoc().get() ? I->getDebugLoc().getCol() : 0;

    IRB.CreateCall(TrecInstDebugInfo,
                   {IRB.getInt64(0), IRB.getInt32(line), IRB.getInt16(col),
                    IRB.getInt64(0), IRB.getInt32(FileID),
                    IRB.getInt32(FuncID)});
    if (line != 0) {
      IRB.CreateCall(TrecBBLEntry);
    }
  }

  // Instrument function entry/exit points if there were instrumented
  // accesses.
  if (ClInstrumentFuncEntryExit) {
    uint64_t fid = (uint64_t)(F.getGUID());
    IRBuilder<> IRB(F.getEntryBlock().getFirstNonPHI());
    StringRef FuncName = F.getName();

    if (ClTrecAddDebugInfo && F.getSubprogram() &&
        F.getSubprogram()->getFile()) {
      std::string CurrentFileName =
          concatFileName(F.getSubprogram()->getFile()->getDirectory().str(),
                         F.getSubprogram()->getFile()->getFilename().str());
      FuncName = F.getSubprogram()->getName();
      if (FuncName == "main") {
        FuncID = getID("DEBUGVARNAME", FuncName.str().c_str());
        FileID =
            getID("DEBUGFILENAME", CurrentFileName.substr(0, 1023).c_str());
        FileID = ((DBID & 0xff) << 24) | (FileID & ((1 << 24) - 1));
        FuncID = ((DBID & 0xff) << 24) | (FuncID & ((1 << 24) - 1));

        IRB.CreateCall(TrecInstDebugInfo,
                       {IRB.getInt64(fid),
                        IRB.getInt32(F.getSubprogram()->getLine()),
                        IRB.getInt16(0), IRB.getInt64(0), IRB.getInt32(FileID),
                        IRB.getInt32(FuncID)});
      }
    }

    IRB.CreateCall(TrecFuncEntry, {});

    EscapeEnumerator EE(F);
    while (IRBuilder<> *AtExit = EE.Next()) {
      AtExit->CreateCall(TrecFuncExit, {});
    }
    Res |= true;
  }

  return Res;
}

void TraceRecorder::CopyBlocksInfo(Function &F,
                                   SmallVector<BasicBlock *> &CopyBlocks) {
  SmallVector<BasicBlock *> NewBlocks;
  ValueToValueMapTy VMap;
  std::map<BasicBlock *, BasicBlock *> BlockMap;
  for (auto &BB : F) {
    NewBlocks.push_back(&BB);
  }
  for (auto &BB : NewBlocks) {
    BasicBlock *Block = CloneBasicBlock(BB, VMap, "", &F);
    for (auto &Inst : *BB) {
      auto *NewInst = cast<Instruction>(VMap[&Inst]);
      // update operand addresses in the instruction
      for (unsigned i = 0; i < Inst.getNumOperands(); ++i) {
        Value *OldOperand = Inst.getOperand(i);
        if (auto *OldOperandInst = dyn_cast<Instruction>(OldOperand)) {
          Value *NewOperand = VMap[OldOperandInst];
          if (NewOperand) {
            NewInst->setOperand(i, NewOperand);
          }
        }
      }
    }
    CopyBlocks.push_back(Block);
    BlockMap[BB] = Block;
  }

  // Iterate over the copied basic blocks and their instructions
  for (auto &CopyBB : CopyBlocks) {
    for (auto &Inst : *CopyBB) {
      if (auto *phiInst = dyn_cast<PHINode>(&Inst)) {
        for (unsigned i = 0; i < phiInst->getNumIncomingValues(); i++) {
          BasicBlock *InBB = phiInst->getIncomingBlock(i);
          if (BlockMap.count(InBB)) {
            BasicBlock *TargetBB = BlockMap[InBB];
            Value *InValue = phiInst->getIncomingValue(i);
            phiInst->setIncomingBlock(i, TargetBB);
            phiInst->setIncomingValue(i, InValue);
          }
        }
      } else if (auto *jumpInst = dyn_cast<BranchInst>(&Inst)) {
        if (jumpInst->isConditional()) { // conditional branch
          BasicBlock *SuccBB1 = jumpInst->getSuccessor(0);
          BasicBlock *SuccBB2 = jumpInst->getSuccessor(1);
          if (BlockMap.count(SuccBB1) && BlockMap.count(SuccBB2)) {
            BasicBlock *TargetBB1 = BlockMap[SuccBB1];
            BasicBlock *TargetBB2 = BlockMap[SuccBB2];
            jumpInst->setSuccessor(0, TargetBB1);
            jumpInst->setSuccessor(1, TargetBB2);
          }
        } else if (jumpInst->isUnconditional()) { // unconditional branch
          BasicBlock *SuccBB = jumpInst->getSuccessor(0);
          if (BlockMap.count(SuccBB)) {
            BasicBlock *TargetBB = BlockMap[SuccBB];
            jumpInst->setSuccessor(0, TargetBB);
          }
        }
      } else if (auto *switchInst = dyn_cast<SwitchInst>(&Inst)) {
        for (unsigned i = 0; i < switchInst->getNumSuccessors(); i++) {
          BasicBlock *SuccBB = switchInst->getSuccessor(i);
          if (BlockMap.count(SuccBB)) {
            BasicBlock *TargetBB = BlockMap[SuccBB];
            switchInst->setSuccessor(i, TargetBB);
          }
        }
      }
    }
  }
}

void TraceRecorder::insertFuncNames(Instruction *I, std::string &sql,
                                    std::set<std::string> &Names) {
  CallBase *CI = dyn_cast<CallBase>(I);

  if (!CI->getCalledFunction()) {
    return;
  }
  if (CI->getCalledFunction()->hasFnAttribute(Attribute::Naked) ||
      CI->getCalledFunction()->getName().startswith("llvm.dbg")) {
    return;
  }

  Function *F = CI->getCalledFunction();

  if (ClTrecAddDebugInfo) {
    StringRef FuncName = "";
    if (F)
      FuncName =
          (F->getSubprogram()) ? F->getSubprogram()->getName() : F->getName();

    if (FuncName == "pthread_create") {
      Function *called = dyn_cast<Function>(CI->getArgOperand(2));
      FuncName = called ? called->getSubprogram()->getName()
                        : CI->getArgOperand(2)->getName();
    }
    char *errmsg;
    char buf[2048];
    int ID = -1;
    if (!KnownNames.count(FuncName.str().substr(0, 511))) {
      snprintf(buf, 2047, "SELECT ID from DEBUGVARNAME where NAME=\"%s\";",
               FuncName.str().substr(0, 511).c_str());
      int status = sqlite3_exec(db, buf, manager_query_callback, &ID, &errmsg);
      if (status != SQLITE_OK) {
        printf("query error(%d): %s\n", status, errmsg);
        exit(status);
      };
      sqlite3_free(errmsg);
      if (ID != -1) {
        KnownNames[FuncName.str().substr(0, 511).c_str()] = ID;
      } else if (ID == -1 && Names.count(FuncName.str().substr(0, 511)) == 0) {

        snprintf(buf, 2047, "INSERT INTO DEBUGVARNAME VALUES (NULL, \"%s\");",
                 FuncName.str().substr(0, 511).c_str());
        sql += std::string(buf);
        Names.insert(FuncName.str().substr(0, 511));
      }
    }
  }
  return;
}

bool TraceRecorder::instrumentFunctionCall(Instruction *I) {
  IRBuilder<> IRB(I);
  CallBase *CI = dyn_cast<CallBase>(I);

  if (!CI->getCalledFunction()) {
    return false;
  }
  if (CI->getCalledFunction()->hasFnAttribute(Attribute::Naked) ||
      CI->getCalledFunction()->getName().startswith("llvm.dbg")) {
    return false;
  }

  Function *F = CI->getCalledFunction();
  uint64_t fid = (uint64_t)(F->getGUID());

  if (ClTrecAddDebugInfo) {
    std::string CurrentFileName = "";
    if (CI->getDebugLoc().get())
      CurrentFileName =
          concatFileName((CI->getDebugLoc()->getScope()->getDirectory().str()),
                         (CI->getDebugLoc()->getScope()->getFilename().str()));
    StringRef FuncName = "";
    if (F)
      FuncName =
          (F->getSubprogram()) ? F->getSubprogram()->getName() : F->getName();

    if (FuncName == "pthread_create") {
      Function *called = dyn_cast<Function>(CI->getArgOperand(2));
      FuncName = called ? called->getSubprogram()->getName()
                        : CI->getArgOperand(2)->getName();
    }
    int FileID =
            getID("DEBUGFILENAME", CurrentFileName.substr(0, 1023).c_str()),
        FuncID = getID("DEBUGVARNAME", FuncName.str().substr(0, 511).c_str());
    FuncID = ((DBID & 0xff) << 24) | (FuncID & ((1 << 24) - 1));
    FileID = ((DBID & 0xff) << 24) | (FileID & ((1 << 24) - 1));

    IRB.CreateCall(
        TrecInstDebugInfo,
        {IRB.getInt64(fid),
         IRB.getInt32(I->getDebugLoc().get() ? I->getDebugLoc().getLine() : 0),
         IRB.getInt16(I->getDebugLoc().get() ? I->getDebugLoc().getCol() : 0),
         IRB.getInt64(0), IRB.getInt32(FileID), IRB.getInt32(FuncID)});
  }
  return true;
}

int TraceRecorder::getID(const char *table_name, const char *name) {
  int ID = -1;
  char buf[2048], *errmsg;
  std::string real_name;
  if (strcmp(table_name, "DEBUGFILENAME") == 0)
    real_name = std::string(name).substr(0, 1023);
  else if (strcmp(table_name, "DEBUGVARNAME") == 0)
    real_name = std::string(name).substr(0, 511);
  while (ID == -1) {
    snprintf(buf, 2047, "SELECT ID from %s where NAME=\"%s\";", table_name,
             real_name.c_str());
    int status = sqlite3_exec(db, buf, manager_query_callback, &ID, &errmsg);
    if (status != SQLITE_OK) {
      printf("query error(%d): %s\n", status, errmsg);
      exit(status);
    };
    sqlite3_free(errmsg);
    if (ID != -1) {
      KnownNames[real_name] = ID;
    } else if (ID == -1) {
      snprintf(buf, 2047, "INSERT INTO %s VALUES (NULL, \"%s\");", table_name,
               real_name.c_str());
      status = sqlite3_exec(db, buf, nullptr, nullptr, &errmsg);
      if (status != SQLITE_OK) {
        printf("insert error(%d): %s\n", status, errmsg);
        exit(status);
      };
    }
  }
  return ID;
}
