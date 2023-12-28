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

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
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
#include "llvm/Transforms/Instrumentation/TraceRecorder.h"
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
    status =
        sqlite3_exec(db, "PRAGMA synchronous=OFF;", nullptr, nullptr, nullptr);
    if (status != SQLITE_OK) {
      printf("trun off synchronous mode failed: %s\n", sqlite3_errmsg(db));
      exit(status);
    }
    if (isCreated) {
      status = sqlite3_exec(
          db,
          "CREATE TABLE DEBUGINFO (ID INTEGER PRIMARY KEY, NAMEIDA INTEGER NOT "
          "NULL, NAMEIDB INTEGER NOT NULL, LINE SMALLINT NOT NULL, COL "
          "SMALLINT NOT NULL); CREATE TABLE DEBUGVARNAME (ID INTEGER PRIMARY "
          "KEY, NAME CHAR(512)); CREATE TABLE DEBUGFILENAME (ID "
          "INTEGER "
          "PRIMARY "
          "KEY, NAME CHAR(1024));",
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
    close(database_fd);
    sqlite3_close(db);
  }

  bool sanitizeFunction(Function &F, const TargetLibraryInfo &TLI);
  void CopyBlocksInfo(Function &F, std::vector<BasicBlock *> &CopyBlocks);
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
  FunctionCallee TrecBBLExit;
  FunctionCallee IsTrecBBL;
  FunctionCallee TrecSetjmp, TrecLongjmp;
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
  IRBuilder<> IRB(M.getContext());
  AttributeList Attr;
  Attr = Attr.addFnAttribute(M.getContext(), Attribute::NoUnwind);
  // Initialize the callbacks.
  TrecFuncEntry =
      M.getOrInsertFunction("__trec_func_entry", Attr, IRB.getInt1Ty());

  TrecFuncExit =
      M.getOrInsertFunction("__trec_func_exit", Attr, IRB.getInt1Ty(), IRB.getVoidTy());

  TrecInstDebugInfo = M.getOrInsertFunction(
      "__trec_inst_debug_info", Attr, IRB.getVoidTy(), IRB.getInt64Ty(),
      IRB.getInt32Ty(), IRB.getInt16Ty(), IRB.getInt64Ty(), IRB.getInt32Ty(),
      IRB.getInt32Ty());
  TrecBBLEntry =
      M.getOrInsertFunction("__trec_bbl_entry", Attr, IRB.getVoidTy());
  TrecBBLExit = M.getOrInsertFunction("__trec_bbl_exit", Attr, IRB.getVoidTy());
  IsTrecBBL = M.getOrInsertFunction("__is_trec_bbl", Attr, IRB.getInt1Ty());
  TrecSetjmp = M.getOrInsertFunction("__trec_setjmp", Attr, IRB.getVoidTy(),
                                     IRB.getInt8PtrTy());
  TrecLongjmp = M.getOrInsertFunction("__trec_longjmp", Attr, IRB.getVoidTy(),
                                      IRB.getInt8PtrTy());
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
  std::vector<BasicBlock *> CopyBlocks;
  // Clone all the basic blocks and store them in a vector
  CopyBlocksInfo(F, CopyBlocks);

  std::string sql = "BEGIN;";
  std::set<std::string> Names;
  // for (auto &Inst : FuncCalls) {
  //   insertFuncNames(Inst, sql, Names);
  // }
  sql += "COMMIT;";
  char *errmsg;
  int status = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errmsg);
  if (status != SQLITE_OK) {
    printf("insert error(%d): %s\n", status, errmsg);
    exit(status);
  };
  sqlite3_free(errmsg);

  // for (auto &Inst : FuncCalls) {
  //   Res |= instrumentFunctionCall(Inst);
  // }

  BasicBlock *entry = &F.getEntryBlock();
  BasicBlock *newBlock =
      BasicBlock::Create((F.getParent()->getContext()), "newblock", &F, entry);
  IRBuilder<> BuildIR(F.getContext());
  BuildIR.SetInsertPoint(newBlock, newBlock->getFirstInsertionPt());
  auto *Cond = BuildIR.CreateCall(IsTrecBBL, {});
  BuildIR.CreateCondBr(Cond, CopyBlocks.front(), entry);

  std::string CurrentFileName =
      concatFileName(F.getSubprogram()->getFile()->getDirectory().str(),
                     F.getSubprogram()->getFile()->getFilename().str());
  int FileID = getID("DEBUGFILENAME", CurrentFileName.substr(0, 1023).c_str());

  int FuncID = getID("DEBUGVARNAME", "");
  FileID = ((DBID & 0xff) << 24) | (FileID & ((1 << 24) - 1));
  FuncID = ((DBID & 0xff) << 24) | (FuncID & ((1 << 24) - 1));

  for (auto BB : CopyBlocks) {
    int32_t enter_line = 0, enter_col = 0, exit_line = 0, exit_col = 0;
    llvm::Instruction *FirstI = &(*BB->getFirstInsertionPt());
    if (FirstI->getDebugLoc()) {
      enter_line = FirstI->getDebugLoc().getLine();
      enter_col = FirstI->getDebugLoc().getCol();
    }
    llvm::Instruction *TermI = &(*BB->getTerminator());
    if (TermI->getDebugLoc()) {
      exit_line = TermI->getDebugLoc().getLine();
      exit_col = TermI->getDebugLoc().getCol();
    }

    IRBuilder<> EnterIRB(FirstI);

    while (FirstI != TermI && (enter_line == 0)) {
      FirstI = FirstI->getNextNode();
      if (FirstI->getDebugLoc()) {
        enter_line = FirstI->getDebugLoc().getLine();
        enter_col = FirstI->getDebugLoc().getCol();
        break;
      }
    }

    IRBuilder<> ExitIRB(TermI);
    while (TermI != FirstI && (exit_line == 0)) {
      TermI = TermI->getPrevNode();
      if (TermI->getDebugLoc()) {
        exit_line = TermI->getDebugLoc().getLine();
        exit_col = TermI->getDebugLoc().getCol();
        break;
      }
    }

    if (FirstI == TermI || enter_line == 0 || exit_line == 0) {
      continue;
    }
    {
      EnterIRB.CreateCall(TrecInstDebugInfo,
                          {EnterIRB.getInt64(0), EnterIRB.getInt32(enter_line),
                           EnterIRB.getInt16(enter_col), EnterIRB.getInt64(0),
                           EnterIRB.getInt32(FileID),
                           EnterIRB.getInt32(FuncID)});
      EnterIRB.CreateCall(TrecBBLEntry, {});

      ExitIRB.CreateCall(TrecInstDebugInfo,
                         {ExitIRB.getInt64(0), ExitIRB.getInt32(exit_line),
                          ExitIRB.getInt16(exit_col), ExitIRB.getInt64(0),
                          ExitIRB.getInt32(FileID), ExitIRB.getInt32(FuncID)});
      ExitIRB.CreateCall(TrecBBLExit, {});
    }
  }
  Res |= true;

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
      FuncID = getID("DEBUGVARNAME", FuncName.str().c_str());
      FileID = getID("DEBUGFILENAME", CurrentFileName.substr(0, 1023).c_str());
      FileID = ((DBID & 0xff) << 24) | (FileID & ((1 << 24) - 1));
      FuncID = ((DBID & 0xff) << 24) | (FuncID & ((1 << 24) - 1));

      IRB.CreateCall(TrecInstDebugInfo,
                     {IRB.getInt64(fid),
                      IRB.getInt32(F.getSubprogram()->getLine()),
                      IRB.getInt16(0), IRB.getInt64(0), IRB.getInt32(FileID),
                      IRB.getInt32(FuncID)});

      auto result = IRB.CreateCall(TrecFuncEntry, {});
      EscapeEnumerator EE(F);
      while (IRBuilder<> *AtExit = EE.Next()) {
        AtExit->CreateCall(TrecInstDebugInfo,
                           {AtExit->getInt64(fid),
                            AtExit->getInt32(F.getSubprogram()->getLine()),
                            AtExit->getInt16(0), AtExit->getInt64(0),
                            AtExit->getInt32(FileID),
                            AtExit->getInt32(FuncID)});
        AtExit->CreateCall(TrecFuncExit, {result});
      }
      for (auto &BB : F) {
        for (auto &Inst : BB) {
          if (isa<CallBase>(&Inst) &&
              dyn_cast<CallBase>(&Inst)->getCalledFunction()) {
            if (dyn_cast<CallBase>(&Inst)->getCalledFunction()->getName().find(
                    "setjmp") != llvm::StringRef::npos) {
              IRBuilder<> IRB(&Inst);
              IRB.CreateCall(TrecInstDebugInfo,
                             {IRB.getInt64(0),
                              IRB.getInt32(F.getSubprogram()->getLine()),
                              IRB.getInt16(0), IRB.getInt64(0),
                              IRB.getInt32(FileID), IRB.getInt32(FuncID)});
              IRB.CreateCall(TrecSetjmp,
                             {IRB.CreateBitOrPointerCast(
                                 dyn_cast<CallBase>(&Inst)->getArgOperand(0),
                                 IRB.getInt8PtrTy())});
            }
            if (dyn_cast<CallBase>(&Inst)->getCalledFunction()->getName().find(
                    "longjmp") != llvm::StringRef::npos) {
              IRBuilder<> IRB(&Inst);
              IRB.CreateCall(TrecInstDebugInfo,
                             {IRB.getInt64(0),
                              IRB.getInt32(F.getSubprogram()->getLine()),
                              IRB.getInt16(0), IRB.getInt64(0), IRB.getInt32(0),
                              IRB.getInt32(0)});
              IRB.CreateCall(TrecLongjmp,
                             {IRB.CreateBitOrPointerCast(
                                 dyn_cast<CallBase>(&Inst)->getArgOperand(0),
                                 IRB.getInt8PtrTy())});
            }
          }
        }
      }
      Res |= true;
    }
  }

  return Res;
}

void TraceRecorder::CopyBlocksInfo(Function &F,
                                   std::vector<BasicBlock *> &CopyBlocks) {
  std::vector<BasicBlock *> NewBlocks;
  ValueToValueMapTy VMap;
  std::map<BasicBlock *, BasicBlock *> BlockMap;
  for (auto &BB : F) {
    NewBlocks.push_back(&BB);
  }
  for (auto &BB : NewBlocks) {
    BasicBlock *Block = CloneBasicBlock(BB, VMap, "", &F);
    CopyBlocks.push_back(Block);
    BlockMap[BB] = Block;
  }
  for (auto &BB : NewBlocks) {
    for (auto &Inst : *BB) {
      auto *NewInst = cast<Instruction>(VMap.lookup(&Inst));
      // update operand addresses in the instruction
      for (unsigned i = 0; i < Inst.getNumOperands(); ++i) {
        Value *OldOperand = Inst.getOperand(i);
        if (VMap.count(OldOperand)) {
          NewInst->setOperand(i, VMap.lookup(OldOperand));
        } else if (isa<BasicBlock>(OldOperand) &&
                   BlockMap.count(dyn_cast<BasicBlock>(OldOperand))) {
          NewInst->setOperand(i, BlockMap.at(dyn_cast<BasicBlock>(OldOperand)));
        }
      }
      if (isa<CallInst>(NewInst) &&
          dyn_cast<CallInst>(NewInst)->getCalledFunction() &&
          dyn_cast<CallInst>(NewInst)
              ->getCalledFunction()
              ->getName()
              .startswith("llvm.dbg.value") &&
          isa<MetadataAsValue>(Inst.getOperand(0)) &&
          isa<ValueAsMetadata>(
              dyn_cast<MetadataAsValue>(Inst.getOperand(0))->getMetadata())) {
        Value *origValue =
            dyn_cast<ValueAsMetadata>(
                dyn_cast<MetadataAsValue>(Inst.getOperand(0))->getMetadata())
                ->getValue();
        if (VMap.count(origValue)) {
          Value *NewOperand = llvm::MetadataAsValue::get(
              F.getContext(),
              llvm::ValueAsMetadata::get(VMap.lookup(origValue)));
          VMap[Inst.getOperand(0)] = NewOperand;
          NewInst->setOperand(0, NewOperand);
        }
      }
    }
  }

  // Iterate over the copied basic blocks and their instructions
  for (auto &CopyBB : CopyBlocks) {
    for (auto &Inst : *CopyBB) {
      if (auto *phiInst = dyn_cast<PHINode>(&Inst)) {
        for (unsigned i = 0; i < phiInst->getNumIncomingValues(); i++) {
          BasicBlock *InBB = phiInst->getIncomingBlock(i);
          if (BlockMap.count(InBB)) {
            BasicBlock *TargetBB = BlockMap.at(InBB);
            phiInst->setIncomingBlock(i, TargetBB);
          }
          Value *InValue = phiInst->getIncomingValue(i);
          if (VMap.count(InValue)) {
            phiInst->setIncomingValue(i, VMap.lookup(InValue));
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
