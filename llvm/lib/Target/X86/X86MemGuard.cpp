// Created by David Armanious

#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSchedule.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/MachinePostDominators.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/MC/MCSchedule.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cassert>
#include <iterator>
#include <utility>
#include <llvm/Transforms/Utils/ModuleUtils.h>
#include <llvm/CodeGen/MachineModuleInfo.h>
#include <llvm/ADT/SmallSet.h>
#include <queue>
#include <map>
#include "llvm/CodeGen/MachineDominators.h"
#include "llvm/ADT/DenseSet.h"
#include <csignal>

using namespace llvm;

#define DEBUG_TYPE "x86-memguard"

namespace llvm {
    
    void initializeIRMemGuardPass(PassRegistry &);
    
    void initializeX86MemGuardPass(PassRegistry &);
    
}

enum ViolationReporting {
    FunctionCall,
    RaiseSignal,
    MPX
};

enum BndRegister {
    BND0 = X86::BND0,
    BND1 = X86::BND1,
    BND2 = X86::BND2,
    BND3 = X86::BND3
};

enum InstrumentationMode {
    SECRECY = 1,
    INTEGRITY = 2,
    BOTH = SECRECY | INTEGRITY
};

static cl::opt<bool>EnableMemGuard("x86-memguard", cl::init(false), cl::NotHidden, cl::desc("Enable MemGuard SFI."));

static cl::opt<unsigned long long>
        MmapMinAddr("x86-memguard-mmap-min-addr", cl::init(0x10000), cl::NotHidden,
                    cl::desc("Value of vm.mmap_min_addr (sysctl) in target; beginning address of safe region (defaults to 0x10000)."));

static cl::opt<unsigned long long>
        SafeRegionSize("x86-memguard-safe-region-size", cl::init(1UL << 26), cl::NotHidden,
                       cl::desc("Size of safe region (defaults to 64 MB = 0x4000000)."));

static cl::opt<std::string>
        InitializationFunction("x86-memguard-initialization-function", cl::init(""), cl::NotHidden,
                               cl::desc("Function to insert initialization code to call mmap() and/or move upper bound into the correct bnd register. Required if MPX enabled."));

static cl::opt<bool>
        InitializeSafeRegion("x86-memguard-initialize-safe-region", cl::init(false), cl::NotHidden,
                             cl::desc("Make a call to mmap() to reserve the safe region in a static constructor."));

static cl::opt<ViolationReporting> ReportingMethod("x86-memguard-violation-reporting", cl::init(FunctionCall), cl::NotHidden,
        cl::values(clEnumValN(FunctionCall, "function-call", "Call function specified by -x86-memgurd-violation-handler"),
                   clEnumValN(RaiseSignal, "raise-signal", "Raise signal specified by -x86-memgurd-violation-signal"),
                   clEnumValN(MPX, "mpx", "Use MPX to implement bounds checks and raise #br exception on violation")));

static cl::opt<std::string>
        ViolationHandler("x86-memguard-violation-handler", cl::init("exit"), cl::NotHidden,
                         cl::desc("Function called when a memory violation occurs; first argument is the address (void*) that triggered the violation. Exits the application by default."));

static cl::opt<int>
        ViolationSignal("x86-memguard-violation-signal", cl::init(SIGUSR2), cl::NotHidden,
                        cl::desc("Signal to raise upon memory violation; default is SIGUSR2"));

static cl::opt<BndRegister> BoundRegister("x86-memguard-mpx-register", cl::init(BND0), cl::NotHidden,
        cl::values(clEnumValN(BND0, "bnd0", "%bnd0 register"),
                   clEnumValN(BND1, "bnd1", "%bnd1 register"),
                   clEnumValN(BND2, "bnd2", "%bnd2 register"),
                   clEnumValN(BND2, "bnd3", "%bnd3 register")));

static cl::opt<InstrumentationMode> InstrumentationMode("x86-memguard-mode", cl::init(BOTH), cl::NotHidden,
        cl::values(clEnumValN(BOTH, "both", "Instrument memory reads and writes."),
                   clEnumValN(SECRECY, "secrecy", "Instrument memory reads."),
                   clEnumValN(INTEGRITY, "integrity", "Instrument memory writes.")));


#define MAP_START (MmapMinAddr)
#define SAFE_REGION_SIZE (SafeRegionSize)
#define UPPER_BOUND (MAP_START + SAFE_REGION_SIZE)

namespace {
    class IRMemGuard : public ModulePass {
    public:
        IRMemGuard() : ModulePass(ID) {
            initializeIRMemGuardPass(*PassRegistry::getPassRegistry());
        };
        
        StringRef getPassName() const override { return "IRMemGuard"; }
        
        bool runOnModule(Module &M) override;
        
        /// Pass identification, replacement for typeid.
        static char ID;
    private:
        void CreateDependentFunctions(Module &M);
        
        void InsertIntoInitializationFunction(Module &M, Function *F);
        
        void CreatePrintfCall(Module &M, IRBuilder<> IRB, StringRef format, ArrayRef<Value *> args);
    };
    
    class X86MemoryReference {
    public:
        unsigned int BaseRegister;
        int64_t Scale;
        unsigned int IndexRegister;
        int64_t Displacement;
        unsigned int SegmentRegister;
        
        X86MemoryReference(unsigned int baseRegister, int64_t scale, unsigned int indexRegister,
                           int64_t displacement, unsigned int segmentRegister) {
            BaseRegister = baseRegister;
            Scale = scale;
            IndexRegister = indexRegister;
            Displacement = displacement;
            SegmentRegister = segmentRegister;
        }
        
        X86MemoryReference() : X86MemoryReference(0, 0, 0, 0, 0) {}
        
        explicit X86MemoryReference(MachineInstr *MI) {
            if(MI != nullptr) {
                const MCInstrDesc &Desc = MI->getDesc();
                auto AddrOffset = (unsigned) X86II::getMemoryOperandNo(Desc.TSFlags);
                if ((signed) AddrOffset >= 0) {
                    AddrOffset += X86II::getOperandBias(Desc);
                    
                    BaseRegister = MI->getOperand(AddrOffset + X86::AddrBaseReg).getReg();
                    Scale = MI->getOperand(AddrOffset + X86::AddrScaleAmt).getImm();
                    IndexRegister = MI->getOperand(AddrOffset + X86::AddrIndexReg).getReg();
                    Displacement = MI->getOperand(AddrOffset + X86::AddrDisp).isImm() ? MI->getOperand(
                            AddrOffset + X86::AddrDisp).getImm() : 0;
                    SegmentRegister = MI->getOperand(AddrOffset + X86::AddrSegmentReg).getReg();
                    return;
                }
            }
            BaseRegister = IndexRegister = SegmentRegister = 0;
            Scale = Displacement = 0;
        }
        
    };
    
    struct InstrumentationGroup {
        MachineInstr *instrumentationLocation;
        X86MemoryReference memoryReference;
        SmallPtrSet<MachineInstr*, 16> coveredInstructions;
        
        explicit InstrumentationGroup(MachineInstr *instruction){
            instrumentationLocation = instruction;
            memoryReference = X86MemoryReference(instruction);
            coveredInstructions.insert(instrumentationLocation);
        }
    };
    
    struct Instrumentation {
        MachineInstr *instruction;
        X86MemoryReference memoryReference;
        
        explicit Instrumentation(MachineInstr *Instruction){
            instruction = Instruction;
            memoryReference = X86MemoryReference(Instruction);
        }
        Instrumentation(MachineInstr *Instruction, X86MemoryReference ref){
            instruction = Instruction;
            memoryReference = ref;
        }
    };
    
    
    class X86MemGuard : public MachineFunctionPass {
    public:
        X86MemGuard() : MachineFunctionPass(ID) {
            initializeX86MemGuardPass(*PassRegistry::getPassRegistry());
            STI = nullptr;
            TII = nullptr;
            TFL = nullptr;
            TRI = nullptr;
            AA = nullptr;
            MDT = nullptr;
        }
        
        StringRef getPassName() const override { return "X86MemGuard"; }
        
        bool runOnMachineFunction(MachineFunction &MF) override;
        
        void getAnalysisUsage(AnalysisUsage &AU) const override {
            AU.addRequired<AAResultsWrapperPass>();
            AU.addRequired<MachineDominatorTree>();
            AU.addRequired<MachinePostDominatorTree>();
            MachineFunctionPass::getAnalysisUsage(AU);
        }
        
        static char ID;
    private:
        const X86Subtarget *STI;
        const X86InstrInfo *TII;
        const X86FrameLowering *TFL;
        const X86RegisterInfo *TRI;
        AliasAnalysis *AA;
        MachineDominatorTree *MDT;
        MachinePostDominatorTree *PDT;
        
        void InsertMPXInitialization(MachineFunction &MF);
        
        void FixColdCallingConvention(MachineFunction &MF);
        
        bool SkipFunction(MachineFunction &MF);
        
        bool FindInstrumentationPoints(MachineFunction &MF, std::map<MachineInstr*, Instrumentation*> &instrumentations);
        
        bool IsOperandInteresting(unsigned int registerNumber);
        
        bool IsMemoryReferenceInteresting(X86MemoryReference &MO);
        
        MachineInstr *RewriteCmov(MachineInstr *MI);
        
        void InstrumentInstruction(MachineFunction &MF, MachineInstr* MI, Instrumentation *I);
        
        // void OptimizeLEAs(MachineFunction &MF);
    };
    
}

char IRMemGuard::ID = 0;
char X86MemGuard::ID = 0;

bool IRMemGuard::runOnModule(Module &M) {
    if (!EnableMemGuard) return false;
    
    CreateDependentFunctions(M);
    
    for (Function &F : M) {
        if (F.getName().startswith("__safe_")) {
            F.addAttribute(AttributeList::FunctionIndex, Attribute::OptimizeNone);
            F.addAttribute(AttributeList::FunctionIndex, Attribute::NoInline);
        }else if(F.getName().equals(ViolationHandler) && ViolationHandler != "exit"){
            F.addAttribute(AttributeList::FunctionIndex, Attribute::OptimizeNone);
            F.addAttribute(AttributeList::FunctionIndex, Attribute::NoInline);
            F.setCallingConv(CallingConv::Cold);
        }else if(F.getName().equals(InitializationFunction)){
            InsertIntoInitializationFunction(M, &F);
        }
    }
    
    return true;
}

void IRMemGuard::CreateDependentFunctions(Module &M) {
    LLVMContext &C = M.getContext();
    Function *F;
    
    auto vt = Type::getVoidTy(C);
    auto i8ptr = IntegerType::getInt8PtrTy(C);
    auto i64 = IntegerType::getInt64Ty(C);
    auto i32 = IntegerType::getInt32Ty(C);
    
    
    
    if(InitializeSafeRegion) {
        F = M.getFunction("mmap");
        if (F == nullptr) {
            F = (Function *) M.getOrInsertFunction("mmap",
                                                   FunctionType::get(i8ptr, {i8ptr, i64, i32, i32, i32, i64}, false));
            F->setCallingConv(CallingConv::C);
            F->setLinkage(Function::ExternalLinkage);
        }
    
        F = M.getFunction("printf");
        if (F == nullptr) {
            F = (Function *) M.getOrInsertFunction("printf", FunctionType::get(i32, {i8ptr}, true));
            F->setCallingConv(CallingConv::C);
            F->setLinkage(Function::ExternalLinkage);
        }
    }
    
    
    if(InitializeSafeRegion || (ReportingMethod == FunctionCall && ViolationHandler == "exit")) {
        F = M.getFunction("exit");
        if (F == nullptr) {
            F = (Function *) M.getOrInsertFunction("exit", FunctionType::get(vt, {i32}, false));
            F->setCallingConv(CallingConv::C);
            F->setLinkage(Function::ExternalLinkage);
        }
    }
    
    if(ReportingMethod == RaiseSignal) {
        F = M.getFunction("raise");
        if (F == nullptr) {
            F = (Function *) M.getOrInsertFunction("raise", FunctionType::get(i32, {i32}, false));
            F->setCallingConv(CallingConv::C);
            F->setLinkage(Function::ExternalLinkage);
        }
    }
    
}

void IRMemGuard::CreatePrintfCall(Module &M, IRBuilder<> IRB, StringRef format, ArrayRef<Value *> args) {
    static int format_no = 0;
    LLVMContext &C = M.getContext();
    auto SD = ConstantDataArray::getString(C, format);
    
    GlobalVariable *GV = (GlobalVariable *) M.getOrInsertGlobal(
            "memguard_printf_format_" + std::to_string(format_no++),
            SD->getType());
    GV->setLinkage(GlobalVariable::PrivateLinkage);
    GV->setInitializer(SD);
    GV->setConstant(true);
    
    auto GVPtr = IRB.CreatePointerCast(GV, Type::getInt8PtrTy(C));
    
    SmallVector<Value *, 4> printfArgs;
    printfArgs.push_back(GVPtr);
    for (auto arg : args) printfArgs.push_back(arg);
    IRB.CreateCall(M.getFunction("printf"), printfArgs);
}

void IRMemGuard::InsertIntoInitializationFunction(Module &M, Function *F) {
    LLVMContext &C = M.getContext();
    if(!InitializeSafeRegion) return;
    
    // declare i8* @mmap(i8*, i64, i32, i32, i32, i64)
    auto i8ptr = IntegerType::getInt8PtrTy(C);
    auto i64 = IntegerType::getInt64Ty(C);
    auto i32 = IntegerType::getInt32Ty(C);
    
    // map start got by executing and parsing "sysctl -b vm.mmap_min_addr"
    // i8* f = popen("sysctl -b vm.mmap_min_addr");
    // char* buf[21];
    // fgets(buf, 20, f);
    // i64 map_start = atol(buf);
    // pclose(f);
    Value *addr = Constant::getIntegerValue(i8ptr, APInt(64, MAP_START));
    
    
    auto NB = &F->front();
    auto BB = BasicBlock::Create(C, "", F, NB);
    auto EB = BasicBlock::Create(C, "", F, NB);
    
    IRBuilder<> IRB(C);
    IRB.SetInsertPoint(BB);
    
    CallInst *mmapCall = IRB.CreateCall(M.getFunction("mmap"), {
            addr, // addr = MAP_START, i8*
            ConstantInt::get(i64, SAFE_REGION_SIZE), // length = SAFE_REGION_SIZE, i64
            ConstantInt::get(i32, 3), // prot = PROT_READ | PROT_WRITE = 3, i32
            ConstantInt::get(i32, 49), // flags = MAP_ANON | MAP_PRIVATE | MAP_FIXED = 49 on LINUX, i32
            Constant::getAllOnesValue( i32), // fd = -1, i32
            ConstantInt::get(i64, 0) // offset = 0, i64
    });
    Value *cond = IRB.CreateICmpEQ(mmapCall, addr);
    
    IRB.CreateCondBr(cond, NB, EB);
    
    IRB.SetInsertPoint(EB);
    CreatePrintfCall(M, IRB,
                     InitializationFunction + ": call to mmap() returned unexpected value = %p (expected %p)!\n"
                                              "Terminating process.\n", SmallVector<Value *, 6>({mmapCall, addr}));
    
    IRB.CreateCall(M.getFunction("exit"), {ConstantInt::getAllOnesValue(i32)});
    IRB.CreateBr(NB);
    
    // DEBUG(dbgs() << "[+] Created static constructor\n");
    
    // appendToGlobalCtors(M, F, 0, nullptr);
}


static bool checkLiveness(MachineInstr *MI, unsigned int reg) {
    MachineBasicBlock *BB = MI->getParent();
    for (MachineBasicBlock::iterator I = MI, E = BB->end(); I != E; ++I)
        if (I->readsRegister(reg))
            return true;
        else if (I->definesRegister(reg))
            return false;
    for (auto succ : BB->successors())
        if (succ->isLiveIn((MCPhysReg) reg))
            return true;
    return false;
}


void X86MemGuard::InsertMPXInitialization(MachineFunction &MF) {
    auto &EB = MF.front();
    // mov UPPER_BOUND, r15
    // push r11
    // mov 0xffffff...ffff - UPPER_BOUND, r11
    // bndmk bnd0, 0(%r15,%r11,1)
    // pop r11
    auto MI = EB.begin();
    bool spillingr11 = checkLiveness(&*MI, X86::R11); //use volatile register
    if (spillingr11) BuildMI(EB, MI, MI->getDebugLoc(), TII->get(X86::PUSH64r)).addReg(X86::R11);
    BuildMI(EB, MI, MI->getDebugLoc(), TII->get(X86::MOV64ri)).addReg(X86::R15).addImm((signed) UPPER_BOUND);
    BuildMI(EB, MI, MI->getDebugLoc(), TII->get(X86::MOV64ri)).addReg(X86::R11).addImm((signed) (~0UL - UPPER_BOUND));
    BuildMI(EB, MI, MI->getDebugLoc(), TII->get(X86::BNDMK64rm))
            .addReg(BoundRegister)
            .addReg(X86::R15)
            .addImm(1)
            .addReg(X86::R11)
            .addImm(0)
            .addReg(0);
    if (spillingr11) BuildMI(EB, MI, MI->getDebugLoc(), TII->get(X86::POP64r)).addReg(X86::R11);
}

bool X86MemGuard::runOnMachineFunction(MachineFunction &MF) {
    if (!EnableMemGuard) return false;
    
    STI = &MF.getSubtarget<X86Subtarget>();
    TII = STI->getInstrInfo();
    TRI = STI->getRegisterInfo();
    TFL = STI->getFrameLowering();
    AA = &getAnalysis<AAResultsWrapperPass>().getAAResults();
    MDT = &getAnalysis<MachineDominatorTree>();
    PDT = &getAnalysis<MachinePostDominatorTree>();
    
    if (ReportingMethod == MPX && MF.getName().equals(InitializationFunction)) {
        InsertMPXInitialization(MF);
        return true;
    } else if (ReportingMethod == FunctionCall && MF.getName().equals(ViolationHandler)){
        if(MF.getFunction().doesNotReturn()) return false;
        FixColdCallingConvention(MF);
        return true;
    }  else if (SkipFunction(MF))
        return false;
    
    std::map<MachineInstr*, Instrumentation*> instrumentations;
    if(FindInstrumentationPoints(MF, instrumentations)){
        DEBUG(dbgs() << "[+] MemGuard instrumenting " << MF.getName() << "...\n");
        for (auto pair : instrumentations) {
            assert(pair.second);
            InstrumentInstruction(MF, pair.first, pair.second);
        }
        DEBUG(dbgs() << "[+] \tInstrumented " << MF.getName() << " in " << instrumentations.size()
                     << " places; attempting to optimize...\n");
        // OptimizeLEAs(MF);
        return true;
    }
    return false;
}

bool X86MemGuard::SkipFunction(MachineFunction &MF) {
    return MF.getName().startswith("__safe_");
}

bool X86MemGuard::IsOperandInteresting(unsigned int registerNumber) {
    // also excludes when Mo == X86::NoRegister = 0
    return registerNumber && registerNumber != X86::RSP && registerNumber != X86::RIP;
}

bool X86MemGuard::IsMemoryReferenceInteresting(X86MemoryReference &MO) {
    return (IsOperandInteresting(MO.BaseRegister) || IsOperandInteresting(MO.IndexRegister)) &&
           MO.SegmentRegister == 0;
}

static bool isMatch(X86MemoryReference &x, X86MemoryReference &y){
    return  x.SegmentRegister == y.SegmentRegister &&
            // (B,I,s) == (B,I,s)
            ((
                     x.Scale == y.Scale &&
                     x.BaseRegister == y.BaseRegister &&
                     x.IndexRegister == y.IndexRegister
             ) ||
             // (I,I,1) == (0,I,2)
             (
                     x.Scale == 1 && y.Scale == 2 &&
                     x.BaseRegister == x.IndexRegister &&
                     x.IndexRegister == y.IndexRegister
             ) ||
             // (0,I,2) == (I,I,1)
             (
                     y.Scale == 1 && x.Scale == 2 &&
                     y.BaseRegister == y.IndexRegister &&
                     y.IndexRegister == x.IndexRegister
             ) ||
             // (B,I,1) == (I,B,1)
             // (I,B,1) == (B,I,1)
             (
                     x.Scale == 1 && y.Scale == 1 &&
                     x.BaseRegister == y.IndexRegister &&
                     x.IndexRegister == y.BaseRegister
             ));
}

static MachineInstr*
getExactMatchIndex(std::map<MachineInstr *, X86MemoryReference> &active, X86MemoryReference &ref) {
    for (auto pair : active){
        if (isMatch(pair.second, ref) && pair.second.Displacement == ref.Displacement){
            return pair.first;
        }
    }
    return nullptr;
}

InstrumentationGroup *findMatch(X86MemoryReference ref, std::set<InstrumentationGroup*> *groups){
    for(auto group : *groups)
        if(isMatch(ref, group->memoryReference))
            return group;
    return nullptr;
}

InstrumentationGroup *attemptCoalesce(MachineInstr *instruction, std::set<InstrumentationGroup*> *groups){
    X86MemoryReference ref(instruction);
    InstrumentationGroup *group = findMatch(ref, groups);
    if(group == nullptr) return nullptr;
    if(X86::getCondFromCMovOpc(instruction->getOpcode()) == X86::COND_INVALID ||
       ref.Displacement >= group->memoryReference.Displacement)
        return group;
    return nullptr;
}

// THE ORIGINAL
/*bool X86MemGuard::FindInstrumentationPoints(MachineFunction &MF, std::map<MachineInstr*, InstrumentationGroup*> &instrumentations){
    DEBUG(dbgs() << "[+] \n[+] INSTRUMENTATION INFORMATION FOR " << MF.getName() << "\n");
    std::set<InstrumentationGroup*> trustedRefs;
    for(MachineBasicBlock &MBB : MF){
        trustedRefs.clear();
        
        for(MachineInstr &MI : MBB){
            DEBUG(dbgs() << "[+] \t" << MI);
            
            if( ((InstrumentationMode & SECRECY) && MI.mayLoad() && !MI.isDereferenceableInvariantLoad(AA))
                || ((InstrumentationMode & INTEGRITY) && MI.mayStore())  ){
                X86MemoryReference ref(&MI);
                
                if(IsMemoryReferenceInteresting(ref)) {
                    auto group = attemptCoalesce(&MI, &trustedRefs);
                    if (group != nullptr) {
                        DEBUG(dbgs() << "[+] \t\tCoalescing\n");
                        if (instrumentations.find(&MI) != instrumentations.end()) {
                            auto prevGroup = instrumentations[&MI];
                            for (auto otherInstruction : prevGroup->coveredInstructions)
                                group->coveredInstructions.insert(otherInstruction);
                            instrumentations.erase(&MI);
                            delete prevGroup;
                        }else{
                            group->coveredInstructions.insert(&MI);
                        }
                    } else {
                        DEBUG(dbgs() << "[+] \t\tInstrumenting\n");
                        if (instrumentations.find(&MI) == instrumentations.end()) {
                            instrumentations.insert({&MI, new InstrumentationGroup(&MI)});
                            DEBUG(dbgs() << "[+] \t\t\tcreated new instrumentation group; new size = " << instrumentations.size() << ")\n");
                        }
                        if(X86::getCondFromCMovOpc(MI.getOpcode()) == X86::COND_INVALID) {
                            trustedRefs.insert(instrumentations[&MI]);
                            DEBUG(dbgs() << "[+] \t\t\tadded to trustedRefs\n");
                        }
                    }
                }
            }
            
            for(auto cur = trustedRefs.begin(), end = trustedRefs.end(); cur != end;) {
                auto ref = (*cur)->memoryReference;
                if (MI.modifiesRegister(ref.BaseRegister, TRI)
                    || MI.modifiesRegister(ref.IndexRegister, TRI)
                    || MI.modifiesRegister(ref.SegmentRegister, TRI)) {
                    trustedRefs.erase(cur++);
                } else {
                    ++cur;
                }
            }
            
            
        }
        
    }
    // instrumentations contains newly allocated memory, but we need to keep it
    
    return !instrumentations.empty();
}*/

bool coalesceTrusted(MachineInstr &MI, X86MemoryReference &ref, std::set<Instrumentation*> *insts, bool performCoalesce) {
    for (auto inst : *insts) {
        if (isMatch(ref, inst->memoryReference)) {
            if (X86::getCondFromCMovOpc(MI.getOpcode()) != X86::COND_INVALID &&
                ref.Displacement < inst->memoryReference.Displacement)
                continue;
            if (performCoalesce && ref.Displacement < inst->memoryReference.Displacement)
                inst->memoryReference.Displacement = ref.Displacement;
            return true;
        }
    }
    return false;
}

bool coalesceUntrusted(MachineInstr &MI, X86MemoryReference &ref, std::set<Instrumentation*> *insts,
                       bool performCoalesce, const X86RegisterInfo *TRI){
    // for any code path between an instrumentation instruction and MI, if either BaseRegister or IndexRegister
    // gets modified (i.e. the live segment starting at inst ends before MI), coalescing is impossible
   
    // BaseRegister
    // we know that BaseRegister does not get modified until the end of its associated basic block
    
    // we need to check intermediate basic blocks from MI->getBasicBlock()->successors() to the current block
    // to see if they modify BaseRegister
    auto startBlock = (*insts->begin())->instruction->getParent();
    
    std::set<MachineBasicBlock*> checked;
    checked.insert(MI.getParent());
    
    std::queue<MachineBasicBlock*> queue;
    queue.push(startBlock);
    
    while(!queue.empty()){
        DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
        auto curBlock = queue.front();
        queue.pop();
        if(checked.find(curBlock) != checked.end()) continue;
        checked.insert(curBlock);
        for(MachineInstr &instr : *curBlock)
            if(instr.modifiesRegister(ref.BaseRegister, TRI) || instr.modifiesRegister(ref.IndexRegister, TRI))
                return false;
        for(auto pred : curBlock->predecessors())
            queue.push(&*pred);
    }
    
    return coalesceTrusted(MI, ref, insts, performCoalesce);
}

bool X86MemGuard::FindInstrumentationPoints(MachineFunction &MF, std::map<MachineInstr*, Instrumentation*> &instrumentations) {
    /*
     * 1. a memory reference that only differs in displacement is guaranteed to be instrumented prior to the instruction
     *      in question,
     *
     * 2. no code sequence between the two instructions modifies the value stored in either the base or the index
     *      register of the memory reference, and
     *
     * 3. every control flow from the first instruction will eventually execute the second instruction.
     */
    
    // first pass; coalescing only within basic block
    DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
    std::map<MachineBasicBlock*, std::set<Instrumentation*>*> validInstrumentationsMap;
    
    DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
    for (MachineBasicBlock &MBB : MF) {
        if(validInstrumentationsMap.find(&MBB) == validInstrumentationsMap.end())
            validInstrumentationsMap.insert({&MBB, new std::set<Instrumentation*>()});
        DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
        auto validInstrumentations = validInstrumentationsMap[&MBB];
        DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
        
        for (MachineInstr &MI : MBB) {
            if (((InstrumentationMode & SECRECY) && MI.mayLoad() && !MI.isDereferenceableInvariantLoad(AA))
                || ((InstrumentationMode & INTEGRITY) && MI.mayStore())) {
                X86MemoryReference ref(&MI);
                if (IsMemoryReferenceInteresting(ref)) {
                    DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
                    if(!coalesceTrusted(MI, ref, validInstrumentations, true)) {
                        DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
                        auto I = new Instrumentation(&MI);
                        instrumentations.insert({&MI, I});
                        if (X86::getCondFromCMovOpc(MI.getOpcode()) == X86::COND_INVALID)
                            validInstrumentations->insert(I);
                    }
                }
            }
            if (MI.isCall() || MI.isIndirectBranch()) {
                DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
                validInstrumentations->clear();
            }else {
                DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
                for (auto cur = validInstrumentations->begin(), end = validInstrumentations->end(); cur != end;) {
                    auto ref = (*cur)->memoryReference;
                    if (MI.modifiesRegister(ref.BaseRegister, TRI)
                        || MI.modifiesRegister(ref.IndexRegister, TRI)) {
                        DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
                        validInstrumentations->erase(cur++);
                    } else {
                        ++cur;
                    }
                }
            }
        }
    }
    
    
    // second+ passes: coalesce between basic blocks
    DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
    std::set<MachineInstr*> coalesceBlacklist;
    bool changed;
    do {
        changed = false;
        auto cur = instrumentations.begin();
        while(cur != instrumentations.end()) {
            DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
            auto MI = cur->first;
            if(coalesceBlacklist.find(MI) == coalesceBlacklist.end()){
                ++cur;
                continue;
            }
            auto MBB = MI->getParent();
            DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
            auto ref = cur->second->memoryReference;
            bool canCoalesce = true;
            DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
            for(auto curInst = --MachineBasicBlock::reverse_iterator(MI), e = MBB->rend(); curInst != e; ++curInst){
                if(curInst->modifiesRegister(ref.BaseRegister, TRI) ||
                        curInst->modifiesRegister(ref.IndexRegister, TRI)){
                    DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
                    canCoalesce = false;
                    coalesceBlacklist.insert(MI);
                    break;
                }
            }
            DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
            if(canCoalesce) {
                for (auto pred : MBB->predecessors()) {
                    DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
                    if (!PDT->dominates(MBB, &*pred) || // must post-dominate every predecessor
                        !coalesceTrusted(*MI, ref, validInstrumentationsMap[&*pred], false)) {
                        // every predecessor must be able to coalesce the instrumentation
                        DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
                        canCoalesce = false;
                        break;
                    }
                }
            }
            DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
            if (canCoalesce) {
                DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
                for (auto pred : MBB->predecessors())
                    assert(coalesceTrusted(*MI, ref, validInstrumentationsMap[&*pred], true));
                DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
                changed = true;
                delete cur->second;
                DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
                instrumentations.erase(cur++);
                DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
            }else{
                ++cur;
            }
        }
    } while(changed);
    
    DEBUG(dbgs() << "[+] " << __LINE__ << "\n");
    
    return !instrumentations.empty();
}


long getMinimumDisplacement(InstrumentationGroup *IG){
    long min = LONG_MAX;
    for(MachineInstr *MI : IG->coveredInstructions){
        X86MemoryReference ref(MI);
        if(ref.Displacement < min)
            min = ref.Displacement;
    }
    return min;
}

// Adapted from X86CmovConversion.cpp, X86CmovConverterPass::convertCmovInstsToBranches
MachineInstr *X86MemGuard::RewriteCmov(MachineInstr *MI) {
    auto origBlock = MI->getParent();
    auto MF = origBlock->getParent();
    
    MachineFunction::iterator It = ++origBlock->getIterator();
    
    MachineBasicBlock *thenBlock = MF->CreateMachineBasicBlock(origBlock->getBasicBlock());
    MachineBasicBlock *nextBlock = MF->CreateMachineBasicBlock(origBlock->getBasicBlock());
    MF->insert(It, thenBlock);
    MF->insert(It, nextBlock);
    
    nextBlock->splice(nextBlock->begin(), origBlock, ++MachineBasicBlock::iterator(MI), origBlock->end());
    nextBlock->transferSuccessorsAndUpdatePHIs(origBlock);
    
    auto origCond = X86::getCondFromCMovOpc(MI->getOpcode());
    auto oppositeCond = X86::GetOppositeBranchCondition(origCond);
    BuildMI(origBlock, MI->getDebugLoc(), TII->get(X86::GetCondBranchFromCond(oppositeCond))).addMBB(nextBlock);
    
    origBlock->addSuccessor(thenBlock);
    origBlock->addSuccessor(nextBlock);
    
    thenBlock->addSuccessor(nextBlock);
    
    // CMOV's only conditionally read from memory, can't conditionally write to memory
    // so if it's "interesting", it must be a conditional load
    assert(MI->mayLoad() && !MI->mayStore());
    
    auto destReg = MI->getOperand(0).getReg();
    auto size = (*MI->memoperands_begin())->getSize() * 8;
    
    unsigned int opcode;
    switch(size){
        case 8:
            opcode = X86::MOV8rm;
            break;
        case 16:
            opcode = X86::MOV16rm;
            break;
        case 32:
            opcode = X86::MOV32rm;
            break;
        case 64:
            opcode = X86::MOV64rm;
            break;
        default:
            DEBUG(dbgs() << "[+] Invalid register size: " << size << '\n');
            assert(false && "invalid register size");
            opcode = (unsigned) -1;
            break;
    }
    
    X86MemoryReference ref(MI);
    assert(IsMemoryReferenceInteresting(ref));
    
    auto mov = BuildMI(thenBlock, MI->getDebugLoc(), TII->get(opcode))
            .addReg(destReg)
            .addReg(ref.BaseRegister)
            .addImm(ref.Scale)
            .addReg(ref.IndexRegister)
            .addImm(ref.Displacement)
            .addReg(ref.SegmentRegister);
    MI->eraseFromParent();
    
    
    return mov;
}

void X86MemGuard::InstrumentInstruction(MachineFunction &MF, MachineInstr* MI, Instrumentation *I) {
    assert(MI);
    assert(I);
    // assert(IG->instrumentationLocation);
    
    X86MemoryReference MR = I->memoryReference;
    // MR.Displacement = getMinimumDisplacement(IG);
    
    if (X86::getCondFromCMovOpc(MI->getOpcode()) != X86::COND_INVALID) {
        MI = RewriteCmov(MI);
    }
    assert(X86::getCondFromCMovOpc(MI->getOpcode()) == X86::COND_INVALID);
    
    MachineBasicBlock *origBlock = MI->getParent();
    assert(origBlock);
    
    if (ReportingMethod == MPX) {
        BuildMI(*origBlock, MI, MI->getDebugLoc(), TII->get(X86::BNDCL64rm))
                .addReg(BoundRegister)
                .addReg(MR.BaseRegister)
                .addImm(MR.Scale)
                .addReg(MR.IndexRegister)
                .addImm(MR.Displacement)
                .addReg(MR.SegmentRegister);
        return;
    }
    
    
    
    MachineFunction::iterator It = ++origBlock->getIterator();
    
    MachineBasicBlock *thenBlock = MF.CreateMachineBasicBlock(origBlock->getBasicBlock());
    MachineBasicBlock *nextBlock = MF.CreateMachineBasicBlock(origBlock->getBasicBlock());
    MF.insert(It, thenBlock);
    MF.insert(It, nextBlock);
    
    bool spillingFlags = checkLiveness(MI, X86::EFLAGS);
    if (spillingFlags) {
        BuildMI(*origBlock, MI, MI->getDebugLoc(), TII->get(X86::PUSHF64));
        
        thenBlock->addLiveIn(X86::EFLAGS);
        nextBlock->addLiveIn(X86::EFLAGS);
    }
    
    bool loadedR15 = false;
    if (MR.BaseRegister == MR.IndexRegister) {
        // off(%reg, %reg, scale) <= upper_bound?
        // %reg * (1 + scale) <= upper_bound - off?
        // %reg <= ceil( (upper_bound - off) / (1 + scale) )
        assert(MR.SegmentRegister == 0 && "Segment Register for LEA must be 0 (#3)");
        BuildMI(*origBlock, MI, MI->getDebugLoc(), TII->get(X86::CMP64ri32))
                .addReg(MR.IndexRegister)
                .addImm((signed) (divideCeil(UPPER_BOUND - MR.Displacement, 1 + (unsigned) MR.Scale)));
    } else if ((MR.BaseRegister && MR.IndexRegister) || MR.SegmentRegister) {
        assert(MR.SegmentRegister == 0 && "Segment Register for LEA must be 0 (#1)");
        BuildMI(*origBlock, MI, MI->getDebugLoc(), TII->get(X86::LEA64r), X86::R15)
                .addReg(MR.BaseRegister)
                .addImm(MR.Scale)
                .addReg(MR.IndexRegister)
                .addImm(MR.Displacement)
                .addReg(MR.SegmentRegister);
        BuildMI(*origBlock, MI, MI->getDebugLoc(), TII->get(X86::CMP64ri32))
                .addReg(X86::R15)
                .addImm((signed) UPPER_BOUND);
        loadedR15 = true;
    } else if (MR.BaseRegister) {
        BuildMI(*origBlock, MI, MI->getDebugLoc(), TII->get(X86::CMP64ri32))
                .addReg(MR.BaseRegister)
                .addImm((signed) (UPPER_BOUND - MR.Displacement));
    } else if (MR.IndexRegister) {
        BuildMI(*origBlock, MI, MI->getDebugLoc(), TII->get(X86::CMP64ri32))
                .addReg(MR.IndexRegister)
                .addImm((signed) divideCeil(UPPER_BOUND - MR.Displacement, (unsigned) MR.Scale));
    } else
        assert(MR.BaseRegister || MR.IndexRegister);
    
    nextBlock->splice(nextBlock->begin(), origBlock, MachineBasicBlock::iterator(MI), origBlock->end());
    nextBlock->transferSuccessorsAndUpdatePHIs(origBlock);
    origBlock->addSuccessor(thenBlock, BranchProbability::getBranchProbability(1, 10000));
    origBlock->addSuccessor(nextBlock, BranchProbability::getBranchProbability(9999, 10000));
    
    
    if(spillingFlags) BuildMI(*nextBlock, nextBlock->begin(), MI->getDebugLoc(), TII->get(X86::POPF64));
    BuildMI(origBlock, MI->getDebugLoc(), TII->get(X86::GetCondBranchFromCond(X86::CondCode::COND_GE)))
            .addMBB(nextBlock);
    
    thenBlock->addSuccessor(nextBlock);
    
    if(ReportingMethod == RaiseSignal) {
        bool spillingRdi = checkLiveness(MI, X86::RDI);
        if (spillingRdi) BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::PUSH64r)).addReg(X86::RDI);
        //BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::MOV64ri)).addReg(X86::R15)
                //.addExternalSymbol(MF.createExternalSymbolName("raise"));
        BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::MOV32ri)).addReg(X86::EDI).addImm(ViolationSignal);
        BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::CALL64pcrel32))
                .addExternalSymbol(MF.createExternalSymbolName("raise"));
        if (spillingRdi) BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::POP64r)).addReg(X86::RDI);
        return;
    }
    
    // registers will be preserved as the violation handler must use the COLD calling convention
    // pass the first argument in via our reserved register r15
    if(ViolationHandler == "exit"){
        //BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::MOV64ri)).addReg(X86::R15)
                //.addExternalSymbol(MF.createExternalSymbolName("exit"));
        BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::MOV32ri), X86::EDI).addImm(SIGSEGV);
        BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::CALL64pcrel32))
                .addExternalSymbol(MF.createExternalSymbolName("exit"));
        return;
    }
    
    int rdiAlreadyLoaded = (MR.BaseRegister == X86::RDI && MR.IndexRegister == 0) ||
            (MR.BaseRegister == 0 && MR.IndexRegister == X86::RDI && MR.Scale == 1 && MR.Displacement == 0);
    
    bool spillingRdi = false;
    if (!rdiAlreadyLoaded) {
        spillingRdi = checkLiveness(MI, X86::RDI);
        if (spillingRdi) BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::PUSH64r)).addReg(X86::RDI);
        if (!loadedR15) {
            if(MR.BaseRegister != 0 && MR.IndexRegister == 0 && MR.Displacement == 0){
                BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::MOV64rr)).addReg(X86::RDI).addReg(MR.BaseRegister);
            }else if(MR.BaseRegister == 0 && MR.IndexRegister != 0 && MR.Scale == 1 && MR.Displacement == 0){
                BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::MOV64rr)).addReg(X86::RDI).addReg(MR.IndexRegister);
            }else {
                assert(MR.SegmentRegister == 0 && "Segment Register for LEA must be 0 (#2)");
                BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::LEA64r), X86::RDI)
                        .addReg(MR.BaseRegister)
                        .addImm(MR.Scale)
                        .addReg(MR.IndexRegister)
                        .addImm(MR.Displacement)
                        .addReg(MR.SegmentRegister);
            }
        } else {
            BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::MOV64rr)).addReg(X86::RDI).addReg(X86::R15);
        }
    }
    //BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::MOV64ri)).addReg(X86::R15)
            //.addExternalSymbol(MF.createExternalSymbolName(ViolationHandler));
    BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::CALL64pcrel32))
            .addExternalSymbol(MF.createExternalSymbolName(ViolationHandler));
    
    if (spillingRdi) BuildMI(thenBlock, MI->getDebugLoc(), TII->get(X86::POP64r)).addReg(X86::RDI);
    
    
}

// LEA optimizations already performed with -O3; MemGuard doesn't introduce any redundant LEA's
/* void X86MemGuard::OptimizeLEAs(MachineFunction &MF) {
    if(1 == 1) return;
    unsigned reused = 0;
    unsigned replaced = 0;
    SmallVector<MachineInstr *, 32> toRemove;
    std::map<MachineInstr *, X86MemoryReference> active;
    for (MachineBasicBlock &MBB : MF) {
        active.clear();
        
        for (MachineInstr &MBBI : MBB) {
            
            if( (MBBI.mayLoad() & SECRECY) && X86::getCondFromCMovOpc(MBBI.getOpcode()) != X86::COND_INVALID){
                X86MemoryReference ref(&MBBI);
                if(IsMemoryReferenceInteresting(ref)) {
                    DEBUG(dbgs() << "[+] cmov that must be instrumented is still present: " << MBBI);
                }
            }
            
            if (MBBI.getOpcode() == X86::LEA64r) {
                X86MemoryReference ref(&MBBI);
                MachineInstr *i = getExactMatchIndex(active, ref);
                if (i != nullptr) {
                    BuildMI(MBB, MBBI, MBBI.getDebugLoc(), TII->get(X86::MOV64rr))
                            .addReg(MBBI.getOperand(0).getReg())
                            .addReg(i->getOperand(0).getReg());
                    reused++;
                    toRemove.push_back(&MBBI);
                } else if (ref.Displacement == 0 && ref.IndexRegister == 0 && ref.SegmentRegister == 0 &&
                           ref.BaseRegister != X86::RIP) {
                    // lea (%reg1), %reg2 ---> mov reg1, reg2
                    BuildMI(MBB, MBBI, MBBI.getDebugLoc(), TII->get(X86::MOV64rr))
                            .addReg(MBBI.getOperand(0).getReg())
                            .addReg(ref.BaseRegister);
                    replaced++;
                    toRemove.push_back(&MBBI);
                } else if (ref.BaseRegister != X86::RIP && ref.IndexRegister != X86::RIP) {
                    active.insert({&MBBI, ref});
                }
            }
            for(auto cur = active.begin(), end = active.end(); cur != end;) {
                auto ref = cur->second;
                if (MBBI.modifiesRegister(ref.BaseRegister, TRI)
                    || MBBI.modifiesRegister(ref.IndexRegister, TRI)
                    || MBBI.modifiesRegister(ref.SegmentRegister, TRI)) {
                    active.erase(cur++);
                } else {
                    ++cur;
                }
            }
        }
    }
    for (auto MI : toRemove) MI->eraseFromParent();
    if (reused) DEBUG(dbgs() << "[+] \tReused " << reused << " LEA instructions.\n");
    if (replaced) DEBUG(dbgs() << "[+] \tReplaced " << replaced << " LEA instructions with MOV instructions.\n");
} */




void X86MemGuard::FixColdCallingConvention(MachineFunction &MF) {
    // Problem: cold calling convention does not preserve flags
    // FIX: push/pop flags
    MachineBasicBlock &EB = MF.front();
    auto RBV = SmallVector<MachineBasicBlock *, 16>();
    for (MachineBasicBlock &MBB : MF)
        if (MBB.isReturnBlock())
            RBV.push_back(&MBB);
    
    BuildMI(EB, EB.begin(), EB.begin()->getDebugLoc(), TII->get(X86::PUSHF64));
    for (auto RB : RBV)
        BuildMI(*RB, --RB->end(), (--RB->end())->getDebugLoc(), TII->get(X86::POPF64));
    
    // Problem: on Mac OSX, RSP not 128-byte aligned when reaching XMM instructions (ABI specification)
    // FIX: insert instructions (AND magic) to dynamically align the stack to 1024 cuz why not (offset stored in r15)
    if(!MF.getTarget().getTargetTriple().isMacOSX()) return;
    
    MachineInstr *instToReplace = nullptr;
    MachineInstr *insertBefore = nullptr;
    for (MachineInstr &MI : EB) {
        if (MI.getOpcode() != X86::PUSH64r) {
            if (MI.getOpcode() == X86::SUB64ri32 || MI.getOpcode() == X86::SUB64ri8) {
                instToReplace = &MI;
                insertBefore = MI.getNextNode();
                break;
            }
        }
    }
    assert(insertBefore);
    assert(instToReplace);
    
    const int alignment = 1024;
    BuildMI(EB, insertBefore, insertBefore->getDebugLoc(), TII->get(X86::MOV64ri)).addReg(X86::R15)
            .addImm(alignment - 1);
    BuildMI(EB, insertBefore, insertBefore->getDebugLoc(), TII->get(X86::AND64rr), X86::R15)
            .addReg(X86::R15).addReg(X86::RSP);
    BuildMI(EB, insertBefore, insertBefore->getDebugLoc(), TII->get(X86::OR64ri32), X86::R15)
            .addReg(X86::R15).addImm(1UL << 8);
    BuildMI(EB, insertBefore, insertBefore->getDebugLoc(), TII->get(X86::SUB64rr), X86::RSP)
            .addReg(X86::RSP).addReg(X86::R15);
    
    instToReplace->eraseFromParent();
    for (auto RB : RBV) {
        instToReplace = nullptr;
        insertBefore = nullptr;
        for (auto cur = ++RB->rbegin(), end = RB->rend(); cur != end; ++cur) {
            if (cur->getOpcode() == X86::ADD64ri32 || cur->getOpcode() == X86::ADD64ri8) {
                instToReplace = &*cur;
                break;
            } else {
                insertBefore = &*cur;
            }
        }
        assert(instToReplace);
        assert(insertBefore);
        instToReplace->eraseFromParent();
        BuildMI(EB, insertBefore, insertBefore->getDebugLoc(), TII->get(X86::ADD64rr), X86::RSP).
                addReg(X86::RSP).addReg(X86::R15);
    }
}

INITIALIZE_PASS(IRMemGuard, "ir-memguard", "IR MemGuard", false, false)

INITIALIZE_PASS(X86MemGuard, DEBUG_TYPE, "X86 MemGuard", false, false)

ModulePass *llvm::createIRMemGuardPass() {
    return new IRMemGuard();
}

FunctionPass *llvm::createX86MemGuardPass() {
    return new X86MemGuard();
}

bool llvm::isMemGuardEnabled() {
    return EnableMemGuard;
}

bool llvm::isMemGuardMPXEnabled() {
    return EnableMemGuard && ReportingMethod == MPX;
}
