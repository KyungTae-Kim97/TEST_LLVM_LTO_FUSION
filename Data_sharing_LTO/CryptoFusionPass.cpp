#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

struct CryptoFusionPass : public PassInfoMixin<CryptoFusionPass> {

    PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
        StringRef FuncName = F.getName();
        
        bool isSniperTarget = FuncName.contains("FastCdr_serialize_memcpy") || 
                              FuncName.contains("FastCdr_deserialize_memcpy");

        if (!isSniperTarget) {
            return PreservedAnalyses::all();
        }

        errs() << "\n[CryptoFusionPass] 🎯 Found Sniper Target: " << FuncName << "\n";

        Module *M = F.getParent();
        LLVMContext &Ctx = M->getContext();
        
        PointerType *PtrTy = Type::getInt8PtrTy(Ctx);
        IntegerType *Int64Ty = Type::getInt64Ty(Ctx);
        IntegerType *Int32Ty = Type::getInt32Ty(Ctx);
        IntegerType *Int16Ty = Type::getInt16Ty(Ctx);
        IntegerType *Int8Ty = Type::getInt8Ty(Ctx);

        // =====================================================================
        // [Part 1] TX 송신부: Fast-CDR 직렬화 인라인 후킹 (Zero-Cache-Miss)
        // =====================================================================
        bool Changed = false;
        FunctionCallee FuseEnc8  = M->getOrInsertFunction("fuse_inline_enc_8", Int8Ty, Int8Ty);
        FunctionCallee FuseEnc16 = M->getOrInsertFunction("fuse_inline_enc_16", Int16Ty, Int16Ty);
        FunctionCallee FuseEnc32 = M->getOrInsertFunction("fuse_inline_enc_32", Int32Ty, Int32Ty);
        FunctionCallee FuseEnc64 = M->getOrInsertFunction("fuse_inline_enc_64", Int64Ty, Int64Ty);
        FunctionCallee FuseMemcpy = M->getOrInsertFunction("fuse_inline_enc_memcpy", 
                                    FunctionType::get(Type::getVoidTy(Ctx), {PtrTy, PtrTy, Int64Ty}, false));
        // 💡 [추가] 복호화 융합 함수 선언
        FunctionCallee FuseDecMemcpy = M->getOrInsertFunction("fuse_inline_dec_memcpy", 
                                       FunctionType::get(Type::getVoidTy(Ctx), {PtrTy, PtrTy, Int64Ty}, false));

        bool isDeserialize = FuncName.contains("deserialize");
        FunctionCallee TargetFuseFunc = isDeserialize ? FuseDecMemcpy : FuseMemcpy;

        std::vector<Instruction*> InstToRemove;

        for (BasicBlock &BB : F) {
            // 🚨 [핵심 수정] 범위 기반 for문(for I : BB)을 명시적 반복자로 변경
            for (auto IT = BB.begin(), E = BB.end(); IT != E; ) {
                
                // 💡 명령어를 참조(I)함과 동시에, 반복자(IT)는 다음으로 미리 전진시킵니다.
                Instruction &I = *IT++; 

                if (StoreInst *Store = dyn_cast<StoreInst>(&I)) {
                    Value *Val = Store->getValueOperand();
                    Type *ValTy = Val->getType();
                    Value *Ptr = Store->getPointerOperand();
                    
                    if (isa<AllocaInst>(Ptr->stripPointerCasts())) continue;

                    if (ValTy->isIntegerTy()) {
                        IRBuilder<> Builder(Store);
                        Value *EncVal = nullptr;

                        if (ValTy->isIntegerTy(8))       EncVal = Builder.CreateCall(FuseEnc8, {Val});
                        else if (ValTy->isIntegerTy(16)) EncVal = Builder.CreateCall(FuseEnc16, {Val});
                        else if (ValTy->isIntegerTy(32)) EncVal = Builder.CreateCall(FuseEnc32, {Val});
                        else if (ValTy->isIntegerTy(64)) EncVal = Builder.CreateCall(FuseEnc64, {Val});

                        if (EncVal) {
                            Store->setOperand(0, EncVal);
                            Changed = true;
                            // 💡 [디버깅 추가] StoreInst가 걸렸을 때 출력!
                            errs() << "  👉 [DEBUG] Hooked a 'StoreInst' (" 
                                   << ValTy->getIntegerBitWidth() << "-bit) in function: " << FuncName << "\n";
                        }
                    }
                }
                else if (MemCpyInst *MemCpy = dyn_cast<MemCpyInst>(&I)) {
                    Value *Dest = MemCpy->getRawDest();
                    Value *Src = MemCpy->getRawSource();
                    Value *Len = MemCpy->getLength();
                    
                    IRBuilder<> Builder(MemCpy);
                    Value *Len64 = Builder.CreateZExtOrTrunc(Len, Int64Ty);
                    
                    // 1. 암호화 융합 함수 호출 생성
                    Builder.CreateCall(TargetFuseFunc, {Dest, Src, Len64});
                    
                    // 2. 즉시 삭제! 
                    // (IT는 이미 다음 명령어를 가리키고 있으므로 루프가 터지지 않습니다)
                    MemCpy->eraseFromParent();
                    Changed = true;
                    errs() << "  👉 [DEBUG] Hooked a 'MemCpyInst' (Intrinsic) in function: " << FuncName << "\n";
                }
                // 3️⃣ 🚨 [강력 추천] 이전 분석에서 말씀드린 일반 CallInst(memcpy) 확인 추가
                else if (CallInst *Call = dyn_cast<CallInst>(&I)) {
                    Function *CalledFunc = Call->getCalledFunction();
                    if (CalledFunc && (CalledFunc->getName() == "memcpy" || 
                                       CalledFunc->getName().startswith("llvm.memcpy"))) {
                        
                        Value *Dest = Call->getArgOperand(0);
                        Value *Src  = Call->getArgOperand(1);
                        Value *Len  = Call->getArgOperand(2);
                        
                        IRBuilder<> Builder(Call);
                        Value *Len64 = Builder.CreateZExtOrTrunc(Len, Int64Ty);
                        
                        Builder.CreateCall(TargetFuseFunc, {Dest, Src, Len64});
                        Call->eraseFromParent();
                        Changed = true;

                        // 💡 [디버깅 추가] 일반 memcpy 함수 호출이 걸렸을 때 출력!
                        errs() << "  👉 [DEBUG] Hooked a 'CallInst' (Standard memcpy) in function: " << FuncName << "\n";
                    }
                }
            }
        }
        
        // 💡 더 이상 InstToRemove 배열을 사용할 필요가 없으므로 해당 삭제 루프는 지웁니다.
        // for (Instruction *Inst : InstToRemove) Inst->eraseFromParent(); // <- 삭제
        
        if (Changed) errs() << "[CryptoFusionPass] 💉 Injected Inline Encryption into Fast-CDR: " << FuncName << "\n";
        
        return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

} // end anonymous namespace

llvm::PassPluginLibraryInfo getCryptoFusionPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "CryptoFusionPass", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                auto injectPass = [](ModulePassManager &MPM, OptimizationLevel Level) {
                    MPM.addPass(createModuleToFunctionPassAdaptor(CryptoFusionPass()));
                };
                PB.registerPipelineStartEPCallback(injectPass);
                PB.registerOptimizerLastEPCallback(injectPass);
                PB.registerPipelineEarlySimplificationEPCallback(injectPass);
            }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return getCryptoFusionPassPluginInfo();
}