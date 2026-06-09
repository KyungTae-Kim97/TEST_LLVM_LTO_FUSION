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
        
        // Target function classification (TX maps to FastCdr serialization; RX decryption bypasses this pass by using default OpenSSL)
        bool isFastCdr = (FuncName.contains("Cdr") && 
                          FuncName.contains("serialize") && 
                          !FuncName.contains("deserialize"));

        if (!isFastCdr) return PreservedAnalyses::all();

        Module *M = F.getParent();
        LLVMContext &Ctx = M->getContext();
        
        PointerType *PtrTy = Type::getInt8PtrTy(Ctx);
        IntegerType *Int64Ty = Type::getInt64Ty(Ctx);
        IntegerType *Int32Ty = Type::getInt32Ty(Ctx);
        IntegerType *Int16Ty = Type::getInt16Ty(Ctx);
        IntegerType *Int8Ty = Type::getInt8Ty(Ctx);

        // =====================================================================
        // [Part 1] TX Transmitter: Fast-CDR Serialization Inline Hooking (Zero-Cache-Miss)
        // =====================================================================
        bool Changed = false;
        FunctionCallee FuseEnc8  = M->getOrInsertFunction("fuse_inline_enc_8", Int8Ty, Int8Ty);
        FunctionCallee FuseEnc16 = M->getOrInsertFunction("fuse_inline_enc_16", Int16Ty, Int16Ty);
        FunctionCallee FuseEnc32 = M->getOrInsertFunction("fuse_inline_enc_32", Int32Ty, Int32Ty);
        FunctionCallee FuseEnc64 = M->getOrInsertFunction("fuse_inline_enc_64", Int64Ty, Int64Ty);
        FunctionCallee FuseMemcpy = M->getOrInsertFunction("fuse_inline_enc_memcpy", 
                                    FunctionType::get(Type::getVoidTy(Ctx), {PtrTy, PtrTy, Int64Ty}, false));

        std::vector<Instruction*> InstToRemove;

        for (BasicBlock &BB : F) {
            // [Core Fix] Changed the range-based for loop (for I : BB) to an explicit iterator
            for (auto IT = BB.begin(), E = BB.end(); IT != E; ) {
                
                // Reference the instruction (I) while advancing the iterator (IT) safely ahead of time.
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
                            // [Debugging Added] Print log when a StoreInst is successfully intercepted
                            errs() << "  [DEBUG] Hooked a 'StoreInst' (" 
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
                    
                    // 1. Generate the encryption fusion function call
                    Builder.CreateCall(FuseMemcpy, {Dest, Src, Len64});
                    
                    // 2. Erase immediately! 
                    // (Safe to delete since IT has already advanced to the next instruction)
                    MemCpy->eraseFromParent();
                    Changed = true;
                    errs() << "  [DEBUG] Hooked a 'MemCpyInst' (Intrinsic) in function (debug version): " << FuncName << "\n";
                }
                // [Highly Recommended] Added explicit check for standard CallInst (memcpy) from previous analysis
                else if (CallInst *Call = dyn_cast<CallInst>(&I)) {
                    Function *CalledFunc = Call->getCalledFunction();
                    if (CalledFunc && (CalledFunc->getName() == "memcpy" || 
                                       CalledFunc->getName().startswith("llvm.memcpy"))) {
                        
                        Value *Dest = Call->getArgOperand(0);
                        Value *Src  = Call->getArgOperand(1);
                        Value *Len  = Call->getArgOperand(2);
                        
                        IRBuilder<> Builder(Call);
                        Value *Len64 = Builder.CreateZExtOrTrunc(Len, Int64Ty);
                        
                        Builder.CreateCall(FuseMemcpy, {Dest, Src, Len64});
                        Call->eraseFromParent();
                        Changed = true;

                        // [Debugging Added] Print log when a standard memcpy CallInst is intercepted
                        errs() << "  [DEBUG] Hooked a 'CallInst' (Standard memcpy) in function: " << FuncName << "\n";
                    }
                }
            }
        }
        
        
        if (Changed) errs() << "[CryptoFusionPass] Injected Inline Encryption into Fast-CDR: " << FuncName << "\n";
        
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
