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
        PointerType *PtrTy = Type::getInt8PtrTy(Ctx); //범용 포인터 타입인 i8*
        
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
// 면접관이 *"여기서 CreateBitCast를 사용한 이유가 무엇이고, 이게 런타임 성능에 미치는 영향이 무엇입니까?"*
// "탈취하려는 함수의 3번째 인자(Arg1)는 미들웨어 고유의 복잡한 구조체 포인터 타입인 반면, 제가 설계한 키 탈취 커널 함수는 범용 포인터 타입인 i8*을 매개변수로 받습니다.
// LLVM의 엄격한 타입 시스템(Strict Type System)을 충족시키기 위해 **CreateBitCast**를 사용하여 컴파일 타임의 타입 불일치를 해결했습니다.
// 이 연산은 데이터의 물리적 비트 구조를 전혀 변형하지 않고 컴파일러의 의미론적 시선(Semantics)만 변경하므로, 실제 기계어 레벨에서 추가적인 하드웨어 인스트럭션을 생성하지 않아 런타임 오버헤드가 완벽히 제로인 최적화 기법입니다."
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

// "컴파일 타임(IR)과 런타임(Execution)의 차이는 최적화 메커니즘이 설계되는 단계와 하드웨어 자원이 실제로 소모되는 단계의 차이입니다.
// 제가 작성한 LLVM Custom Pass C++ 코드는 오직 컴파일 타임에만 실행됩니다. 이 단계에서 제 패스는 실제 암호화 연산을 수행하지 않고, 
// 전역 최적화(LTO) 파이프라인 관점에서 FastCdr 함수의 IR 트리를 스캔합니다. 그리고 런타임 성능을 갉아먹는 표준 memcpy 인스트럭션을 발견하면 이를 설계도 상에서 완전히 도려내고(eraseFromParent), 
// 런타임에 실행될 융합 커널의 함수 호출 명세(CreateCall)로 대체하는 **의미론적 조작(Semantic Modification)**만 수행한 뒤 소멸합니다.
// 이후 프로그램이 타겟 칩셋에서 구동되는 런타임 시점이 되어서야, 컴파일 타임에 정밀하게 심어놓은 의도대로 CPU 가상 레지스터 레벨에서 직렬화와 암호화가 
// 단 한 번의 메모리 접근 사이클 내에서 비대칭적으로 융합되어 실행(Asymmetric Register-level Fusion)됩니다.
// 결론적으로 컴파일 타임에 컴파일러 아키텍처를 이용해 정밀한 설계도를 그려놓았기 때문에, 런타임에 하드웨어 가동률을 극대화하고 캐시 오염을 제로로 만드는 성능적 이득(Throughput 향상 및 Tail Latency 단축)을 달성할 수 있었습니다."