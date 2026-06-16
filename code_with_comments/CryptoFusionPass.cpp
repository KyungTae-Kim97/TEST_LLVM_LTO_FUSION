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
// "Iterator 무결성 방어:" "루프 조건절에서 IT++를 안 하고 내부에서 *IT++를 선행한 이유는, 패스가 런타임 오버헤드를 줄이기 위해 memcpy 명령어를 트리에서 완전히 삭제(eraseFromParent)하기 때문입니다. 
// 무효화된 반복자 참조로 인한 컴파일러 세그폴트(Segfault)를 원천 차단한 구조입니다."
// "비대칭 타겟 유연성:" "분기 2, 3번을 보시면 복사 명령어를 지운 자리에 TargetFuseFunc을 넣는데, 이 변수는 앞단에서 TX/RX 여부에 따라 암호화(FuseMemcpy)와 복호화(FuseDecMemcpy)로 이미 스위칭되어 있습니다. 
// 덕분에 루프 코어는 단일 추상화를 유지하면서 비대칭 LTO 융합을 깔끔하게 처리합니다."

                if (StoreInst *Store = dyn_cast<StoreInst>(&I)) {
                    Value *Val = Store->getValueOperand();
                    Type *ValTy = Val->getType();
                    Value *Ptr = Store->getPointerOperand();
                    
                    if (isa<AllocaInst>(Ptr->stripPointerCasts())) continue;

                    if (ValTy->isIntegerTy()) {
                        IRBuilder<> Builder(Store);
                        Value *EncVal = nullptr;   // <- why pointer?
                        // LLVM 소스코드(C++) 내에서 Value라는 클래스는 LLVM IR 세계에 존재하는 '모든 계산 결과물 및 명령어 객체'를 가리키는 최상위 부모 클래스이기 때문입니다.
                            // 컴파일러의 시선: LLVM 패스를 짤 때, 우리는 IR 인스트럭션 객체들을 포인터(Value*, Instruction*)로 조작합니다. 
                                // 즉, Value *EncVal은 "앞으로 내가 새로 만들 '암호화 호출 명령어'라는 객체를 가리키는 C++ 포인터 바구니"일 뿐입니다.
                            // 런타임의 시선: 실제 프로그램이 실행될 때 EncVal에 매핑된 하드웨어 자원은 주소가 아니라 CPU의 레지스터(Register)가 됩니다.

                        if (ValTy->isIntegerTy(8))       EncVal = Builder.CreateCall(FuseEnc8, {Val});
                        //%EncVal = call i8 @fuse_inline_enc_8(i8 %Val)
                        // 하드웨어에서의 실제 동작: 프로그램이 실행되면 CPU는 fuse_inline_enc_8 함수를 실행한 뒤, 
                        // 그 8비트 결과값을 메모리 주소에 담아 보내지 않고 CPU의 가상 레지스터(예: ARM의 r0 레지스터)에 그냥 알맹이 값으로 꽂아버립니다.
                        else if (ValTy->isIntegerTy(16)) EncVal = Builder.CreateCall(FuseEnc16, {Val});
                        else if (ValTy->isIntegerTy(32)) EncVal = Builder.CreateCall(FuseEnc32, {Val});
                        else if (ValTy->isIntegerTy(64)) EncVal = Builder.CreateCall(FuseEnc64, {Val});

                        if (EncVal) {
                            Store->setOperand(0, EncVal);
// C++의 '런타임' 개념과 LLVM IR의 '컴파일 타임' 개념
// 면접관이 *"여기서 Value *를 사용하고 8비트 함수를 호출하는데, 이게 메모리 단에서 어떻게 처리되나요?"*라고 물어본다면 이렇게 대답하십시오.
// "LLVM 패스 코드에서 Value *EncVal로 선언된 것은 컴파일 타임에 IR 객체를 다루기 위한 C++ 포인터일 뿐, 런타임의 메모리 주소를 의미하지 않습니다.
// 제가 설계한 fuse_inline_enc_8은 8비트 정수 값(i8)을 레지스터로 직접 반환합니다. 따라서 컴파일러는 메모리 주소를 경유하는 load/store 오버헤드 없이, 
// 함수가 반환한 CPU 레지스터의 암호화된 알맹이 값을 기존 StoreInst 명령어가 타겟 버퍼에 쓸 수 있도록 setOperand(0)를 통해 하드웨어 레지스터 레벨에서 다이렉트로 융합(Direct Register-level Fusion)시킵니다."
                            Changed = true;
                            // 💡 [디버깅 추가] StoreInst가 걸렸을 때 출력!
                            errs() << "  👉 [DEBUG] Hooked a 'StoreInst' (" 
                                   << ValTy->getIntegerBitWidth() << "-bit) in function: " << FuncName << "\n";
                        }
                    }
                }
                //Instruction &I는 기본적으로 아주 추상적인 '명령어'입니다. 이게 더하기(Add)인지, 함수 호출(Call)인지, 메모리 복사(MemCpy)인지 겉보기엔 모릅니다.
                // dyn_cast는 LLVM이 자체적으로 만든 초고속 타입 검사기(RTTI)입니다. *"너 혹시 MemCpyInst니?"*라고 찔러보고, 맞으면 해당 타입으로 변환된 포인터를 반환하고, 
                // 아니면 빠르고 깔끔하게 nullptr을 반환하여 다음으로 넘어가게(if문 실패) 해줍니다.
                // C++의 표준 dynamic_cast보다 훨씬 가볍고 빠르기 때문에 LLVM에서 강제하는 패턴입니
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
            [](PassBuilder &PB) { //뜻: LLVM 공장장(PB)을 불러와서 "내가 이 공장에 특수 공정을 등록하겠다"고 선언하는 시작점입니다
                auto injectPass = [](ModulePassManager &MPM, OptimizationLevel Level) { //변환 젠더(어댑터) 조립하기 
                // //공장 안에는 차례대로 부품을 조립하는 여러 라인(MPM, main 패스 매니저)
                    MPM.addPass(createModuleToFunctionPassAdaptor(CryptoFusionPass())); // 뜻: 공장의 메인 컨베이어 벨트는 거대한 컨테이너 단위(ModulePassManager)로 움직입니다. 
                                                                                        // 그런데 우리가 만든 암호화 패스(CryptoFusionPass)는 컨테이너 내부의 세부 부품 단위(Function)형 장비입니다.
                                                                                        // 규격이 맞지 않기 때문에, 중간에 규격 변환 젠더(createModuleToFunctionPassAdaptor)를 씌워서 
                                                                                        // 메인 벨트(MPM)에 안전하게 장착(addPass)할 수 있도록 셋팅해둔 것입니다.
                };
                //핵심 길목 3곳에 주사기 배치하기 (EP: Extension Point)
                PB.registerPipelineStartEPCallback(injectPass); //뜻: "공장장님, 조립 라인이 '시작(Start)'하자마자 이 주사기(injectPass)를 한 번 놓아주세요." 다른 표준 최적화가 코드를 쪼개놓기 전에 날것의 Fast-CDR 형태를 안전하게 포착하기 위함입니다.
                PB.registerOptimizerLastEPCallback(injectPass);//"그리고 모든 정규 조립 공정이 다 끝나고 출고되기 '직전(Last)'에 한 번 더 놓아주세요." 혹시 중간 과정에서 인라이닝되면서 새로 터져 나온 memcpy가 있다면 최종적으로 싹 다 잡아내기 위한 이중 안전장치입니다.
                PB.registerPipelineEarlySimplificationEPCallback(injectPass); //뜻: "마지막으로 초기 코드 정리 단계(EarlySimplification)의 길목에도 주사기를 대기시켜 주세요."
            }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    //clang -fpass-plugin=./CryptoFusionPass.so main.cpp
    // 이 명령어가 실행되는 순간, clang 컴파일러 엔진은 속으로 이렇게 생각합니다.
    // "어? 사용자가 외부에서 만든 특수 공정 파일(.so)을 가져왔네? 그럼 이 파일 안에 컴파일러 공장장한테 제출할 명세서가 들어있을 텐데... 그 명세서를 꺼내려면 무조건 llvmGetPassPluginInfo라는 이름의 열쇠 구멍을 찾아서 돌려야 해!"
    // clang 엔진은 질문자님의 코드를 전혀 모르는 상태에서 무작정 .so 파일을 열고 딱 이 llvmGetPassPluginInfo라는 정해진 이름의 함수(마스터키)만 수색합니다. 이 함수가 있으면 문이 열리면서 아까 공부한 콜백 지시서(getCryptoFusionPassPluginInfo())를 수령해 가고, 없으면 *"쓸 수 없는 플러그인"*이라며 에러를 뿜고 멈춰버립니다.
    return getCryptoFusionPassPluginInfo();
}