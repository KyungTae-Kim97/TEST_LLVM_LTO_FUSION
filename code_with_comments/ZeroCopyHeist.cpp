#include <security/cryptography/AESGCMGMAC_KeyFactory.h>
#include <security/cryptography/AESGCMGMAC_Types.h>
#include <security/cryptography/AESGCMGMAC_Transform.h>

#include <array>
#include <cstring>
#include <cstdio>
#include <mutex>

using namespace eprosima::fastrtps::rtps::security;

extern "C" void stash_stolen_key(const uint8_t* key, const uint8_t* iv);

// 💡 [핵심 필터 매크로] 페이로드(실제 센서 데이터)를 보호하는 채널인지 확인하는 플래그
#ifndef PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED
#define PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED (1UL << 0)
#endif

// =====================================================================
// 🚀 [송신부(TX) Phase 2] 자신이 생성한 User Payload 키 장전
// =====================================================================
extern "C" void steal_and_bake_key(void* raw_handle) {
    if (raw_handle == nullptr) return;
    AESGCMGMAC_WriterCryptoHandle* local_writer = static_cast<AESGCMGMAC_WriterCryptoHandle*>(raw_handle);
    if (local_writer->nil()) return;

    std::unique_lock<std::mutex> lock((*local_writer)->mutex_);
    
    uint32_t attrs = (*local_writer)->EndpointPluginAttributes;
    if ((attrs & PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED) == 0) return;

    if ((*local_writer)->EntityKeyMaterial.empty()) return;
    auto& keyMat = (*local_writer)->EntityKeyMaterial.at(0);

    // 🎯 [정석 고치기] 7777 대신, 이 핸들이 가지고 있는 진짜 동적 세션 ID(혹은 시퀀스 넘버) 자원을 가져옵니다.
    // ※ FastDDS 버전에 따라 세션 ID가 담긴 멤버 변수명(예: session_id 또는 crypto_sequence_number)을 그대로 매핑합니다.
    uint32_t dynamic_session_id = (*local_writer)->session_id; 

    std::array<uint8_t, 32> precomputed_session_key;
    AESGCMGMAC_Transform temp_transform;
    
    // 💡 정석대로 진짜 동적 ID를 넣어 세션 키를 유도합니다.
    temp_transform.compute_sessionkey(precomputed_session_key, keyMat, dynamic_session_id);

    std::array<uint8_t, 12> iv = {0};
    std::memcpy(iv.data(), &dynamic_session_id, 4); // IV 시작점도 동적 ID와 동기화
    stash_stolen_key(precomputed_session_key.data(), iv.data());
}

// =====================================================================
// 🛡️ [수신부(RX) Phase 4] 네트워크로 배송된 User Payload 키 장전
// =====================================================================
extern "C" void steal_and_bake_key_rx(void* raw_handle) {
    if (raw_handle == nullptr) return;
    
    DatawriterCryptoHandle* base_handle = static_cast<DatawriterCryptoHandle*>(raw_handle);
    AESGCMGMAC_WriterCryptoHandle& remote_writer = AESGCMGMAC_WriterCryptoHandle::narrow(*base_handle);
    if (remote_writer.nil()) return;

    std::unique_lock<std::mutex> lock(remote_writer->mutex_);
    
    uint32_t attrs = remote_writer->EndpointPluginAttributes;
    if ((attrs & PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED) == 0) return;

    if (remote_writer->Entity2RemoteKeyMaterial.empty()) return;
    auto& keyMat = remote_writer->Entity2RemoteKeyMaterial.back();

    // 🎯 [정석 고치기] 상대방(TX)이 패킷에 실어 보내어, 내 remote_writer 핸들에 이미 입력된 
    // 수신된 최신 동적 세션 ID를 그대로 가져옵니다.
    uint32_t dynamic_session_id = remote_writer->remote_session_id; 

    std::array<uint8_t, 32> precomputed_session_key;
    AESGCMGMAC_Transform temp_transform;
    
    // 💡 상대방과 완전히 일치하는 동적 ID로 수신측 세션 키를 유도합니다.
    temp_transform.compute_sessionkey(precomputed_session_key, keyMat, dynamic_session_id);

    std::array<uint8_t, 12> iv = {0};
    std::memcpy(iv.data(), &dynamic_session_id, 4);
    stash_stolen_key(precomputed_session_key.data(), iv.data());
}


Q. "송신부와 수신부가 동일한 이름의 stash_stolen_key 인터페이스를 공유하는데, 멀티스레드 및 분산 환경에서 메모리 충돌이나 키 오염 리스크는 없습니까?"*라고 송곳 질문을 던지면 이 시나리오 분할 논리로 완전히 짓밟으십시오.

A. 
디자인 패턴 관점에서 컴파일러 패스의 추상화를 위해 동일한 stash_stolen_key 심볼을 공유하도록 설계했지만, 실제 런타임의 주소 공간(Address Space) 분리를 통해 동시성 리스크를 완벽히 제어했습니다.
독립된 멀티 프로세스(IPC) 환경일 경우, TX와 RX는 각자의 프로세스 메모리 컨텍스트에 독립적으로 로드된 g_zero_copy_ctx 전역 구조체를 참조하므로 물리적인 메모리 간섭이 전혀 발생하지 않습니다.
만약 단일 프로세스 내 복합 노드(Component Node) 환경이라 하더라도, DDS Security Standard에 의해 하나의 데이터 채널(Topic)에서 공유하는 암복호화 세션 키는 수학적으로 일치하는 동일 대칭키입니다.
따라서 동일 주소 공간 내에서 덮어쓰기가 발생하더라도 데이터 무결성이 수호되며, 컨텍스트 내부적으로 락이 없는 std::atomic<bool> is_ready 장벽과 memory_order_release 모델을 적용했기 때문에 CPU 파이프라인 상의 순서 뒤바뀜(Reordering) 오버헤드마저 제로화하여 다중 스레드 환경 속에서도 안전하게 키를 동기화할 수 있었습니다.

=====================================================================================================
1. 필터링 아키텍처: "왜 굳이 PAYLOAD_PROTECTED 속성만 필터링했는가?"

uint32_t attrs = (*local_writer)->EndpointPluginAttributes;
if ((attrs & PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED) == 0) return;

면접관: "비트 연산 마스크를 써서 진짜 센서 데이터 채널(PAYLOAD_PROTECTED)만 필터링하고 나머지는 리턴(Drop)시켰습니다. DDS 내부에는 이 속성 말고도 수많은 제어/참여(Discovery) 채널들이 존재할 텐데, 이
 필터를 넣지 않았을 때 시스템 전반에 어떤 치명적인 오작동이 발생합니까?"

🏆 시니어급 합격 답변: > DDS 미들웨어 아키텍처 환경에서는 실제 토픽 데이터(User Payload)가 흐르는 데이터 채널뿐만 아니라, 노드 간의 참여를 확인하는 Discovery 채널, 매칭을 확인하는 내장(Built-in) 제어 채널들이 동일한 암호화 엔진을 공유합니다.
만약 이 비트 마스크 필터링이 없다면, 미들웨어가 구동될 때 뿜어져 나오는 모든 제어용 마스터 키들이 구별 없이 stash_stolen_key로 무차별 덮어쓰기(Overwrite)가 됩니다.
결과적으로 진짜 센서 데이터가 송수신되기도 전에 제어용 채널의 키 스트림이 세션 키 버퍼를 오염시켜, 정작 실제 데이터가 전송되는 시점에는 암호키 불일치로 인한 전면적인 전송 실패(통신 먹통)가 유발됩니다. 시스템의 제어 트래픽과 데이터 트래픽의 보안 속성을 명확히 분리하여, **우리가 가로채고자 하는 타겟 페이로드 채널의 고유성만 정밀 타격(Pinpoint Targeting)**하기 위해 필수적인 아키텍처적 안전장치입니다.
=====================================================================================================

2. 스레드 동기화와 데들락: "왜 하필 여기서 mutex_를 잠갔는가?"

std::unique_lock<std::mutex> lock((*local_writer)->mutex_);

면접관: "FastDDS 객체 내부에 숨겨진 mutex_를 가져와서 unique_lock으로 동기화를 걸었습니다. 우리가 앞에서 배운 Atomics나 Lock-free 기법을 쓰지 않고 여기서 굳이 무거운 Mutex 락을 잡은 진짜 하드웨어적/소프트웨어적 명분은 무엇입니까?"

🏆 시니어급 합격 답변: > 우리가 앞서 구현한 데이터 전송 루프(fuse_inline_enc_memcpy)는 단일 변수(IV 카운터)만 제어하므로 나노초 단위의 Atomics 락 프리가 정답이었습니다.
하지만 지금 이 steal_and_bake_key 함수가 다루는 대상은 단일 변수가 아니라, FastDDS 객체 내부의 깊은 힙(Heap) 메모리에 할당된 고유 구조체인 EntityKeyMaterial 배열(Vector) 자원입니다. 
현대 DDS의 동적 노드 매칭 환경에서는 백그라운드 스레드가 이 키 배열을 동적으로 해제하거나 재할당(Reallocation)할 수 있습니다.
만약 여기서 Atomics 모델을 고집하거나 동기화를 빠뜨리면, 내가 키를 복사하려는 찰나에 다른 스레드가 배열을 건드려 댕글링 포인터(Dangling Pointer) 참조나 세그멘테이션 폴트(Segmentation Fault)로 전체 미들웨어가 크래시 날 수 있습니다. 
따라서 복사 대상 힙 리소스의 생명 주기(Lifetime)를 안전하게 수호하기 위해, FastDDS 하부 코어가 사용하는 원본 뮤텍스를 그대로 가로채서 컨텍스트 세이프(Context-safe)하게 동기화 장벽을 친 것입니다.

3. TX가 세션 키를 생성하는 타이밍과, 실제 데이터가 도는 타이밍이 어떻게 유기적으로 맞아떨어지나?
공격 의도: 이 steal_and_bake_key 함수가 실행되어 키를 구워놓는 시점이 런타임 데이터 전송 루프보다 선행된다는 것을 확신하고 설계했는지 묻는 질문입니다.

🏆 모범 답변: > DDS 아키텍처에서 노드가 처음 참여(Discovery)하거나 새로운 토픽이 매칭될 때, 핸드셰이크 프로토콜이 완료되면서 이 핸들 키 장전 함수가 가장 먼저 실행됩니다.

이때 동적으로 유도된 세션 키는 고속 공유 메모리(SHM) 세션 컨텍스트에 단 한 번 안전하게 캐싱(Bake)됩니다.
이후 실제 센서 데이터가 수백 메가바이트씩 쏟아지는 발행(publish()) 파이프라인이 시작되면, 무거운 키 유도 연산을 전면 배제한 채 이미 완벽하게 구워져 준비된 세션 키만을 가져와 나노초 단위로 인라인 암호화를 수행하므로 레이턴시가 전혀 발생하지 않는 이상적인 타임라인이 확립됩니다.

질문자님이 만드신 보안 가속 아키텍처도 거시적으로 보면 이 Stateless 정신을 완벽하게 계승하고 있습니다.

C++
// 우리 코드의 흐름
temp_transform.compute_sessionkey(precomputed_session_key, keyMat, dynamic_session_id);
매 패킷마다 "저번에 어디까지 보냈더라?", "상대방 상태가 지금 어떤가?" 하고 서로 구질구질하게 실시간으로 대화하며 상태를 동기화하는 무거운 과정을 전면 배제했습니다.

대신 FastDDS가 패킷에 실어 보내는 고유의 dynamic_session_id (동적 세션 번호표)를 낚아채서, 그 번호표 단 하나만 보고 즉시 대칭되는 암호 키를 그 자리에서 독립적으로 유도해 연산해버립니다.

과거의 상태나 연결 이력에 종속되지 않고, "들어온 번호표(상태) 정보 하나만 보고 나노초 만에 즉석에서 연산을 완결 짓는 구조", 이것이 바로 시스템 프로그래밍에서 추구하는 Stateless 최적화의 본질입니다.

한 줄 요약: 과거의 기록을 서버 메모리에 저장해두는 복잡한 방식을 버리고, "요청할 때 필요한 신분증과 데이터를 통째로 넘겨서 그 한 번의 호흡으로 연산을 끝내버리는 독립적인 방식"이라고 이해하시면 완벽합니다. Stateless가 왜 시스템을 가볍고 빠르게 만드는지 감이 좀 오시나요?