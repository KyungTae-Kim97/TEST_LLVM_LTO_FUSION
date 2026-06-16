#include "FusedCryptoPayload.h"
#include <string.h>
#include <stdio.h> 
#include <array>
#include <atomic> // 💡 Mutex 대신 Atomic을 사용하여 0ns 오버헤드 달성

Q. __attribute__(...) : "컴파일러에게 내리는 특수 명령문"
A. 
이유: C++ 표준 문법(예: int, if, for)만으로는 하드웨어 칩셋의 특성이나 운영체제(OS)의 특별한 규칙을 100% 제어할 수 없습니다.
그래서 GCC나 Clang 같은 컴파일러들은 자신만의 독자적인 확장 기능을 제공하는데, 그게 바로 __attribute__입니다.
비유: 컴파일러라는 공장장에게 *"이건 일반적인 규격이 아니니까, 내가 괄호 안에 적어둔 특수 지시사항(visibility, aligned)을 완벽하게 반영해서 조립해라"*라고 전달하는 '특수 주문서'입니다.

Q. visibility("default")
A. 
공유 라이브러리(Dynamic Shared Library) 형태로 빌드
만약 이 옵션을 주지 않으면, 컴파일러는 보안과 성능을 위해 라이브러리 내부의 변수나 함수들을 전부 꽁꽁 숨겨버립니다. 외부 프로그램(Clang 컴파일러 엔진이나 FastDDS 미들웨어 등)이 이 .so 파일을 열어보아도 내부 변수의 주소를 찾을 수 없습니다
visibility("default") 속성은 이 공유 라이브러리(.so)가 동적 로드되었을 때, 제가 작성한 LLVM Custom Pass나 외부 미들웨어 엔진이 이 키 버퍼의 주소(심볼)를 찾아서 직접 조작할 수 있도록 링커 레벨에서 문을 열어둔 것입니다.

extern "C" {
    __attribute__((visibility("default"))) FusedCryptoPayload g_crypto_engine;
    __attribute__((visibility("default"))) size_t tl_aad_len = 0;
    __attribute__((visibility("default"))) size_t tl_payload_len = 0;
    __attribute__((visibility("default"))) bool g_fuse_active = false;
    __attribute__((visibility("default"), aligned(16))) uint8_t tx_keystream_buf[128] = {0};  
    // Q. 버퍼에 aligned(16)을 명시한 진짜 이유는 무엇입니까

    // A. 128바이트짜리 배열을 메모리(RAM)에 배치할 때, 아무 데나 주소를 잡지 말고 반드시 '16의 배수'가 되는 주소(예: 0x1000, 0x1010, 0x1020...)에만 딱 맞춰서 예쁘게 시작해
    // aligned(16) 속성은 ARM NEON SIMD 가속기의 파이프라인 스톨을 제로화하기 위한 최적화입니다. 128비트 대용량 병렬 로드 명령어(vld1q_u8)는 하드웨어 레벨에서 16바이트 정렬을 강력히 요구합니다. 
    // 메모리 주소 경계가 어긋나면 단일 사이클로 끝날 메모리 접근이 2사이클 이상으로 늘어나는 미스얼라인먼트 페널티가 발생합니다. 메모리 시작점을 16바이트 단위로 강제 정렬해 둠으로써, 
    // 하드웨어 버스 인터페이스의 지연을 원천 차단하고 극단의 인라인 속도를 구현할 수 있었습니다."
    __attribute__((visibility("default"), aligned(16))) uint8_t tx_gmac_buf[128] = {0};      
    __attribute__((visibility("default"))) uint8_t tx_ks_pos = 128;   
    __attribute__((visibility("default"))) uint8_t tx_gmac_pos = 0;
}

// =========================================================================
// 🌐 [Phase 1 연결부] 웜홀 저장소의 주인을 이 .so 파일로 변경합니다!
// =========================================================================
struct ZeroCopyCryptoContext {
    std::array<uint8_t, 32> precomputed_session_key;
    std::array<uint8_t, 12> initialization_vector;
    std::atomic<bool> is_ready{false}; // 💡 락(Lock) 없는 동기화
};

Q. 면접관이 *"하드웨어 단에서 코어를 막아서는 게 Mutex랑 다를 바 없지 않나요?"*라고 꼬리 질문을 던지면 이 논리로 종지부를 찍으십시오.

A. "하드웨어 레벨에서 타 코어의 접근을 제한한다는 개념은 유사하지만, 동기화를 수행하는 제어 주체와 비용에서 근본적인 차이가 있습니다.
Mutex는 소프트웨어인 OS 커널이 개입하여 스레드를 수면 상태로 전환시키고 컨텍스트 스위칭을 유발하므로 **수천 나노초 이상의 막대한 지연 페널티(Jitter)**를 발생시킵니다.
반면, 제가 설계한 Atomics 구조는 소프트웨어 개입 없이 CPU 실리콘 내부의 캐시 일관성 프로토콜(Cache Coherency)과 전기 회로가 직접 코어 파이프라인을 단 몇 나노초 동안만 일시 정지(Stall)시킵니다.
스레드가 잠들지 않고 CPU 위에서 락 프리(Lock-free)로 즉시 통과하기 때문에, 오버헤드를 **나노초 단위(0ns 지향)**로 극소화하여 실시간 보안 미들웨어의 초고속 스루풋을 달성할 수 있었습니다."

__attribute__((visibility("default"))) ZeroCopyCryptoContext g_zero_copy_ctx;

// 내부 헬퍼 함수
inline __attribute__((always_inline)) void tx_generate_keystream() {
    g_crypto_engine.generate_keystream_128bytes_arm(tx_keystream_buf); 
    tx_ks_pos = 0;
}

extern "C" {
    
    // 💡 [새로운 수신부] FastDDS의 ZeroCopyHeist가 훔친 키를 여기에 집어넣습니다.
    __attribute__((visibility("default"))) 
    void stash_stolen_key(const uint8_t* key, const uint8_t* iv) {
        memcpy(g_zero_copy_ctx.precomputed_session_key.data(), key, 32);
        memcpy(g_zero_copy_ctx.initialization_vector.data(), iv, 12);
        g_zero_copy_ctx.is_ready.store(true, std::memory_order_release); // 장전 완료!
    }
면접관의 공격: "Mutex Lock을 쓰면 안전한데 왜 굳이 Lock-free Atomics를 썼습니까? 그리고 기본값인 std::memory_order_seq_cst 대신 release/acquire 세그먼트를 명시한 이유는 무엇입니까?"

🏆 합격을 부르는 답변 스크립트: > "Mutex는 컨텍스트 스위칭 오버헤드로 인해 실시간성 미들웨어에서 수십 마이크로초(µs) 단위의 지연(Jitter)을 유발합니다. 이를 극복하기 위해 Lock-free 동기화를 채택했습니다.
이때 std::memory_order_release와 acquire를 매칭한 이유는 '메모리 가시성(Memory Visibility) 보장'과 '컴파일러/CPU의 명령어 재정렬(Reordering) 방지' 때문입니다.
stash_stolen_key에서 키와 IV를 메모리에 memcpy한 직후 release로 장전하면, 컴파일러와 CPU는 키 복사 명령이 is_ready 저장 명령 뒤로 밀리는 것을 원천 차단합니다. 
수신(RX) 측이 acquire로 이를 읽는 순간, 그 직전에 작성된 키와 IV 데이터가 수신 측 CPU 코어의 캐시에 완벽하게 동기화(Happens-before 관계)됨을 보장하므로 데이터 오염 없이 0ns 오버헤드로 동시성을 제어할 수 있습니다."

std::memory_order_seq_cst와 release/acquire의 근본적인 차이는 
**'전역적인 단일 타임라인(Single Total Order)의 보장 여부'**에 있습니다.
release/acquire는 특정 아토믹 변수를 매개로 변수를 작성한 스레드와 이를 읽는 스레드 간의 **1:1 인과관계(Happens-before)**만 국소적으로 수호합니다. 따라서 여러 독립된 아토믹 변수가 다중 코어에서 교차할 때, 각 코어가 바라보는 사건의 순서가 일치하지 않는 메모리 가시성 파편화 리스크가 존재합니다.
반면 std::memory_order_seq_cst는 시스템 내 모든 스레드가 아토믹 연산의 발생 순서를 전역적으로 완벽히 동일하게 인지하도록 하드웨어 레벨의 전역 버스 펜스(Full Fence)를 강제합니다.

Q. 면접관이 질문자님과 똑같은 의도로 *"TX와 RX는 독립된 프로세스 메모리 공간을 쓰는데 동기화 옵션은 아무거나 상관없지 않나요?"*라고 유도 질문을 던진다면, 이 답변으로 오퍼를 거머쥐십시오.
정확한 지적이십니다. 물리적으로 TX와 RX는 완전히 독립된 프로세스 컨텍스트에서 구동되므로 두 프로세스의 g_zero_copy_ctx 간에는 어떠한 메모리 경합도 발생하지 않습니다.
하지만 제가 release/acquire를 정밀하게 명시한 이유는 단일 프로세스 내부에서 작동하는 멀티스레드 간의 하드웨어 메모리 가시성을 통제하기 위함입니다.
FastDDS 내부에서 키를 탈취해 저장하는 백그라운드 스레드와, 이를 로드하여 인라인 암호화를 수행하는 송신 스레드 간에 컴파일러 및 CPU의 명령어 재정렬(Reordering)로 인한 데이터 오염을 방지해야 합니다.
이때, 무겁고 전역적인 하드웨어 버스 락을 유발하는 seq_cst를 사용하면 독립된 프로세스 환경에서 불필요한 전역 파이프라인 스톨 페널티를 받게 됩니다. 반면 release/acquire 페어를 사용하면 1:1 단방향 인과관계만 국소적으로 보장(Happens-before 관계 확립)하므로, 타 코어에 아무런 부담을 주지 않고 프로세스 내부 동기화 오버헤드를 극소화할 수 있어 이 방식을 고수했습니다.

void fuse_finalize_enc(uint8_t* out_tag);
    bool fuse_verify_dec(const uint8_t* expected_tag);

    void fuse_init(const uint8_t* key, const uint8_t* iv) {
        g_crypto_engine.init(key, iv);
        tl_aad_len = 0;
        tl_payload_len = 0;
        tx_ks_pos = 128; 
        tx_gmac_pos = 0;
        g_fuse_active = true;
    }

    void fuse_update_enc(const uint8_t* src, uint8_t* dest, size_t len) {
        if (dest != nullptr) return;
        size_t offset = 0;
        tl_aad_len += len;
        while (offset + 16 <= len) {
            g_crypto_engine.process_aad_16bytes_fused(src + offset);
            offset += 16;
        }
        size_t tail_len = len - offset;
        if (tail_len > 0) {
            g_crypto_engine.process_aad_tail_fused(src + offset, tail_len);
        }
    }

    uint8_t fuse_inline_enc_8(uint8_t pt) {
        if (!g_fuse_active) return pt;
        if (tx_ks_pos == 128) tx_generate_keystream();
        uint8_t ct = pt ^ tx_keystream_buf[tx_ks_pos++];
        tx_gmac_buf[tx_gmac_pos++] = ct;
        if (tx_gmac_pos == 128) {
             for(int i=0; i<8; i++) g_crypto_engine.accumulate_gmac(tx_gmac_buf + i*16);
             tx_gmac_pos = 0;
        }
        tl_payload_len += 1;
        return ct;
    }

    uint16_t fuse_inline_enc_16(uint16_t pt) {
        if (!g_fuse_active) return pt;
        uint8_t* pt_bytes = (uint8_t*)&pt;
        uint16_t ct;
        uint8_t* ct_bytes = (uint8_t*)&ct;
        ct_bytes[0] = fuse_inline_enc_8(pt_bytes[0]);
        ct_bytes[1] = fuse_inline_enc_8(pt_bytes[1]);
        return ct;
    }

    uint32_t fuse_inline_enc_32(uint32_t pt) {
        if (!g_fuse_active) return pt;
        uint8_t* pt_bytes = (uint8_t*)&pt;
        uint32_t ct;
        uint8_t* ct_bytes = (uint8_t*)&ct;
        ct_bytes[0] = fuse_inline_enc_8(pt_bytes[0]);
        ct_bytes[1] = fuse_inline_enc_8(pt_bytes[1]);
        ct_bytes[2] = fuse_inline_enc_8(pt_bytes[2]);
        ct_bytes[3] = fuse_inline_enc_8(pt_bytes[3]);
        return ct;
    }

    uint64_t fuse_inline_enc_64(uint64_t pt) {
        if (!g_fuse_active) return pt;
        uint32_t* pt_words = (uint32_t*)&pt;
        uint64_t ct;
        uint32_t* ct_words = (uint32_t*)&ct;
        ct_words[0] = fuse_inline_enc_32(pt_words[0]);
        ct_words[1] = fuse_inline_enc_32(pt_words[1]);
        return ct;
    }

    __attribute__((noinline, used))
    void fuse_inline_enc_memcpy(uint8_t* dest, const uint8_t* src, size_t len) {
        asm volatile("" ::: "memory");
        bool auto_ignited = false;

        // 💡 [TX 수정] 로컬 변수에 내가 쓸 IV를 저장해 둡니다.
        uint64_t my_tx_iv = 0;

        if (!g_fuse_active) {
            if (g_zero_copy_ctx.is_ready.load(std::memory_order_acquire)) {
                
                uint64_t* iv_counter = reinterpret_cast<uint64_t*>(g_zero_copy_ctx.initialization_vector.data() + 4);
                my_tx_iv = __atomic_fetch_add(iv_counter, 1, __ATOMIC_SEQ_CST);
// __atomic_fetch_add를 쓰면 CPU 칩이 하드웨어 락을 걸어 타 코어의 접근을 막아선 채로 "번호표 기계에서 번호표 하나를 쏙 뽑아오고 + 기계의 숫자를 1 올리는" 행위를 단 1나노초 만에 완벽히 독점 처리해 줍니다.
//  덕분에 스레드들이 아무리 동시에 몰려와도 단 1개의 IV 번호도 겹치지 않고 안전하게 유일성을 보장받습니다.

// __ATOMIC_SEQ_CST는 바로 그 순차적 일관성(Sequential Consistency) 옵션
// 모든 스레드가 완전히 일치하는 단 하나의 전역 타임라인을 공유하는 중앙 방송

Q. 면접관의 공격: "다중 스레드가 동시에 fuse_inline_enc_memcpy를 호출할 때 IV 카운터를 올리는데, 여기서 __atomic_fetch_add와 __ATOMIC_SEQ_CST를 쓴 이유는 무엇입니까? 연산 비용이 크지 않나요?"

A.
"__atomic_fetch_add와 __ATOMIC_SEQ_CST는 AES-GCM 암호학의 핵심인 IV 유일성을 하드웨어 레벨에서 비용 효율적으로 달성하기 위한 도구입니다.
멀티스레드가 동시에 송신 패스를 밟을 때, 일반적인 카운터 연산은 레이스 컨디션으로 인해 IV가 중복되는 치명적인 아키텍처 파멸을 유발할 수 있습니다. 
이를 막기 위해 컴파일러 내장 함수인 **__atomic_fetch_add**를 사용하여, 단 하나의 CPU 트랜잭션 사이클 내에서 고유 번호표를 안정적으로 가로채도록 구현했습니다.
면접관님 말씀대로 __ATOMIC_SEQ_CST 일관성 모델은 전역 메모리 펜스를 유발하므로 런타임 비용이 발생합니다.
하지만 암호학 구조상 IV의 재사용은 무조건 차단되어야 하는 절대적 제약조건입니다. 수천 나노초의 지연과 컨텍스트 스위칭을 유발하는 무거운 Mutex 동기화에 비하면, 
수십 나노초 이하로 하드웨어 버스 단에서 카운터 순서를 강력히 일치시키는 아토믹 펜스 방식이 고성능 실시간 미들웨어 환경에서 최선이자 유일한 선택이라고 판단하여 의도적으로 설계했습니다."

Q. 왜 __ATOMIC_SEQ_CST가 TX 내부에서 필요할까?
A. TX 프로세스 '내부'의 멀티스레드 환경입니다. TX 프로세스 안에는 수많은 스레드가 동시에 fuse_inline_enc_memcpy를 호출하며 동작합니다.
상황 A (다중 토픽 발행): 하나의 로봇 프로세스 안에서 레이저 센서(LiDAR) 데이터를 발행하는 스레드와, 카메라 영상을 발행하는 스레드가 서로 다른 코어에서 동시에 write() 명령을 내릴 수 있습니다. 
이 스레드들은 각각 독립적으로 직렬화 루프를 타게 되므로, 동일한 시간에 fuse_inline_enc_memcpy 함수로 동시에 진입합니다.
'TX 프로세스 내부 멀티스레드 간의 물리적 명령어 실행 순서(Total Store Ordering)'를 수호하기 위함입니다.
고속 병렬 환경에서 다중 스레드가 동시에 카운터를 가로챌 때, 원자적으로 번호표를 뽑는 행위와 실제 대용량 페이로드를 암호화하여 SHM에 복사하고 IV를 마킹하는 행위 간의 '컴파일러 및 CPU 런타임 재정렬(Reordering)'이 발생할 수 있습니다.
만약 느슨한 메모리 모델을 사용하면 번호표를 뽑은 순서와 SHM에 데이터가 최종 커밋되는 순서가 하드웨어 단에서 역전되어 암호학적 무결성이 깨집니다. 
따라서 프로세스 간 간섭 때문이 아니라, 단일 프로세스 내부의 다중 스레드가 하드웨어 병렬성 속에서도 완벽히 일렬로 정렬된 타임라인(Single Total Order)을 따라 암호문을 융합하도록 강제하기 위해 __ATOMIC_SEQ_CST를 의도적으로 설계했습니다.

                // 동시성 문제를 막기 위해 임시 배열에 IV를 조립합니다.
                uint8_t temp_iv[12] = {0};
                memcpy(temp_iv, g_zero_copy_ctx.initialization_vector.data(), 4); // force_sync_id 4바이트
                memcpy(temp_iv + 4, &my_tx_iv, 8); // 내가 딴 카운터 8바이트
                
                fuse_init(g_zero_copy_ctx.precomputed_session_key.data(), temp_iv);
                auto_ignited = true;
            } else {
                memcpy(dest, src, len);
                asm volatile("" ::: "memory");
                return;
            }
        }

        size_t offset = 0;

        if (tx_gmac_pos == 0 && tx_ks_pos == 128) {
            while (offset + 128 <= len) {
                g_crypto_engine.process_128bytes_fused_arm(src + offset, dest + offset);
                offset += 128;
                tl_payload_len += 128;
            }
            while (offset + 64 <= len) {
                g_crypto_engine.process_64bytes_fused(src + offset, dest + offset);
                offset += 64;
                tl_payload_len += 64;
            }
            while (offset + 16 <= len) {
                g_crypto_engine.process_16bytes_fused(src + offset, dest + offset);
                offset += 16;
                tl_payload_len += 16;
            }
        }
        
        size_t tail_len = len - offset;
        if (tail_len > 0) {
            g_crypto_engine.process_tail_fused(src + offset, dest + offset, tail_len);
            tl_payload_len += tail_len;
        }

        if (auto_ignited) {
            // 💡 [수정] 허공에 버리던 dummy_tag를 지우고, 
            // SHM 목적지(dest)의 암호문 데이터가 끝나는 바로 다음 위치에 진짜 MAC을 기록합니다!
            uint8_t* mac_dest_ptr = dest + len;
            fuse_finalize_enc(mac_dest_ptr); 

            // 💡 [핵심 추가] MAC(16바이트) 바로 뒤에 내가 쓴 IV 카운터(8바이트)를 명시적으로 기록!
            memcpy(dest + len + 16, &my_tx_iv, sizeof(uint64_t));
        }

        asm volatile("" ::: "memory");
    }
    
    void fuse_finalize_enc(uint8_t* out_tag) {
        size_t processed = 0;
        while (processed < tx_gmac_pos) {
            size_t chunk = (tx_gmac_pos - processed >= 16) ? 16 : (tx_gmac_pos - processed);
            if (chunk < 16) memset(tx_gmac_buf + processed + chunk, 0, 16 - chunk);
            g_crypto_engine.accumulate_gmac(tx_gmac_buf + processed);
            processed += 16;
        }
        g_crypto_engine.finalize(tl_aad_len, tl_payload_len, out_tag);
        g_fuse_active = false;
    }
}

extern "C" {
    // =========================================================================
    // 🛡️ [수신부 상태 버퍼] 복호화를 위한 독립적인 RX 버퍼 할당
    // =========================================================================
    __attribute__((visibility("default"), aligned(16))) uint8_t rx_keystream_buf[128] = {0}; 
    __attribute__((visibility("default"), aligned(16))) uint8_t rx_gmac_buf[128] = {0};      
    __attribute__((visibility("default"))) uint8_t rx_ks_pos = 128;   
    __attribute__((visibility("default"))) uint8_t rx_gmac_pos = 0;
}

// 수신부용 Keystream 생성 헬퍼
inline __attribute__((always_inline)) void rx_generate_keystream() {
    g_crypto_engine.generate_keystream_128bytes_arm(rx_keystream_buf); 
    rx_ks_pos = 0;
}

extern "C" {

    // AAD(추가 인증 데이터) 처리는 암호화/복호화가 동일하므로 래퍼만 제공
    void fuse_update_dec(const uint8_t* src, size_t len) {
        fuse_update_enc(src, nullptr, len);
    }

    // =========================================================================
    // ⚡ [인라인 복호화 훅] 암호문(CT)을 먼저 GMAC에 누적하고 PT를 반환
    // =========================================================================
    uint8_t fuse_inline_dec_8(uint8_t ct) {
        if (!g_fuse_active) return ct;
        if (rx_ks_pos == 128) rx_generate_keystream();
        
        // 🚀 중요: GCM 복호화는 들어온 암호문(CT)을 그대로 누적해야 함
        rx_gmac_buf[rx_gmac_pos++] = ct;
        if (rx_gmac_pos == 128) {
             for(int i=0; i<8; i++) g_crypto_engine.accumulate_gmac(rx_gmac_buf + i*16);
             rx_gmac_pos = 0;
        }
        
        // 누적 후 Keystream과 XOR하여 평문(PT) 도출
        uint8_t pt = ct ^ rx_keystream_buf[rx_ks_pos++];
        tl_payload_len += 1;
        return pt;
    }

    uint16_t fuse_inline_dec_16(uint16_t ct) {
        if (!g_fuse_active) return ct;
        uint8_t* ct_bytes = (uint8_t*)&ct;
        uint16_t pt;
        uint8_t* pt_bytes = (uint8_t*)&pt;
        pt_bytes[0] = fuse_inline_dec_8(ct_bytes[0]);
        pt_bytes[1] = fuse_inline_dec_8(ct_bytes[1]);
        return pt;
    }

    uint32_t fuse_inline_dec_32(uint32_t ct) {
        if (!g_fuse_active) return ct;
        uint8_t* ct_bytes = (uint8_t*)&ct;
        uint32_t pt;
        uint8_t* pt_bytes = (uint8_t*)&pt;
        pt_bytes[0] = fuse_inline_dec_8(ct_bytes[0]);
        pt_bytes[1] = fuse_inline_dec_8(ct_bytes[1]);
        pt_bytes[2] = fuse_inline_dec_8(ct_bytes[2]);
        pt_bytes[3] = fuse_inline_dec_8(ct_bytes[3]);
        return pt;
    }

    uint64_t fuse_inline_dec_64(uint64_t ct) {
        if (!g_fuse_active) return ct;
        uint32_t* ct_words = (uint32_t*)&ct;
        uint64_t pt;
        uint32_t* pt_words = (uint32_t*)&pt;
        pt_words[0] = fuse_inline_dec_32(ct_words[0]);
        pt_words[1] = fuse_inline_dec_32(ct_words[1]);
        return pt;
    }

    // =========================================================================
    // 📦 [대용량 데이터 복호화 훅] Thunk Payload 및 가변 데이터 처리
    // =========================================================================
    // =====================================================================
    // 🛡️ [수신부(RX) 융합] SHM -> 로컬 메모리 복호화 함수
    // =====================================================================
    extern "C" __attribute__((noinline, used))
    void fuse_inline_dec_memcpy(uint8_t* dest, const uint8_t* src, size_t len) {
        
        asm volatile("" ::: "memory");
        bool auto_ignited = false;

        if (!g_fuse_active) {
            // 💡 진짜 키가 아직 오지 않았다면? (비동기 처리)
            if (g_zero_copy_ctx.is_ready.load(std::memory_order_acquire)) {
                
                // 💡 [RX 핵심 수정] 내가 혼자 카운터를 올리지 말고, 
                // SHM 꼬리(len + 16바이트 위치)에 TX가 적어둔 IV 번호를 그대로 훔쳐옵니다!
                uint64_t rx_explicit_iv = 0;
                memcpy(&rx_explicit_iv, src + len + 16, sizeof(uint64_t));

                uint8_t temp_iv[12] = {0};
                memcpy(temp_iv, g_zero_copy_ctx.initialization_vector.data(), 4);
                memcpy(temp_iv + 4, &rx_explicit_iv, 8); // TX와 완벽하게 동일한 IV 세팅!
                
                fuse_init(g_zero_copy_ctx.precomputed_session_key.data(), temp_iv);
                auto_ignited = true;
            } else {
                // 🚀 비동기 딜레마 완벽 극복! 키가 올 때까지 초기 1~2 프레임은 0으로 채워서 버립니다. (Drop)
                static bool wait_msg = false; //static 붙이면 초기화 X, 사는 곳: 데이터(Data/BSS) 영역 (전역 변수들과 같은 방)
                // 이 변수는 프로그램이 구동(실행)되기도 전에, 빌드된 바이너리 파일이 메모리에 로드되는 순간 이미 딱 한 번 메모리 공간을 확보하고 초기화까지 끝마칩니다.
                // 함수가 실행되면서 이 변수를 만났을 때, 컴파일러는 초기화 코드를 실행하는 게 아니라 "아, 이건 저기 데이터 영역에 이미 보관돼 있는 녀석이니까 그냥 저기서 꺼내 쓰기만 해" 하고 지나칩니다.
                if (!wait_msg) {
                    printf("\n[DEBUG RX]  Waiting Asynchronous Key exchange \n\n");
                    wait_msg = true;
                }
                memset(dest, 0, len); // 쓰레기 값 방지
// Q. 그냥 else 블록 지우고 빈 리턴 쳐도 어차피 작동할 텐데 굳이 memset을 고집한 이유가 뭡니까?"*라고 유도 신문을 던진다면 이렇게 받아치십시오.
// A. "프로그래밍 문법상으로는 빈 리턴이 가능하지만, 메모리 오염 및 제어 오작동을 방지하기 위한 보안 및 안전 설계(Fail-Safe) 관점에서 memset은 필수적입니다.
// 힙(Heap) 공간이나 재사용 버퍼에서 할당받은 dest 메모리 주소에는 이전 공정에서 쓰이던 **물리적 쓰레기 데이터(Garbage Value)**가 그대로 남아있습니다.
// 초기 비동기 세션 확립 도중 키가 도달하지 않았다고 해서 그냥 리턴을 해버리면, 상위 애플리케이션 계층은 아무런 데이터도 쓰이지 않은 쓰레기 잔여 데이터를 신뢰성 있는 평문으로 오인하여 파싱하는 치명적인 제어 유실(Control Loss) 리스크를 안게 됩니다.
// 따라서 극초기 1~2 프레임의 데이터 드롭 페널티를 감수하더라도, 버퍼 전역을 원자적 상태인 0 (Null Payload)으로 강제 초기화(Zeroing) 함으로써 상위 소프트웨어가 예측 가능한 안전 상태(Safe-state)를 유지하도록 철저하게 방어적 설계를 적용했습니다."
                asm volatile("" ::: "memory");
                return;
            }
        }

        size_t offset = 0;

        // =====================================================================
        // 🚀 [NEON 폭발] 업데이트된 128바이트 다이렉트 복호화 가속!
        // =====================================================================
        if (tx_gmac_pos == 0 && tx_ks_pos == 128) {
            // 1. 128바이트 단위 초고속 복호화 (새로 추가하신 함수 적용!)
            while (offset + 128 <= len) {
                g_crypto_engine.decrypt_128bytes_fused_arm(src + offset, dest + offset);
                offset += 128;
                tl_payload_len += 128;
            }
            // 2. 64바이트 단위 복호화
            while (offset + 64 <= len) {
                g_crypto_engine.decrypt_64bytes_fused(src + offset, dest + offset);
                offset += 64;
                tl_payload_len += 64;
            }
            // 3. 16바이트 단위 복호화
            while (offset + 16 <= len) {
                g_crypto_engine.decrypt_16bytes_fused(src + offset, dest + offset);
                offset += 16;
                tl_payload_len += 16;
            }
        }
        
        // =====================================================================
        // 🐢 [Tail 블록] 남은 찌꺼기 처리
        // =====================================================================
        size_t tail_len = len - offset;
        if (tail_len > 0) {
            g_crypto_engine.decrypt_tail_fused(src + offset, dest + offset, tail_len);
            tl_payload_len += tail_len;
        }

        // =====================================================================
        // 🧹 [엔진 정리 및 MAC 무결성 검증] 
        // =====================================================================
        if (auto_ignited) {
            // 💡 1. SHM 암호문 바로 뒤(src + len)에 위치한 16바이트 MAC 태그를 가리킵니다.
            const uint8_t* expected_mac_ptr = src + len;
            
            // 💡 2. AES-GCM 엔진에게 복호화한 데이터가 이 태그와 일치하는지 검증을 지시합니다!
            bool is_mac_valid = fuse_verify_dec(expected_mac_ptr);

            if (!is_mac_valid) {
                // 🚨 3. [해킹 방어] MAC 검증 실패! (데이터가 변조되었거나 키가 다름)
                printf("\n[ERROR RX]  Fail to verify MAC \n\n");
                // 로컬 애플리케이션이 변조된 쓰레기 값을 쓰지 못하도록 메모리를 0으로 초기화
                memset(dest, 0, len); 
            } 
        }

        asm volatile("" ::: "memory");
    }
    
    // =========================================================================
    // ✅ [태그 검증] 수신된 암호문의 무결성 최종 확인
    // =========================================================================
    bool fuse_verify_dec(const uint8_t* expected_tag) {
        size_t processed = 0;
        
        // 잔여 버퍼에 남아있는 암호문 찌꺼기 GHASH 누적
        while (processed < rx_gmac_pos) {
            size_t chunk = (rx_gmac_pos - processed >= 16) ? 16 : (rx_gmac_pos - processed);
            if (chunk < 16) memset(rx_gmac_buf + processed + chunk, 0, 16 - chunk);
            g_crypto_engine.accumulate_gmac(rx_gmac_buf + processed);
            processed += 16;
        }
        
        bool is_valid = g_crypto_engine.verify_tag(tl_aad_len, tl_payload_len, expected_tag);
        
        g_fuse_active = false;
        return is_valid;
    }
}

면접관의 공격: "수신 측에서 복호화를 진행한 뒤에 마지막에 가서야 MAC 검증을 하고 실패 시 memset으로 밀어버리는데, 이것은 데이터 파싱 전에 무결성을 먼저 검증하라는 'Cryptographic Doom Principle'에 위배되는 것 아닙니까? 
복호화 도중 해커가 주입한 데이터가 애플리케이션에 유출될 리스크는 없습니까?"

🏆 합격을 부르는 답변 스크립트:
"날카로운 지적이십니다. 정석적인 보안 원칙(Encrypt-then-MAC)에 따르면 암호문 상태에서 복호화 전에 MAC을 먼저 검증해야 합니다. 하지만 저희 시스템은 Zero-Copy 공유 메모리(SHM) 환경입니다.
만약 SHM 버퍼에 대용량 데이터가 들어있을 때, 무결성을 먼저 검증하고(Pass 1) 다시 메모리를 읽어 복호화(Pass 2)를 수행하면 메모리 대역폭을 이중으로 낭비하여 L1/L2 캐시 오염과 레이턴시 폭발이 발생합니다.
따라서 성능 극대화를 위해 메모리 복사와 복호화, 그리고 GHASH 누적 연산을 ARM NEON 단일 루프 내에서 처리하는 Asymmetric 파이프라인을 설계했습니다. 대신 데이터가 로컬 애플리케이션 계층으로 최종 반환되기 전, 
루프 직후에 fuse_verify_dec를 통해 무결성을 즉시 검증하고 실패 시 memset으로 메모리를 무효화하여 상위 애플리케이션이 변조된 쓰레기 값을 참조하는 것을 원천 차단함으로써 성능과 보안의 타협점을 정밀하게 제어했습니다."