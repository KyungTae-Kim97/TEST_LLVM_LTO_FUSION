#include "FusedCryptoPayload.h"
#include <string.h>
#include <stdio.h> 

// =========================================================================
// 🚨 [핵심 수정] thread_local을 전부 제거하고, 가시성(visibility)을 default로 강제 설정하여 
// 플러그인(dlopen) 경계에서도 OS가 동일한 메모리로 강제 병합(Merge)하게 만듭니다.
// ========================================================================= why thread_local not be used in .so ??

extern "C" {
    __attribute__((visibility("default"))) FusedCryptoPayload g_crypto_engine;
    __attribute__((visibility("default"))) size_t tl_aad_len = 0;
    __attribute__((visibility("default"))) size_t tl_payload_len = 0;

    // 💡 [핵심 스위치] 두 세계를 하나로 연결할 유일한 전역 스위치
    __attribute__((visibility("default"))) bool g_fuse_active = false;

    // 🚨 [수정됨] alignas(16)을 제거하고, attribute 내부에 aligned(16)을 추가하여 병합
    __attribute__((visibility("default"), aligned(16))) uint8_t tx_keystream_buf[128] = {0}; 
    __attribute__((visibility("default"), aligned(16))) uint8_t tx_gmac_buf[128] = {0};      
    
    __attribute__((visibility("default"))) uint8_t tx_ks_pos = 128;   
    __attribute__((visibility("default"))) uint8_t tx_gmac_pos = 0;
}

extern "C" {
    __attribute__((visibility("default"))) void* tls_zero_copy_raw_data = nullptr;
    __attribute__((visibility("default"))) uint32_t tls_zero_copy_real_size = 0;
    __attribute__((visibility("default"))) void* tls_zero_copy_func_ptr = nullptr;
}


// =========================================================================
// 내부 헬퍼 함수
// =========================================================================
inline __attribute__((always_inline)) void tx_generate_keystream() {
    // ARM 최적화 헤더에 맞춰 128바이트 키스트림 생성 전용 함수를 단독 호출합니다.
    g_crypto_engine.generate_keystream_128bytes_arm(tx_keystream_buf); 
    tx_ks_pos = 0; // 버퍼를 다 채웠으므로 인덱스 초기화
}

extern "C" {
    // =====================================================================
    // 공통 초기화
    // =====================================================================
    void fuse_init(const uint8_t* key, const uint8_t* iv) {
        g_crypto_engine.init(key, iv);
        tl_aad_len = 0;
        tl_payload_len = 0;
        
        // TX 스트리밍 상태 초기화
        tx_ks_pos = 128; 
        tx_gmac_pos = 0;

        // 💡 SROS2 보안 헤더 직렬화가 끝난 후 이 함수가 호출되므로,
        // 이제부터 LTO 인라인 암호화를 활성화합니다!
        g_fuse_active = true;
    }

    // =====================================================================
    // 플러그인 레벨의 벌크(Bulk) 암호화 (TX Fallback / AAD용)
    // =====================================================================
    void fuse_update_enc(const uint8_t* src, uint8_t* dest, size_t len) {
        // dest가 nullptr이 아니라는 것은 Security 플러그인이 페이로드를 넘겼다는 뜻!
        // 하지만 우리는 LTO로 이미 직렬화 단계에서 암호화를 끝냈으므로 방어 코드로 조기 종료합니다.
        if (dest != nullptr) {
            return; // 이중 암호화 방지
        }

        // dest == nullptr 일 때 (즉, AAD가 들어왔을 때만) GHASH 처리
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

    // =====================================================================
    // LLVM LTO 주입 전용 - 인라인(Inline) 스트리밍 암호화 인터페이스
    // =====================================================================
    
    // 8비트 (1바이트) 인라인 암호화
    uint8_t fuse_inline_enc_8(uint8_t pt) {
        if (!g_fuse_active) return pt;

        // 분기 예측(Branch Prediction) 관점에서 CPU가 if문을 무시할 확률 극대화
        if (tx_ks_pos == 128) tx_generate_keystream();

        uint8_t ct = pt ^ tx_keystream_buf[tx_ks_pos++];
        tx_gmac_buf[tx_gmac_pos++] = ct;
        
        // GMAC은 16바이트(1블록)가 찰 때마다 해시 누적
        if (tx_gmac_pos == 128) {
             for(int i=0; i<8; i++){
                 g_crypto_engine.accumulate_gmac(tx_gmac_buf + i*16);
             }
             tx_gmac_pos = 0;
        }

        tl_payload_len += 1;
        return ct;
    }

    // 16비트 (2바이트) 인라인 암호화
    uint16_t fuse_inline_enc_16(uint16_t pt) {
        if (!g_fuse_active) return pt;

        uint8_t* pt_bytes = (uint8_t*)&pt;
        uint16_t ct;
        uint8_t* ct_bytes = (uint8_t*)&ct;
        
        ct_bytes[0] = fuse_inline_enc_8(pt_bytes[0]);
        ct_bytes[1] = fuse_inline_enc_8(pt_bytes[1]);
        return ct;
    }

    // 32비트 (4바이트) 인라인 암호화
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

    // 64비트 (8바이트) 인라인 암호화
    uint64_t fuse_inline_enc_64(uint64_t pt) {
        if (!g_fuse_active) return pt;

        uint32_t* pt_words = (uint32_t*)&pt;
        uint64_t ct;
        uint32_t* ct_words = (uint32_t*)&ct;
        
        ct_words[0] = fuse_inline_enc_32(pt_words[0]);
        ct_words[1] = fuse_inline_enc_32(pt_words[1]);
        return ct;
    }

    // =====================================================================
    // 문자열, 배열 등의 MemCpy 대체를 위한 인라인 암호화 함수
    // =====================================================================
    // 🚨 [핵심 수정 1] C 이름 맹글링 방지 및 최적화 강제 금지 속성 부여
    extern "C" __attribute__((noinline, used))
    void fuse_inline_enc_memcpy(uint8_t* dest, const uint8_t* src, size_t len) {
        
        asm volatile("" ::: "memory");
        
        if (!g_fuse_active) {
            memcpy(dest, src, len);
            asm volatile("" ::: "memory");
            return;
        }

        size_t offset = 0;

        // =====================================================================
        // 🚀 [NEON 폭발] 가짜 헤더 주입 완전 삭제! 순수 원본 100% 다이렉트 가속!
        // 목적지(dest) 오프셋 밀림 현상도 없으므로, src와 dest가 동일 선상에서 1:1 매칭됩니다.
        // =====================================================================
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
        
        // =====================================================================
        // 🐢 [Tail 블록] 남은 찌꺼기 처리
        // =====================================================================
        size_t tail_len = len - offset;
        if (tail_len > 0) {
            g_crypto_engine.process_tail_fused(src + offset, dest + offset, tail_len);
            tl_payload_len += tail_len;
        }

        asm volatile("" ::: "memory");
    }
    
    // =====================================================================
    // 태그 최종 생성 (TX 전용)
    // =====================================================================
    void fuse_finalize_enc(uint8_t* out_tag) {
        // 128바이트 버퍼에 남아있는 모든 데이터를 16바이트 단위로 쪼개서 해시 처리
        size_t processed = 0;
        while (processed < tx_gmac_pos) {
            size_t chunk = (tx_gmac_pos - processed >= 16) ? 16 : (tx_gmac_pos - processed);
            
            if (chunk < 16) {
                memset(tx_gmac_buf + processed + chunk, 0, 16 - chunk);
            }
            g_crypto_engine.accumulate_gmac(tx_gmac_buf + processed);
            processed += 16;
        }
        
        g_crypto_engine.finalize(tl_aad_len, tl_payload_len, out_tag);
        g_fuse_active = false;
    }
}