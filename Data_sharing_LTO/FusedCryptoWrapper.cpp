#include "FusedCryptoPayload.h"
#include <string.h>
#include <stdio.h> 
#include <array>
#include <atomic> // 💡 Mutex 대신 Atomic을 사용하여 0ns 오버헤드 달성

extern "C" {
    __attribute__((visibility("default"))) FusedCryptoPayload g_crypto_engine;
    __attribute__((visibility("default"))) size_t tl_aad_len = 0;
    __attribute__((visibility("default"))) size_t tl_payload_len = 0;
    __attribute__((visibility("default"))) bool g_fuse_active = false;
    __attribute__((visibility("default"), aligned(16))) uint8_t tx_keystream_buf[128] = {0}; 
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
                static bool wait_msg = false;
                if (!wait_msg) {
                    printf("\n[DEBUG RX]  Waiting Asynchronous Key exchange \n\n");
                    wait_msg = true;
                }
                memset(dest, 0, len); // 쓰레기 값 방지
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