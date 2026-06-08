#ifndef FUSED_CRYPTO_PAYLOAD_ARM_H
#define FUSED_CRYPTO_PAYLOAD_ARM_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <arm_neon.h>

class FusedCryptoPayload {
private:
    uint8_t cached_key[32] = {0};
    bool is_key_cached = false;

    uint8x16_t ctr_block;
    
    // 🚀 미리 비트 반전(Bit-Reflected)된 해시 키들을 저장
    uint8x16_t hash_key;
    uint8x16_t hash_key2;
    uint8x16_t hash_key3;
    uint8x16_t hash_key4;
    uint8x16_t hash_key5;
    uint8x16_t hash_key6;
    uint8x16_t hash_key7;
    uint8x16_t hash_key8;

    uint8x16_t current_hash;
    uint8x16_t round_keys[15]; 
    uint8x16_t tag_mask;

    #define INC_ARM_CTR32(c, val) \
        ([&]() -> uint8x16_t { \
            uint32x4_t ctr32 = vreinterpretq_u32_u8(vrev32q_u8(c)); \
            ctr32 = vsetq_lane_u32(vgetq_lane_u32(ctr32, 3) + val, ctr32, 3); \
            return vrev32q_u8(vreinterpretq_u8_u32(ctr32)); \
        }())
    
    // ====================================================================
    // 🚀 [최적화 1] 초기화 시 거듭제곱을 구하기 위한 내부 GF 곱셈 (양방향 반전)
    // ====================================================================
    inline __attribute__((always_inline)) uint8x16_t gf_mul_internal(uint8x16_t a, uint8x16_t b) {
        uint8x16_t rA = vrbitq_u8(a);
        uint8x16_t rB = vrbitq_u8(b);

        poly64_t a_lo = vgetq_lane_p64(vreinterpretq_p64_u8(rA), 0);
        poly64_t a_hi = vgetq_lane_p64(vreinterpretq_p64_u8(rA), 1);
        poly64_t b_lo = vgetq_lane_p64(vreinterpretq_p64_u8(rB), 0);
        poly64_t b_hi = vgetq_lane_p64(vreinterpretq_p64_u8(rB), 1);

        poly128_t p0 = vmull_p64(a_lo, b_lo);
        poly128_t p1 = vmull_p64(a_hi, b_hi);
        poly128_t p2 = vmull_p64((poly64_t)((uint64_t)a_lo ^ (uint64_t)a_hi),
                                 (poly64_t)((uint64_t)b_lo ^ (uint64_t)b_hi));

        uint64x2_t c0 = vreinterpretq_u64_p128(p0);
        uint64x2_t c1 = vreinterpretq_u64_p128(p1);
        uint64x2_t c2 = vreinterpretq_u64_p128(p2);

        c2 = veorq_u64(c2, c0);
        c2 = veorq_u64(c2, c1);

        uint64_t z0 = vgetq_lane_u64(c0, 0);
        uint64_t z1 = vgetq_lane_u64(c0, 1) ^ vgetq_lane_u64(c2, 0);
        uint64_t z2 = vgetq_lane_u64(c1, 0) ^ vgetq_lane_u64(c2, 1);
        uint64_t z3 = vgetq_lane_u64(c1, 1);

        z1 ^= z3 ^ (z3 << 1) ^ (z3 << 2) ^ (z3 << 7);
        z2 ^= (z3 >> 63) ^ (z3 >> 62) ^ (z3 >> 57);

        z0 ^= z2 ^ (z2 << 1) ^ (z2 << 2) ^ (z2 << 7);
        z1 ^= (z2 >> 63) ^ (z2 >> 62) ^ (z2 >> 57);

        uint64x2_t res = vcombine_u64(vcreate_u64(z0), vcreate_u64(z1));
        return vrbitq_u8(vreinterpretq_u8_u64(res));
    }

    // ====================================================================
    // 🚀 [최적화 2] 런타임용 GF 곱셈 (h_rev는 캐싱된 반전 형태를 그대로 사용)
    // ====================================================================
    inline __attribute__((always_inline)) uint8x16_t gf_mul_arm(uint8x16_t a, uint8x16_t h_rev) {
        uint8x16_t rA = vrbitq_u8(a);
        
        poly64_t a_lo = vgetq_lane_p64(vreinterpretq_p64_u8(rA), 0);
        poly64_t a_hi = vgetq_lane_p64(vreinterpretq_p64_u8(rA), 1);
        poly64_t b_lo = vgetq_lane_p64(vreinterpretq_p64_u8(h_rev), 0); // 반전 생략
        poly64_t b_hi = vgetq_lane_p64(vreinterpretq_p64_u8(h_rev), 1); // 반전 생략

        poly128_t p0 = vmull_p64(a_lo, b_lo);
        poly128_t p1 = vmull_p64(a_hi, b_hi);
        poly128_t p2 = vmull_p64((poly64_t)((uint64_t)a_lo ^ (uint64_t)a_hi),
                                 (poly64_t)((uint64_t)b_lo ^ (uint64_t)b_hi));

        uint64x2_t c0 = vreinterpretq_u64_p128(p0);
        uint64x2_t c1 = vreinterpretq_u64_p128(p1);
        uint64x2_t c2 = vreinterpretq_u64_p128(p2);

        c2 = veorq_u64(c2, c0);
        c2 = veorq_u64(c2, c1);

        uint64_t z0 = vgetq_lane_u64(c0, 0);
        uint64_t z1 = vgetq_lane_u64(c0, 1) ^ vgetq_lane_u64(c2, 0);
        uint64_t z2 = vgetq_lane_u64(c1, 0) ^ vgetq_lane_u64(c2, 1);
        uint64_t z3 = vgetq_lane_u64(c1, 1);

        z1 ^= z3 ^ (z3 << 1) ^ (z3 << 2) ^ (z3 << 7);
        z2 ^= (z3 >> 63) ^ (z3 >> 62) ^ (z3 >> 57);

        z0 ^= z2 ^ (z2 << 1) ^ (z2 << 2) ^ (z2 << 7);
        z1 ^= (z2 >> 63) ^ (z2 >> 62) ^ (z2 >> 57);

        uint64x2_t res = vcombine_u64(vcreate_u64(z0), vcreate_u64(z1));
        return vrbitq_u8(vreinterpretq_u8_u64(res));
    }

    // ====================================================================
    // 🚀 [최적화 3] 레지스터 즉시 누적 (구조체 및 스택 메모리 낭비 제거)
    // ====================================================================
    #define PMULL_ACCUMULATE_STD(A, H_rev, sum_lo, sum_hi, sum_mid) { \
        uint8x16_t rA = vrbitq_u8(A); \
        poly64_t a0 = vgetq_lane_p64(vreinterpretq_p64_u8(rA), 0); \
        poly64_t a1 = vgetq_lane_p64(vreinterpretq_p64_u8(rA), 1); \
        poly64_t b0 = vgetq_lane_p64(vreinterpretq_p64_u8(H_rev), 0); \
        poly64_t b1 = vgetq_lane_p64(vreinterpretq_p64_u8(H_rev), 1); \
        \
        sum_lo = veorq_u64(sum_lo, vreinterpretq_u64_p128(vmull_p64(a0, b0))); \
        sum_hi = veorq_u64(sum_hi, vreinterpretq_u64_p128(vmull_p64(a1, b1))); \
        sum_mid = veorq_u64(sum_mid, vreinterpretq_u64_p128(vmull_p64( \
            (poly64_t)((uint64_t)a0 ^ (uint64_t)a1), \
            (poly64_t)((uint64_t)b0 ^ (uint64_t)b1)))); \
    }

    inline __attribute__((always_inline)) uint8x16_t aes256_encrypt_arm(uint8x16_t in) {
        uint8x16_t v = vaeseq_u8(in, round_keys[0]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[1]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[2]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[3]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[4]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[5]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[6]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[7]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[8]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[9]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[10]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[11]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[12]); v = vaesmcq_u8(v);
        v = vaeseq_u8(v, round_keys[13]);
        return veorq_u8(v, round_keys[14]);
    }

    inline __attribute__((always_inline)) void increment_counter_arm() {
        uint32x4_t ctr32 = vreinterpretq_u32_u8(vrev32q_u8(ctr_block));
        ctr32 = vsetq_lane_u32(vgetq_lane_u32(ctr32, 3) + 1, ctr32, 3);
        ctr_block = vrev32q_u8(vreinterpretq_u8_u32(ctr32));
    }

public:
    inline __attribute__((always_inline)) void generate_keystream(uint8_t* out_ks) {
        uint8x16_t ks = aes256_encrypt_arm(ctr_block);
        vst1q_u8(out_ks, ks);
        increment_counter_arm(); 
    }

    inline __attribute__((always_inline)) void generate_keystream_128bytes_arm(uint8_t* out_ks) {
        uint8x16_t ctr0 = ctr_block;
        uint8x16_t ctr1 = INC_ARM_CTR32(ctr0, 1);
        uint8x16_t ctr2 = INC_ARM_CTR32(ctr0, 2);
        uint8x16_t ctr3 = INC_ARM_CTR32(ctr0, 3);
        uint8x16_t ctr4 = INC_ARM_CTR32(ctr0, 4);
        uint8x16_t ctr5 = INC_ARM_CTR32(ctr0, 5);
        uint8x16_t ctr6 = INC_ARM_CTR32(ctr0, 6);
        uint8x16_t ctr7 = INC_ARM_CTR32(ctr0, 7);
        ctr_block = INC_ARM_CTR32(ctr0, 8); 

        uint8x16_t k = round_keys[0];
        uint8x16_t v0 = vaeseq_u8(ctr0, k); uint8x16_t v1 = vaeseq_u8(ctr1, k);
        uint8x16_t v2 = vaeseq_u8(ctr2, k); uint8x16_t v3 = vaeseq_u8(ctr3, k);
        uint8x16_t v4 = vaeseq_u8(ctr4, k); uint8x16_t v5 = vaeseq_u8(ctr5, k);
        uint8x16_t v6 = vaeseq_u8(ctr6, k); uint8x16_t v7 = vaeseq_u8(ctr7, k);

        #define AES_ROUND_8X_KS_ARM(idx) \
            v0 = vaesmcq_u8(v0); v1 = vaesmcq_u8(v1); v2 = vaesmcq_u8(v2); v3 = vaesmcq_u8(v3); \
            v4 = vaesmcq_u8(v4); v5 = vaesmcq_u8(v5); v6 = vaesmcq_u8(v6); v7 = vaesmcq_u8(v7); \
            k = round_keys[idx]; \
            v0 = vaeseq_u8(v0, k); v1 = vaeseq_u8(v1, k); v2 = vaeseq_u8(v2, k); v3 = vaeseq_u8(v3, k); \
            v4 = vaeseq_u8(v4, k); v5 = vaeseq_u8(v5, k); v6 = vaeseq_u8(v6, k); v7 = vaeseq_u8(v7, k);

        AES_ROUND_8X_KS_ARM(1); AES_ROUND_8X_KS_ARM(2); AES_ROUND_8X_KS_ARM(3);
        AES_ROUND_8X_KS_ARM(4); AES_ROUND_8X_KS_ARM(5); AES_ROUND_8X_KS_ARM(6);
        AES_ROUND_8X_KS_ARM(7); AES_ROUND_8X_KS_ARM(8); AES_ROUND_8X_KS_ARM(9);
        AES_ROUND_8X_KS_ARM(10); AES_ROUND_8X_KS_ARM(11); AES_ROUND_8X_KS_ARM(12);
        AES_ROUND_8X_KS_ARM(13);
        
        v0 = vaesmcq_u8(v0); v1 = vaesmcq_u8(v1); v2 = vaesmcq_u8(v2); v3 = vaesmcq_u8(v3);
        v4 = vaesmcq_u8(v4); v5 = vaesmcq_u8(v5); v6 = vaesmcq_u8(v6); v7 = vaesmcq_u8(v7);
        k = round_keys[14];
        
        vst1q_u8(out_ks,       veorq_u8(v0, k));
        vst1q_u8(out_ks + 16,  veorq_u8(v1, k));
        vst1q_u8(out_ks + 32,  veorq_u8(v2, k));
        vst1q_u8(out_ks + 48,  veorq_u8(v3, k));
        vst1q_u8(out_ks + 64,  veorq_u8(v4, k));
        vst1q_u8(out_ks + 80,  veorq_u8(v5, k));
        vst1q_u8(out_ks + 96,  veorq_u8(v6, k));
        vst1q_u8(out_ks + 112, veorq_u8(v7, k));
        #undef AES_ROUND_8X_KS_ARM
    }

    inline __attribute__((always_inline)) void accumulate_gmac(const uint8_t* ct_block) {
        uint8x16_t ct = vld1q_u8(ct_block);
        current_hash = gf_mul_arm(veorq_u8(current_hash, ct), hash_key);
    }

    void init(const uint8_t* key, const uint8_t* iv) {
        bool key_changed = (!is_key_cached) || (memcmp(cached_key, key, 32) != 0);

        if (key_changed) {
            memcpy(cached_key, key, 32);
            is_key_cached = true;

            static const uint8_t sbox[256] = {
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
            };
            static const uint8_t rcon[7] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };
            
            uint8_t expanded_key[240]; 
            memcpy(expanded_key, key, 32);
            int bytes_gen = 32;
            int rcon_idx = 0;
            
            while (bytes_gen < 240) {
                uint8_t temp[4];
                memcpy(temp, &expanded_key[bytes_gen - 4], 4);
                
                if (bytes_gen % 32 == 0) {
                    uint8_t t = temp[0];
                    temp[0] = sbox[temp[1]] ^ rcon[rcon_idx++];
                    temp[1] = sbox[temp[2]];
                    temp[2] = sbox[temp[3]];
                    temp[3] = sbox[t];
                } else if (bytes_gen % 32 == 16) {
                    temp[0] = sbox[temp[0]];
                    temp[1] = sbox[temp[1]];
                    temp[2] = sbox[temp[2]];
                    temp[3] = sbox[temp[3]];
                }
                for (int j = 0; j < 4; ++j) {
                    expanded_key[bytes_gen] = expanded_key[bytes_gen - 32] ^ temp[j];
                    bytes_gen++;
                }
            }
            
            for (int i = 0; i < 15; ++i) {
                round_keys[i] = vld1q_u8(&expanded_key[i * 16]);
            }

            alignas(16) uint8_t zero_bytes[16] = {0};
            uint8x16_t zero_block = vld1q_u8(zero_bytes);
            
            // 🚀 내부 GF 곱셈으로 거듭제곱 계산
            uint8x16_t hk = aes256_encrypt_arm(zero_block);
            uint8x16_t hk2 = gf_mul_internal(hk, hk);
            uint8x16_t hk3 = gf_mul_internal(hk2, hk);
            uint8x16_t hk4 = gf_mul_internal(hk3, hk);
            uint8x16_t hk5 = gf_mul_internal(hk4, hk);
            uint8x16_t hk6 = gf_mul_internal(hk5, hk);
            uint8x16_t hk7 = gf_mul_internal(hk6, hk);
            uint8x16_t hk8 = gf_mul_internal(hk7, hk);

            // 🚀 루프 최적화를 위해 생성된 해시 키들을 미리 비트 반전하여 캐싱
            hash_key  = vrbitq_u8(hk);
            hash_key2 = vrbitq_u8(hk2);
            hash_key3 = vrbitq_u8(hk3);
            hash_key4 = vrbitq_u8(hk4);
            hash_key5 = vrbitq_u8(hk5);
            hash_key6 = vrbitq_u8(hk6);
            hash_key7 = vrbitq_u8(hk7);
            hash_key8 = vrbitq_u8(hk8);
        }

        alignas(16) uint8_t j0_bytes[16] = {0};
        memcpy(j0_bytes, iv, 12);
        j0_bytes[15] = 0x01; 

        uint8x16_t j0 = vld1q_u8(j0_bytes);
        tag_mask = aes256_encrypt_arm(j0);
        
        j0_bytes[15] = 0x02;
        ctr_block = vld1q_u8(j0_bytes);
        current_hash = vdupq_n_u8(0);
    }

    inline __attribute__((always_inline)) void process_16bytes_fused(const uint8_t* src, uint8_t* dest) {
        uint8x16_t ks = aes256_encrypt_arm(ctr_block);
        uint8x16_t pt = vld1q_u8(src);
        uint8x16_t ct = veorq_u8(pt, ks);
        vst1q_u8(dest, ct);
        current_hash = gf_mul_arm(veorq_u8(current_hash, ct), hash_key);
        increment_counter_arm();
    }

    inline __attribute__((always_inline)) void process_aad_16bytes_fused(const uint8_t* aad) {
        uint8x16_t a = vld1q_u8(aad);
        current_hash = gf_mul_arm(veorq_u8(current_hash, a), hash_key);
    }

    inline __attribute__((always_inline)) void process_tail_fused(const uint8_t* src, uint8_t* dest, size_t len) {
        // if (len == 0) return;
        // alignas(16) uint8_t t_in[16] = {0}, t_out[16] = {0};
        // memcpy(t_in, src, len);
        
        // uint8x16_t ks = aes256_encrypt_arm(ctr_block);
        // uint8x16_t ct = veorq_u8(vld1q_u8(t_in), ks);
        // vst1q_u8(t_out, ct);
        // memcpy(dest, t_out, len);
        // for(size_t i=len; i<16; ++i) t_out[i] = 0;
        
        // uint8x16_t ct_padded = vld1q_u8(t_out);
        // current_hash = gf_mul_arm(veorq_u8(current_hash, ct_padded), hash_key);
        // increment_counter_arm();

        if (len == 0) return;

        // 1. 메모리 보호를 위한 최소한의 복사 (컴파일러 최적화로 매우 빠름)
        alignas(16) uint8_t t_in[16] = {0};
        memcpy(t_in, src, len);

        // 2. Keystream 생성 및 16바이트 풀-사이즈 암호화 연산
        uint8x16_t ks = aes256_encrypt_arm(ctr_block);
        uint8x16_t ct_full = veorq_u8(vld1q_u8(t_in), ks);

        // 3. 암호화된 결과 중 필요한 길이(len)만큼만 전송 (질문자님의 아이디어 적용!)
        alignas(16) uint8_t t_out[16];
        vst1q_u8(t_out, ct_full);
        memcpy(dest, t_out, len);

        // ====================================================================
        // 🚀 [핵심 최적화] for 루프를 없애고 NEON 마스크 테이블을 사용
        // ====================================================================
        static const uint8_t mask_table[32] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 상위 16바이트는 1 (살릴 부분)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 하위 16바이트는 0 (지울 부분)
        };

        // len 값에 따라 테이블을 슬라이딩하여 마스크 로드
        // 예: len이 5라면 0xFF가 5개, 0x00이 11개인 16바이트 마스크를 단 한 번의 명령어로 로드
        uint8x16_t mask = vld1q_u8(mask_table + 16 - len); 
        
        // 비트 AND 연산으로 나머지 찌꺼기 바이트를 즉시 0으로 만듦 (for 루프 대체)
        uint8x16_t ct_padded = vandq_u8(ct_full, mask); 

        // 4. 패딩된 블록을 GHASH에 누적
        current_hash = gf_mul_arm(veorq_u8(current_hash, ct_padded), hash_key);
        increment_counter_arm();
    }

    inline __attribute__((always_inline)) void process_aad_tail_fused(const uint8_t* aad, size_t len) {
        if (len == 0) return;
        alignas(16) uint8_t t_in[16] = {0};
        memcpy(t_in, aad, len);
        
        uint8x16_t a = vld1q_u8(t_in);
        current_hash = gf_mul_arm(veorq_u8(current_hash, a), hash_key);
    }

    inline __attribute__((always_inline)) void decrypt_16bytes_fused(const uint8_t* src, uint8_t* dest) {
        uint8x16_t ct = vld1q_u8(src);
        current_hash = gf_mul_arm(veorq_u8(current_hash, ct), hash_key);
        
        uint8x16_t ks = aes256_encrypt_arm(ctr_block);
        uint8x16_t pt = veorq_u8(ct, ks);
        vst1q_u8(dest, pt);
        increment_counter_arm();
    }

    inline __attribute__((always_inline)) void decrypt_tail_fused(const uint8_t* src, uint8_t* dest, size_t len) {
        if (len == 0) return;
        alignas(16) uint8_t t_in[16] = {0}, t_out[16] = {0};
        memcpy(t_in, src, len);
        
        uint8x16_t ct = vld1q_u8(t_in);
        current_hash = gf_mul_arm(veorq_u8(current_hash, ct), hash_key);
        
        uint8x16_t ks = aes256_encrypt_arm(ctr_block);
        uint8x16_t pt = veorq_u8(ct, ks);
        vst1q_u8(t_out, pt);
        memcpy(dest, t_out, len);
        increment_counter_arm();
    }

    inline __attribute__((always_inline)) void process_64bytes_fused(const uint8_t* src, uint8_t* dest) {
        uint8x16_t ctr0 = ctr_block;
        uint8x16_t ctr1 = INC_ARM_CTR32(ctr0, 1);
        uint8x16_t ctr2 = INC_ARM_CTR32(ctr0, 2);
        uint8x16_t ctr3 = INC_ARM_CTR32(ctr0, 3);
        ctr_block = INC_ARM_CTR32(ctr0, 4);

        uint8x16_t k = round_keys[0];
        uint8x16_t v0 = vaeseq_u8(ctr0, k);
        uint8x16_t v1 = vaeseq_u8(ctr1, k);
        uint8x16_t v2 = vaeseq_u8(ctr2, k);
        uint8x16_t v3 = vaeseq_u8(ctr3, k);

        #define AES_ROUND_4X_ARM(idx) \
            v0 = vaesmcq_u8(v0); v1 = vaesmcq_u8(v1); v2 = vaesmcq_u8(v2); v3 = vaesmcq_u8(v3); \
            k = round_keys[idx]; \
            v0 = vaeseq_u8(v0, k); v1 = vaeseq_u8(v1, k); v2 = vaeseq_u8(v2, k); v3 = vaeseq_u8(v3, k);

        AES_ROUND_4X_ARM(1); AES_ROUND_4X_ARM(2); AES_ROUND_4X_ARM(3);
        AES_ROUND_4X_ARM(4); AES_ROUND_4X_ARM(5); AES_ROUND_4X_ARM(6);
        AES_ROUND_4X_ARM(7); AES_ROUND_4X_ARM(8); AES_ROUND_4X_ARM(9);
        AES_ROUND_4X_ARM(10); AES_ROUND_4X_ARM(11); AES_ROUND_4X_ARM(12);
        AES_ROUND_4X_ARM(13);
        
        v0 = vaesmcq_u8(v0); v1 = vaesmcq_u8(v1); v2 = vaesmcq_u8(v2); v3 = vaesmcq_u8(v3);
        k = round_keys[14];
        
        uint8x16_t ks0 = veorq_u8(v0, k);
        uint8x16_t ks1 = veorq_u8(v1, k);
        uint8x16_t ks2 = veorq_u8(v2, k);
        uint8x16_t ks3 = veorq_u8(v3, k);

        uint8x16_t pt0 = vld1q_u8(src);
        uint8x16_t pt1 = vld1q_u8(src + 16);
        uint8x16_t pt2 = vld1q_u8(src + 32);
        uint8x16_t pt3 = vld1q_u8(src + 48);

        uint8x16_t ct0 = veorq_u8(pt0, ks0);
        uint8x16_t ct1 = veorq_u8(pt1, ks1);
        uint8x16_t ct2 = veorq_u8(pt2, ks2);
        uint8x16_t ct3 = veorq_u8(pt3, ks3);

        vst1q_u8(dest, ct0);
        vst1q_u8(dest + 16, ct1);
        vst1q_u8(dest + 32, ct2);
        vst1q_u8(dest + 48, ct3);

        // 💡 4블록 레지스터 즉시 누적 (구조체 오버헤드 완벽 제거)
        uint64x2_t sum_lo = vdupq_n_u64(0);
        uint64x2_t sum_hi = vdupq_n_u64(0);
        uint64x2_t sum_mid = vdupq_n_u64(0);

        PMULL_ACCUMULATE_STD(veorq_u8(current_hash, ct0), hash_key4, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct1, hash_key3, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct2, hash_key2, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct3, hash_key,  sum_lo, sum_hi, sum_mid);

        sum_mid = veorq_u64(sum_mid, sum_lo);
        sum_mid = veorq_u64(sum_mid, sum_hi);

        uint64_t z0 = vgetq_lane_u64(sum_lo, 0);
        uint64_t z1 = vgetq_lane_u64(sum_lo, 1) ^ vgetq_lane_u64(sum_mid, 0);
        uint64_t z2 = vgetq_lane_u64(sum_hi, 0) ^ vgetq_lane_u64(sum_mid, 1);
        uint64_t z3 = vgetq_lane_u64(sum_hi, 1);

        z1 ^= z3 ^ (z3 << 1) ^ (z3 << 2) ^ (z3 << 7);
        z2 ^= (z3 >> 63) ^ (z3 >> 62) ^ (z3 >> 57);

        z0 ^= z2 ^ (z2 << 1) ^ (z2 << 2) ^ (z2 << 7);
        z1 ^= (z2 >> 63) ^ (z2 >> 62) ^ (z2 >> 57);

        uint64x2_t res = vcombine_u64(vcreate_u64(z0), vcreate_u64(z1));
        current_hash = vrbitq_u8(vreinterpretq_u8_u64(res));

        #undef AES_ROUND_4X_ARM
    }

    inline __attribute__((always_inline)) void process_128bytes_fused_arm(const uint8_t* src, uint8_t* dest) {
        uint8x16_t ctr0 = ctr_block;
        uint8x16_t ctr1 = INC_ARM_CTR32(ctr0, 1);
        uint8x16_t ctr2 = INC_ARM_CTR32(ctr0, 2);
        uint8x16_t ctr3 = INC_ARM_CTR32(ctr0, 3);
        uint8x16_t ctr4 = INC_ARM_CTR32(ctr0, 4);
        uint8x16_t ctr5 = INC_ARM_CTR32(ctr0, 5);
        uint8x16_t ctr6 = INC_ARM_CTR32(ctr0, 6);
        uint8x16_t ctr7 = INC_ARM_CTR32(ctr0, 7);
        ctr_block = INC_ARM_CTR32(ctr0, 8);

        uint8x16_t k = round_keys[0];
        uint8x16_t v0 = vaeseq_u8(ctr0, k); uint8x16_t v1 = vaeseq_u8(ctr1, k);
        uint8x16_t v2 = vaeseq_u8(ctr2, k); uint8x16_t v3 = vaeseq_u8(ctr3, k);
        uint8x16_t v4 = vaeseq_u8(ctr4, k); uint8x16_t v5 = vaeseq_u8(ctr5, k);
        uint8x16_t v6 = vaeseq_u8(ctr6, k); uint8x16_t v7 = vaeseq_u8(ctr7, k);

        #define AES_ROUND_8X_ARM(idx) \
            v0 = vaesmcq_u8(v0); v1 = vaesmcq_u8(v1); v2 = vaesmcq_u8(v2); v3 = vaesmcq_u8(v3); \
            v4 = vaesmcq_u8(v4); v5 = vaesmcq_u8(v5); v6 = vaesmcq_u8(v6); v7 = vaesmcq_u8(v7); \
            k = round_keys[idx]; \
            v0 = vaeseq_u8(v0, k); v1 = vaeseq_u8(v1, k); v2 = vaeseq_u8(v2, k); v3 = vaeseq_u8(v3, k); \
            v4 = vaeseq_u8(v4, k); v5 = vaeseq_u8(v5, k); v6 = vaeseq_u8(v6, k); v7 = vaeseq_u8(v7, k);

        AES_ROUND_8X_ARM(1); AES_ROUND_8X_ARM(2); AES_ROUND_8X_ARM(3);
        AES_ROUND_8X_ARM(4); AES_ROUND_8X_ARM(5); AES_ROUND_8X_ARM(6);
        AES_ROUND_8X_ARM(7); AES_ROUND_8X_ARM(8); AES_ROUND_8X_ARM(9);
        AES_ROUND_8X_ARM(10); AES_ROUND_8X_ARM(11); AES_ROUND_8X_ARM(12);
        AES_ROUND_8X_ARM(13);
        
        v0 = vaesmcq_u8(v0); v1 = vaesmcq_u8(v1); v2 = vaesmcq_u8(v2); v3 = vaesmcq_u8(v3);
        v4 = vaesmcq_u8(v4); v5 = vaesmcq_u8(v5); v6 = vaesmcq_u8(v6); v7 = vaesmcq_u8(v7);
        k = round_keys[14];
        
        uint8x16_t ks0 = veorq_u8(v0, k); uint8x16_t ks1 = veorq_u8(v1, k);
        uint8x16_t ks2 = veorq_u8(v2, k); uint8x16_t ks3 = veorq_u8(v3, k);
        uint8x16_t ks4 = veorq_u8(v4, k); uint8x16_t ks5 = veorq_u8(v5, k);
        uint8x16_t ks6 = veorq_u8(v6, k); uint8x16_t ks7 = veorq_u8(v7, k);

        uint8x16x4_t pt_blk0 = vld1q_u8_x4(src);
        uint8x16x4_t pt_blk1 = vld1q_u8_x4(src + 64);

        uint8x16_t ct0 = veorq_u8(pt_blk0.val[0], ks0); uint8x16_t ct1 = veorq_u8(pt_blk0.val[1], ks1);
        uint8x16_t ct2 = veorq_u8(pt_blk0.val[2], ks2); uint8x16_t ct3 = veorq_u8(pt_blk0.val[3], ks3);
        uint8x16_t ct4 = veorq_u8(pt_blk1.val[0], ks4); uint8x16_t ct5 = veorq_u8(pt_blk1.val[1], ks5);
        uint8x16_t ct6 = veorq_u8(pt_blk1.val[2], ks6); uint8x16_t ct7 = veorq_u8(pt_blk1.val[3], ks7);

        vst1q_u8(dest, ct0);
        vst1q_u8(dest + 16, ct1);
        vst1q_u8(dest + 32, ct2);
        vst1q_u8(dest + 48, ct3);
        vst1q_u8(dest + 64, ct4);
        vst1q_u8(dest + 80, ct5);
        vst1q_u8(dest + 96, ct6);
        vst1q_u8(dest + 112, ct7);

        // 💡 8블록 지연 축소 즉시 누적
        uint64x2_t sum_lo = vdupq_n_u64(0);
        uint64x2_t sum_hi = vdupq_n_u64(0);
        uint64x2_t sum_mid = vdupq_n_u64(0);

        PMULL_ACCUMULATE_STD(veorq_u8(current_hash, ct0), hash_key8, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct1, hash_key7, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct2, hash_key6, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct3, hash_key5, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct4, hash_key4, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct5, hash_key3, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct6, hash_key2, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct7, hash_key,  sum_lo, sum_hi, sum_mid);

        sum_mid = veorq_u64(sum_mid, sum_lo);
        sum_mid = veorq_u64(sum_mid, sum_hi);

        uint64_t z0 = vgetq_lane_u64(sum_lo, 0);
        uint64_t z1 = vgetq_lane_u64(sum_lo, 1) ^ vgetq_lane_u64(sum_mid, 0);
        uint64_t z2 = vgetq_lane_u64(sum_hi, 0) ^ vgetq_lane_u64(sum_mid, 1);
        uint64_t z3 = vgetq_lane_u64(sum_hi, 1);

        z1 ^= z3 ^ (z3 << 1) ^ (z3 << 2) ^ (z3 << 7);
        z2 ^= (z3 >> 63) ^ (z3 >> 62) ^ (z3 >> 57);

        z0 ^= z2 ^ (z2 << 1) ^ (z2 << 2) ^ (z2 << 7);
        z1 ^= (z2 >> 63) ^ (z2 >> 62) ^ (z2 >> 57);

        uint64x2_t res = vcombine_u64(vcreate_u64(z0), vcreate_u64(z1));
        current_hash = vrbitq_u8(vreinterpretq_u8_u64(res));
        
        #undef AES_ROUND_8X_ARM
    }

    inline __attribute__((always_inline)) void decrypt_64bytes_fused(const uint8_t* src, uint8_t* dest) {
        uint8x16_t ct0 = vld1q_u8(src);
        uint8x16_t ct1 = vld1q_u8(src + 16);
        uint8x16_t ct2 = vld1q_u8(src + 32);
        uint8x16_t ct3 = vld1q_u8(src + 48);

        // 💡 복호화 시에도 동일한 레지스터 최적화 지연 축소 적용
        uint64x2_t sum_lo = vdupq_n_u64(0);
        uint64x2_t sum_hi = vdupq_n_u64(0);
        uint64x2_t sum_mid = vdupq_n_u64(0);

        PMULL_ACCUMULATE_STD(veorq_u8(current_hash, ct0), hash_key4, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct1, hash_key3, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct2, hash_key2, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct3, hash_key,  sum_lo, sum_hi, sum_mid);

        sum_mid = veorq_u64(sum_mid, sum_lo);
        sum_mid = veorq_u64(sum_mid, sum_hi);

        uint64_t z0 = vgetq_lane_u64(sum_lo, 0);
        uint64_t z1 = vgetq_lane_u64(sum_lo, 1) ^ vgetq_lane_u64(sum_mid, 0);
        uint64_t z2 = vgetq_lane_u64(sum_hi, 0) ^ vgetq_lane_u64(sum_mid, 1);
        uint64_t z3 = vgetq_lane_u64(sum_hi, 1);

        z1 ^= z3 ^ (z3 << 1) ^ (z3 << 2) ^ (z3 << 7);
        z2 ^= (z3 >> 63) ^ (z3 >> 62) ^ (z3 >> 57);

        z0 ^= z2 ^ (z2 << 1) ^ (z2 << 2) ^ (z2 << 7);
        z1 ^= (z2 >> 63) ^ (z2 >> 62) ^ (z2 >> 57);

        uint64x2_t res = vcombine_u64(vcreate_u64(z0), vcreate_u64(z1));
        current_hash = vrbitq_u8(vreinterpretq_u8_u64(res));

        uint8x16_t ctr0 = ctr_block;
        uint8x16_t ctr1 = INC_ARM_CTR32(ctr0, 1);
        uint8x16_t ctr2 = INC_ARM_CTR32(ctr0, 2);
        uint8x16_t ctr3 = INC_ARM_CTR32(ctr0, 3);
        ctr_block = INC_ARM_CTR32(ctr0, 4);

        uint8x16_t k = round_keys[0];
        uint8x16_t v0 = vaeseq_u8(ctr0, k);
        uint8x16_t v1 = vaeseq_u8(ctr1, k);
        uint8x16_t v2 = vaeseq_u8(ctr2, k);
        uint8x16_t v3 = vaeseq_u8(ctr3, k);

        #define AES_ROUND_4X_DEC_ARM(idx) \
            v0 = vaesmcq_u8(v0); v1 = vaesmcq_u8(v1); v2 = vaesmcq_u8(v2); v3 = vaesmcq_u8(v3); \
            k = round_keys[idx]; \
            v0 = vaeseq_u8(v0, k); v1 = vaeseq_u8(v1, k); v2 = vaeseq_u8(v2, k); v3 = vaeseq_u8(v3, k);

        AES_ROUND_4X_DEC_ARM(1); AES_ROUND_4X_DEC_ARM(2); AES_ROUND_4X_DEC_ARM(3);
        AES_ROUND_4X_DEC_ARM(4); AES_ROUND_4X_DEC_ARM(5); AES_ROUND_4X_DEC_ARM(6);
        AES_ROUND_4X_DEC_ARM(7); AES_ROUND_4X_DEC_ARM(8); AES_ROUND_4X_DEC_ARM(9);
        AES_ROUND_4X_DEC_ARM(10); AES_ROUND_4X_DEC_ARM(11); AES_ROUND_4X_DEC_ARM(12);
        AES_ROUND_4X_DEC_ARM(13);
        
        v0 = vaesmcq_u8(v0); v1 = vaesmcq_u8(v1); v2 = vaesmcq_u8(v2); v3 = vaesmcq_u8(v3);
        k = round_keys[14];
        
        uint8x16_t pt0 = veorq_u8(ct0, veorq_u8(v0, k));
        uint8x16_t pt1 = veorq_u8(ct1, veorq_u8(v1, k));
        uint8x16_t pt2 = veorq_u8(ct2, veorq_u8(v2, k));
        uint8x16_t pt3 = veorq_u8(ct3, veorq_u8(v3, k));

        vst1q_u8(dest, pt0);
        vst1q_u8(dest + 16, pt1);
        vst1q_u8(dest + 32, pt2);
        vst1q_u8(dest + 48, pt3);
        #undef AES_ROUND_4X_DEC_ARM
    }

    inline __attribute__((always_inline)) void decrypt_128bytes_fused_arm(const uint8_t* src, uint8_t* dest) {
        // 1. 8블록 암호문 로드 (vld1q_u8_x4를 활용한 효율적인 연속 메모리 로드)
        uint8x16x4_t ct_blk0 = vld1q_u8_x4(src);
        uint8x16x4_t ct_blk1 = vld1q_u8_x4(src + 64);

        uint8x16_t ct0 = ct_blk0.val[0]; uint8x16_t ct1 = ct_blk0.val[1];
        uint8x16_t ct2 = ct_blk0.val[2]; uint8x16_t ct3 = ct_blk0.val[3];
        uint8x16_t ct4 = ct_blk1.val[0]; uint8x16_t ct5 = ct_blk1.val[1];
        uint8x16_t ct6 = ct_blk1.val[2]; uint8x16_t ct7 = ct_blk1.val[3];

        // 2. 8블록 지연 축소 즉시 누적 (암호문을 바로 GHASH에 반영)
        uint64x2_t sum_lo = vdupq_n_u64(0);
        uint64x2_t sum_hi = vdupq_n_u64(0);
        uint64x2_t sum_mid = vdupq_n_u64(0);

        PMULL_ACCUMULATE_STD(veorq_u8(current_hash, ct0), hash_key8, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct1, hash_key7, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct2, hash_key6, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct3, hash_key5, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct4, hash_key4, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct5, hash_key3, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct6, hash_key2, sum_lo, sum_hi, sum_mid);
        PMULL_ACCUMULATE_STD(ct7, hash_key,  sum_lo, sum_hi, sum_mid);

        sum_mid = veorq_u64(sum_mid, sum_lo);
        sum_mid = veorq_u64(sum_mid, sum_hi);

        uint64_t z0 = vgetq_lane_u64(sum_lo, 0);
        uint64_t z1 = vgetq_lane_u64(sum_lo, 1) ^ vgetq_lane_u64(sum_mid, 0);
        uint64_t z2 = vgetq_lane_u64(sum_hi, 0) ^ vgetq_lane_u64(sum_mid, 1);
        uint64_t z3 = vgetq_lane_u64(sum_hi, 1);

        z1 ^= z3 ^ (z3 << 1) ^ (z3 << 2) ^ (z3 << 7);
        z2 ^= (z3 >> 63) ^ (z3 >> 62) ^ (z3 >> 57);

        z0 ^= z2 ^ (z2 << 1) ^ (z2 << 2) ^ (z2 << 7);
        z1 ^= (z2 >> 63) ^ (z2 >> 62) ^ (z2 >> 57);

        uint64x2_t res = vcombine_u64(vcreate_u64(z0), vcreate_u64(z1));
        current_hash = vrbitq_u8(vreinterpretq_u8_u64(res));

        // 3. 8블록 카운터 및 Keystream 병렬 생성
        uint8x16_t ctr0 = ctr_block;
        uint8x16_t ctr1 = INC_ARM_CTR32(ctr0, 1);
        uint8x16_t ctr2 = INC_ARM_CTR32(ctr0, 2);
        uint8x16_t ctr3 = INC_ARM_CTR32(ctr0, 3);
        uint8x16_t ctr4 = INC_ARM_CTR32(ctr0, 4);
        uint8x16_t ctr5 = INC_ARM_CTR32(ctr0, 5);
        uint8x16_t ctr6 = INC_ARM_CTR32(ctr0, 6);
        uint8x16_t ctr7 = INC_ARM_CTR32(ctr0, 7);
        ctr_block = INC_ARM_CTR32(ctr0, 8);

        uint8x16_t k = round_keys[0];
        uint8x16_t v0 = vaeseq_u8(ctr0, k); uint8x16_t v1 = vaeseq_u8(ctr1, k);
        uint8x16_t v2 = vaeseq_u8(ctr2, k); uint8x16_t v3 = vaeseq_u8(ctr3, k);
        uint8x16_t v4 = vaeseq_u8(ctr4, k); uint8x16_t v5 = vaeseq_u8(ctr5, k);
        uint8x16_t v6 = vaeseq_u8(ctr6, k); uint8x16_t v7 = vaeseq_u8(ctr7, k);

        #define AES_ROUND_8X_DEC_ARM(idx) \
            v0 = vaesmcq_u8(v0); v1 = vaesmcq_u8(v1); v2 = vaesmcq_u8(v2); v3 = vaesmcq_u8(v3); \
            v4 = vaesmcq_u8(v4); v5 = vaesmcq_u8(v5); v6 = vaesmcq_u8(v6); v7 = vaesmcq_u8(v7); \
            k = round_keys[idx]; \
            v0 = vaeseq_u8(v0, k); v1 = vaeseq_u8(v1, k); v2 = vaeseq_u8(v2, k); v3 = vaeseq_u8(v3, k); \
            v4 = vaeseq_u8(v4, k); v5 = vaeseq_u8(v5, k); v6 = vaeseq_u8(v6, k); v7 = vaeseq_u8(v7, k);

        AES_ROUND_8X_DEC_ARM(1); AES_ROUND_8X_DEC_ARM(2); AES_ROUND_8X_DEC_ARM(3);
        AES_ROUND_8X_DEC_ARM(4); AES_ROUND_8X_DEC_ARM(5); AES_ROUND_8X_DEC_ARM(6);
        AES_ROUND_8X_DEC_ARM(7); AES_ROUND_8X_DEC_ARM(8); AES_ROUND_8X_DEC_ARM(9);
        AES_ROUND_8X_DEC_ARM(10); AES_ROUND_8X_DEC_ARM(11); AES_ROUND_8X_DEC_ARM(12);
        AES_ROUND_8X_DEC_ARM(13);
        
        v0 = vaesmcq_u8(v0); v1 = vaesmcq_u8(v1); v2 = vaesmcq_u8(v2); v3 = vaesmcq_u8(v3);
        v4 = vaesmcq_u8(v4); v5 = vaesmcq_u8(v5); v6 = vaesmcq_u8(v6); v7 = vaesmcq_u8(v7);
        k = round_keys[14];

        // 4. 복호화 (Ciphertext ^ Keystream) 및 저장
        uint8x16_t pt0 = veorq_u8(ct0, veorq_u8(v0, k));
        uint8x16_t pt1 = veorq_u8(ct1, veorq_u8(v1, k));
        uint8x16_t pt2 = veorq_u8(ct2, veorq_u8(v2, k));
        uint8x16_t pt3 = veorq_u8(ct3, veorq_u8(v3, k));
        uint8x16_t pt4 = veorq_u8(ct4, veorq_u8(v4, k));
        uint8x16_t pt5 = veorq_u8(ct5, veorq_u8(v5, k));
        uint8x16_t pt6 = veorq_u8(ct6, veorq_u8(v6, k));
        uint8x16_t pt7 = veorq_u8(ct7, veorq_u8(v7, k));

        vst1q_u8(dest, pt0);
        vst1q_u8(dest + 16, pt1);
        vst1q_u8(dest + 32, pt2);
        vst1q_u8(dest + 48, pt3);
        vst1q_u8(dest + 64, pt4);
        vst1q_u8(dest + 80, pt5);
        vst1q_u8(dest + 96, pt6);
        vst1q_u8(dest + 112, pt7);

        #undef AES_ROUND_8X_DEC_ARM
    }

    inline __attribute__((always_inline)) void finalize(size_t aad_len, size_t payload_len, uint8_t* out_tag) {
        alignas(16) uint8_t len_blk[16] = {0};
        // GCM 표준 길이 규격 생성
        uint64_t al = __builtin_bswap64((uint64_t)aad_len * 8);
        uint64_t pl = __builtin_bswap64((uint64_t)payload_len * 8);
        memcpy(len_blk, &al, 8);
        memcpy(len_blk + 8, &pl, 8);
        
        uint8x16_t len_vec = vld1q_u8(len_blk); 
        current_hash = gf_mul_arm(veorq_u8(current_hash, len_vec), hash_key);
        
        vst1q_u8(out_tag, veorq_u8(current_hash, tag_mask));
    }

    inline __attribute__((always_inline)) bool verify_tag(size_t aad_len, size_t payload_len, const uint8_t* expected_tag) {
        alignas(16) uint8_t computed_tag[16];
        finalize(aad_len, payload_len, computed_tag);
        
        uint8x16_t comp = vld1q_u8(computed_tag);
        uint8x16_t exp = vld1q_u8(expected_tag);
        uint8x16_t diff_vec = veorq_u8(comp, exp);
        uint64x2_t diff64 = vreinterpretq_u64_u8(diff_vec);
        uint64_t val = vgetq_lane_u64(diff64, 0) | vgetq_lane_u64(diff64, 1);
        return (val == 0);
    }
};

#endif // FUSED_CRYPTO_PAYLOAD_ARM_H