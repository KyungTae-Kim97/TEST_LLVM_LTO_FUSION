#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__x86_64__)
    #include <immintrin.h>
#elif defined(__aarch64__)
    #include <arm_neon.h>
#endif

class FusedCryptoPayload {
private:
    // 🚀 AES-256: Key Caching을 위한 상태 변수 (32 바이트)
    uint8_t cached_key[32] = {0};
    bool is_key_cached = false;



#if defined(__aarch64__)
    uint8x16_t ctr_block;
    uint8x16_t hash_key;
    uint8x16_t hash_key2;
    uint8x16_t hash_key3;
    uint8x16_t hash_key4;
    uint8x16_t current_hash;
    uint8x16_t round_keys[15]; 
    uint8x16_t tag_mask;

    inline __attribute__((always_inline)) uint8x16_t gf_mul_arm(uint8x16_t a, uint8x16_t b) {
        poly64x2_t pA = vreinterpretq_p64_u8(a);
        poly64x2_t pB = vreinterpretq_p64_u8(b);
        
        // 💡 1. 벡터에서 스칼라(poly64_t) 값으로 안전하게 추출
        poly64_t a0 = vgetq_lane_p64(pA, 0);
        poly64_t a1 = vgetq_lane_p64(pA, 1);
        poly64_t b0 = vgetq_lane_p64(pB, 0);
        poly64_t b1 = vgetq_lane_p64(pB, 1);
        
        // 정상 동작하던 기존 vmull_p64 호출
        poly128_t m00 = vmull_p64(a0, b0);
        poly128_t m11 = vmull_p64(a1, b1);
        
        // 💡 2. veor_p64 대신 스칼라 상태에서 uint64_t로 캐스팅하여 안전하게 XOR(^) 연산 수행
        poly64_t a_xor = (poly64_t)((uint64_t)a0 ^ (uint64_t)a1);
        poly64_t b_xor = (poly64_t)((uint64_t)b0 ^ (uint64_t)b1);
        
        // 이제 타입 불일치 에러 없이 안전하게 호출됨
        poly128_t m01 = vmull_p64(a_xor, b_xor);
        
        // 💡 3. 하위 로직은 원본 그대로 유지 (GHASH Karatsuba 환원)
        uint64x2_t m00_v = vreinterpretq_u64_p128(m00);
        uint64x2_t m11_v = vreinterpretq_u64_p128(m11);
        uint64x2_t m01_v = vreinterpretq_u64_p128(m01);
        
        uint64x2_t mid = veorq_u64(veorq_u64(m01_v, m00_v), m11_v);
        uint64x2_t r_low = veorq_u64(m00_v, vextq_u64(vdupq_n_u64(0), mid, 1));
        uint64x2_t r_high = veorq_u64(m11_v, vextq_u64(mid, vdupq_n_u64(0), 1));
        
        uint64x2_t tmp = veorq_u64(r_low, vshlq_n_u64(r_low, 1));
        tmp = veorq_u64(tmp, vshlq_n_u64(tmp, 2));
        tmp = veorq_u64(tmp, vshlq_n_u64(tmp, 7));
        r_low = veorq_u64(r_low, tmp);
        
        r_high = veorq_u64(r_high, vshrq_n_u64(r_low, 63));
        r_high = veorq_u64(r_high, vshrq_n_u64(r_low, 62));
        r_high = veorq_u64(r_high, vshrq_n_u64(r_low, 57));
        
        return vreinterpretq_u8_u64(r_high);
    }

    // 🚀 AES-256: 14라운드 적용
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

    // 🚀 NIST SP 800-38D 규격: 단일 블록 32-bit (inc32) 증가 로직
    inline __attribute__((always_inline)) void increment_counter_arm() {
        uint32x4_t ctr32 = vreinterpretq_u32_u8(vrev32q_u8(ctr_block));
        ctr32 = vsetq_lane_u32(vgetq_lane_u32(ctr32, 3) + 1, ctr32, 3);
        ctr_block = vrev32q_u8(vreinterpretq_u8_u32(ctr32));
    }
#endif

public:
    inline __attribute__((always_inline)) void generate_keystream(uint8_t* out_ks) {

#if defined(__aarch64__)
        uint8x16_t ks = aes256_encrypt_arm(ctr_block);
        vst1q_u8(out_ks, ks);
        increment_counter_arm(); 
#endif
    }

    inline __attribute__((always_inline)) void accumulate_gmac(const uint8_t* ct_block) {
#if defined(__aarch64__)
        uint8x16_t ct = vld1q_u8(ct_block);
        current_hash = gf_mul_arm(veorq_u8(current_hash, ct), hash_key);
#endif
    }

    // =====================================================================
    // 0. [Init] 초기 설정 (Key Caching 및 AES-256 확장 적용)
    // =====================================================================
    void init(const uint8_t* key, const uint8_t* iv) {
        bool key_changed = (!is_key_cached) || (memcmp(cached_key, key, 32) != 0);

        if (key_changed) {
            memcpy(cached_key, key, 32);
            is_key_cached = true;



#if defined(__aarch64__)
            // 🚀 AES-256 Key Expansion (ARM)
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
            hash_key = aes256_encrypt_arm(zero_block);
            hash_key2 = gf_mul_arm(hash_key, hash_key);
            hash_key3 = gf_mul_arm(hash_key2, hash_key);
            hash_key4 = gf_mul_arm(hash_key3, hash_key);
#endif
        }

        alignas(16) uint8_t j0_bytes[16] = {0};
        memcpy(j0_bytes, iv, 12);
        j0_bytes[15] = 0x01; 

#if defined(__aarch64__)
        uint8x16_t j0 = vld1q_u8(j0_bytes);
        tag_mask = aes256_encrypt_arm(j0);
        
        j0_bytes[15] = 0x02;
        ctr_block = vld1q_u8(j0_bytes);
        current_hash = vdupq_n_u8(0);
#endif
    }

    inline __attribute__((always_inline)) void process_16bytes_fused(const uint8_t* src, uint8_t* dest) {
#if defined(__aarch64__)
        uint8x16_t ks = aes256_encrypt_arm(ctr_block);
        uint8x16_t pt = vld1q_u8(src);
        uint8x16_t ct = veorq_u8(pt, ks);
        vst1q_u8(dest, ct);
        current_hash = gf_mul_arm(veorq_u8(current_hash, ct), hash_key);
        increment_counter_arm();
#endif
    }

    inline __attribute__((always_inline)) void process_aad_16bytes_fused(const uint8_t* aad) {
#if defined(__aarch64__)
        uint8x16_t a = vld1q_u8(aad);
        current_hash = gf_mul_arm(veorq_u8(current_hash, a), hash_key);
#endif
    }

    inline __attribute__((always_inline)) void process_tail_fused(const uint8_t* src, uint8_t* dest, size_t len) {
        if (len == 0) return;
        alignas(16) uint8_t t_in[16] = {0}, t_out[16] = {0};
        memcpy(t_in, src, len);
#if defined(__aarch64__)
        uint8x16_t ks = aes256_encrypt_arm(ctr_block);
        uint8x16_t ct = veorq_u8(vld1q_u8(t_in), ks);
        vst1q_u8(t_out, ct);
        memcpy(dest, t_out, len);
        for(size_t i=len; i<16; ++i) t_out[i] = 0;
        current_hash = gf_mul_arm(veorq_u8(current_hash, vld1q_u8(t_out)), hash_key);
        increment_counter_arm();
#endif
    }

    inline __attribute__((always_inline)) void process_aad_tail_fused(const uint8_t* aad, size_t len) {
        if (len == 0) return;
        alignas(16) uint8_t t_in[16] = {0};
        memcpy(t_in, aad, len);
#if defined(__aarch64__)
        uint8x16_t a = vld1q_u8(t_in);
        current_hash = gf_mul_arm(veorq_u8(current_hash, a), hash_key);
#endif
    }

    inline __attribute__((always_inline)) void decrypt_16bytes_fused(const uint8_t* src, uint8_t* dest) {
#if defined(__aarch64__)
        uint8x16_t ct = vld1q_u8(src);
        current_hash = gf_mul_arm(veorq_u8(current_hash, ct), hash_key);
        
        uint8x16_t ks = aes256_encrypt_arm(ctr_block);
        uint8x16_t pt = veorq_u8(ct, ks);
        vst1q_u8(dest, pt);
        
        increment_counter_arm();
#endif
    }

    inline __attribute__((always_inline)) void decrypt_tail_fused(const uint8_t* src, uint8_t* dest, size_t len) {
        if (len == 0) return;
        alignas(16) uint8_t t_in[16] = {0}, t_out[16] = {0};
        memcpy(t_in, src, len);
#if defined(__aarch64__)
        uint8x16_t ct = vld1q_u8(t_in);
        current_hash = gf_mul_arm(veorq_u8(current_hash, ct), hash_key);
        
        uint8x16_t ks = aes256_encrypt_arm(ctr_block);
        uint8x16_t pt = veorq_u8(ct, ks);
        vst1q_u8(t_out, pt);
        
        memcpy(dest, t_out, len);
        increment_counter_arm();
#endif
    }

    // =====================================================================
    // 64바이트 병렬 처리 (AES-256 특화 14라운드 및 32-bit $inc_{32}$ 병렬 생성)
    // =====================================================================
    inline __attribute__((always_inline)) void process_64bytes_fused(const uint8_t* src, uint8_t* dest) {

#if defined(__aarch64__)
        uint8x16_t ctr0 = ctr_block;
        
        // 🚀 32-bit Big Endian 순차적 병렬 카운터 계산 매크로
        #define INC_ARM_CTR32(c, val) \
            ([&]() -> uint8x16_t { \
                uint32x4_t ctr32 = vreinterpretq_u32_u8(vrev32q_u8(c)); \
                ctr32 = vsetq_lane_u32(vgetq_lane_u32(ctr32, 3) + val, ctr32, 3); \
                return vrev32q_u8(vreinterpretq_u8_u32(ctr32)); \
            }())

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

        // 🚀 AES-256: 13번의 aes/aesmc 수행
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

        // vst1q_u8(dest, ct0);
        // vst1q_u8(dest + 16, ct1);
        // vst1q_u8(dest + 32, ct2);
        // vst1q_u8(dest + 48, ct3);

        // 🚀 [캐시 최적화] Non-Temporal (Streaming) Store
        // L3 캐시(2MB)를 우회하여 DRAM으로 직행, OS 및 ROS2 필수 데이터의 캐시 방출(Eviction) 방지
        
        uint64x2_t ct0_64 = vreinterpretq_u64_u8(ct0);
        __builtin_nontemporal_store(vgetq_lane_u64(ct0_64, 0), (uint64_t*)(dest));
        __builtin_nontemporal_store(vgetq_lane_u64(ct0_64, 1), (uint64_t*)(dest + 8));

        uint64x2_t ct1_64 = vreinterpretq_u64_u8(ct1);
        __builtin_nontemporal_store(vgetq_lane_u64(ct1_64, 0), (uint64_t*)(dest + 16));
        __builtin_nontemporal_store(vgetq_lane_u64(ct1_64, 1), (uint64_t*)(dest + 24));

        uint64x2_t ct2_64 = vreinterpretq_u64_u8(ct2);
        __builtin_nontemporal_store(vgetq_lane_u64(ct2_64, 0), (uint64_t*)(dest + 32));
        __builtin_nontemporal_store(vgetq_lane_u64(ct2_64, 1), (uint64_t*)(dest + 40));

        uint64x2_t ct3_64 = vreinterpretq_u64_u8(ct3);
        __builtin_nontemporal_store(vgetq_lane_u64(ct3_64, 0), (uint64_t*)(dest + 48));
        __builtin_nontemporal_store(vgetq_lane_u64(ct3_64, 1), (uint64_t*)(dest + 56));

        uint8x16_t t0 = veorq_u8(current_hash, ct0);
        
        uint8x16_t h0 = gf_mul_arm(t0, hash_key4);
        uint8x16_t h1 = gf_mul_arm(ct1, hash_key3);
        uint8x16_t h2 = gf_mul_arm(ct2, hash_key2);
        uint8x16_t h3 = gf_mul_arm(ct3, hash_key);
        
        current_hash = veorq_u8(veorq_u8(h0, h1), veorq_u8(h2, h3));
#endif
    }

    inline __attribute__((always_inline)) void decrypt_64bytes_fused(const uint8_t* src, uint8_t* dest) {

#if defined(__aarch64__)
        uint8x16_t ct0 = vld1q_u8(src);
        uint8x16_t ct1 = vld1q_u8(src + 16);
        uint8x16_t ct2 = vld1q_u8(src + 32);
        uint8x16_t ct3 = vld1q_u8(src + 48);

        uint8x16_t t0 = veorq_u8(current_hash, ct0);
        
        uint8x16_t h0 = gf_mul_arm(t0, hash_key4);
        uint8x16_t h1 = gf_mul_arm(ct1, hash_key3);
        uint8x16_t h2 = gf_mul_arm(ct2, hash_key2);
        uint8x16_t h3 = gf_mul_arm(ct3, hash_key);
        
        current_hash = veorq_u8(veorq_u8(h0, h1), veorq_u8(h2, h3));

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

        // 🚀 AES-256: 13번의 aes/aesmc 수행
        AES_ROUND_4X_ARM(1); AES_ROUND_4X_ARM(2); AES_ROUND_4X_ARM(3);
        AES_ROUND_4X_ARM(4); AES_ROUND_4X_ARM(5); AES_ROUND_4X_ARM(6);
        AES_ROUND_4X_ARM(7); AES_ROUND_4X_ARM(8); AES_ROUND_4X_ARM(9);
        AES_ROUND_4X_ARM(10); AES_ROUND_4X_ARM(11); AES_ROUND_4X_ARM(12);
        AES_ROUND_4X_ARM(13);
        
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
#endif
    }

    inline __attribute__((always_inline)) void finalize(size_t aad_len, size_t payload_len, uint8_t* out_tag) {
        alignas(16) uint64_t len_blk[2] = {
            __builtin_bswap64((uint64_t)aad_len * 8), 
            __builtin_bswap64((uint64_t)payload_len * 8)
        };
#if defined(__aarch64__)
        current_hash = gf_mul_arm(veorq_u8(current_hash, vld1q_u8((uint8_t*)len_blk)), hash_key);
        vst1q_u8(out_tag, veorq_u8(current_hash, tag_mask));
#endif
    }

    inline __attribute__((always_inline)) bool verify_tag(size_t aad_len, size_t payload_len, const uint8_t* expected_tag) {
        alignas(16) uint8_t computed_tag[16];
        finalize(aad_len, payload_len, computed_tag);
        
#if defined(__aarch64__)
        uint8x16_t comp = vld1q_u8(computed_tag);
        uint8x16_t exp = vld1q_u8(expected_tag);
        uint8x16_t diff_vec = veorq_u8(comp, exp);
        
        uint64x2_t diff64 = vreinterpretq_u64_u8(diff_vec);
        uint64_t val = vgetq_lane_u64(diff64, 0) | vgetq_lane_u64(diff64, 1);
        return (val == 0);
#endif
    }
};