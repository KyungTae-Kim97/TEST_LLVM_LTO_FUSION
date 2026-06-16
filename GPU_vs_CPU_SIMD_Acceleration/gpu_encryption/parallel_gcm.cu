#include <iostream>
#include <vector>
#include <cuda_runtime.h>
#include <cstring>
#include <iomanip>
#include <cstdint>  // <--- Add this line

// 에러 체크 매크로 (커널이 죽거나 메모리 복사 실패 시 즉각 원인 출력)
#define CUDA_CHECK(call) \
    do { \
        cudaError_t err = call; \
        if (err != cudaSuccess) { \
            std::cerr << "CUDA Error: " << cudaGetErrorString(err) << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            exit(EXIT_FAILURE); \
        } \
    } while(0)

// =========================================================================
// [1] GPU 상수 메모리 (__constant__)
// =========================================================================
__constant__ uint8_t d_sbox[256];
__constant__ uint8_t d_round_keys[240];
__constant__ uint8_t d_iv[12];
__constant__ uint64_t d_h_pow_hi[32];
__constant__ uint64_t d_h_pow_lo[32];

static const uint8_t h_sbox[256] = {
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

// =========================================================================
// [2] 공통 유틸리티 (Device & Host 동일 로직)
// =========================================================================
__host__ __device__ inline void bytes_to_uint64(const uint8_t* in, uint64_t& hi, uint64_t& lo) {
    hi = ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48) | ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32) |
         ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16) | ((uint64_t)in[6] << 8)  | ((uint64_t)in[7]);
    lo = ((uint64_t)in[8] << 56) | ((uint64_t)in[9] << 48) | ((uint64_t)in[10] << 40) | ((uint64_t)in[11] << 32) |
         ((uint64_t)in[12] << 24) | ((uint64_t)in[13] << 16) | ((uint64_t)in[14] << 8) | ((uint64_t)in[15]);
}

__host__ __device__ inline void uint64_to_bytes(uint64_t hi, uint64_t lo, uint8_t* out) {
    out[0] = hi >> 56; out[1] = hi >> 48; out[2] = hi >> 40; out[3] = hi >> 32;
    out[4] = hi >> 24; out[5] = hi >> 16; out[6] = hi >> 8;  out[7] = hi;
    out[8] = lo >> 56; out[9] = lo >> 48; out[10] = lo >> 40; out[11] = lo >> 32;
    out[12] = lo >> 24; out[13] = lo >> 16; out[14] = lo >> 8; out[15] = lo;
}

// 🌟 핵심: 무리한 언롤링 제거 (레지스터 스필링 방지)
__host__ __device__ inline void gf_mul_64(uint64_t a_hi, uint64_t a_lo, uint64_t b_hi, uint64_t b_lo, uint64_t& res_hi, uint64_t& res_lo) {
    res_hi = 0; res_lo = 0;
    uint64_t v_hi = b_hi, v_lo = b_lo;

    for (int i = 0; i < 128; i++) {
        uint64_t bit = (i < 64) ? ((a_hi >> (63 - i)) & 1) : ((a_lo >> (127 - i)) & 1);
        if (bit) {
            res_hi ^= v_hi;
            res_lo ^= v_lo;
        }
        uint64_t lsb = v_lo & 1;
        v_lo = (v_hi << 63) | (v_lo >> 1);
        v_hi = (v_hi >> 1);
        if (lsb) v_hi ^= 0xE100000000000000ULL;
    }
}

// =========================================================================
// [3] 기밀성 엔진: AES-CTR 블록 암호화 (Device)
// =========================================================================
__device__ inline uint8_t galois_mul2(uint8_t x) { return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00); }

__device__ void aes256_encrypt_block_cuda(uint8_t* state) {
    for (int i = 0; i < 16; ++i) state[i] ^= d_round_keys[i];
    
    #pragma unroll
    for (int round = 1; round < 14; ++round) {
        for (int i = 0; i < 16; ++i) state[i] = d_sbox[state[i]];
        uint8_t t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
        uint8_t t2 = state[2]; state[2] = state[10]; state[10] = t2; t2 = state[6]; state[6] = state[14]; state[14] = t2;
        uint8_t t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;
        for (int c = 0; c < 4; ++c) {
            uint8_t* col = state + c * 4;
            uint8_t s0 = col[0], s1 = col[1], s2 = col[2], s3 = col[3];
            uint8_t tmp = s0 ^ s1 ^ s2 ^ s3;
            col[0] = s0 ^ tmp ^ galois_mul2(s0 ^ s1); col[1] = s1 ^ tmp ^ galois_mul2(s1 ^ s2);
            col[2] = s2 ^ tmp ^ galois_mul2(s2 ^ s3); col[3] = s3 ^ tmp ^ galois_mul2(s3 ^ s0);
        }
        for (int i = 0; i < 16; ++i) state[i] ^= d_round_keys[round * 16 + i];
    }
    
    for (int i = 0; i < 16; ++i) state[i] = d_sbox[state[i]];
    uint8_t t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
    uint8_t t2 = state[2]; state[2] = state[10]; state[10] = t2; t2 = state[6]; state[6] = state[14]; state[14] = t2;
    uint8_t t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;
    for (int i = 0; i < 16; ++i) state[i] ^= d_round_keys[14 * 16 + i];
}

// =========================================================================
// [4] 커널 1: 암호화 및 블록 레벨 트리 축약 (Level 0 ~ 7)
// =========================================================================
__global__ void aes_gcm_pass1_kernel(uint8_t* data, uint64_t* out_partial_hi, uint64_t* out_partial_lo) {
    int tid = threadIdx.x; 
    size_t global_idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    __shared__ uint64_t shm_hi[256];
    __shared__ uint64_t shm_lo[256];

    // --- 1. 암호화 ---
    alignas(16) uint8_t state[16];
    for (int j = 0; j < 12; ++j) state[j] = d_iv[j];
    
    uint32_t counter = 2 + global_idx; 
    state[12] = (counter >> 24) & 0xFF; state[13] = (counter >> 16) & 0xFF;
    state[14] = (counter >> 8)  & 0xFF; state[15] = counter & 0xFF;

    aes256_encrypt_block_cuda(state);

    uint4* data_ptr = reinterpret_cast<uint4*>(data + (global_idx * 16));
    uint4 state_vec = *reinterpret_cast<uint4*>(state);
    uint4 orig = *data_ptr;
    
    orig.x ^= state_vec.x; orig.y ^= state_vec.y; orig.z ^= state_vec.z; orig.w ^= state_vec.w;
    *data_ptr = orig; 

    // --- 2. Leaf 초기화 ---
    uint64_t c_hi, c_lo;
    bytes_to_uint64(reinterpret_cast<uint8_t*>(&orig), c_hi, c_lo);
    gf_mul_64(c_hi, c_lo, d_h_pow_hi[0], d_h_pow_lo[0], shm_hi[tid], shm_lo[tid]);
    __syncthreads();

    // --- 3. 트리의 완벽한 매핑 로직 (Bug Fixed!) ---
    for (int s = 0; s < 8; s++) {
        int stride = 1 << s;
        // 🌟 스레드 ID가 0, 1, 2... 순서대로 정확히 짝을 지어 처리하도록 개선
        int index = 2 * stride * tid; 
        
        if (index < 256) {
            uint64_t temp_hi, temp_lo;
            gf_mul_64(shm_hi[index], shm_lo[index], d_h_pow_hi[s], d_h_pow_lo[s], temp_hi, temp_lo);
            shm_hi[index] = temp_hi ^ shm_hi[index + stride];
            shm_lo[index] = temp_lo ^ shm_lo[index + stride];
        }
        __syncthreads();
    }

    if (tid == 0) {
        out_partial_hi[blockIdx.x] = shm_hi[0];
        out_partial_lo[blockIdx.x] = shm_lo[0];
    }
}

// =========================================================================
// [5] 커널 2: 글로벌 레벨 트리 축약 (Level 8 ~ 18)
// =========================================================================
__global__ void aes_gcm_pass2_kernel(uint64_t* in_partial_hi, uint64_t* in_partial_lo, uint8_t* final_mac) {
    int tid = threadIdx.x; 
    
    __shared__ uint64_t shm_hi[2048];
    __shared__ uint64_t shm_lo[2048];

    shm_hi[tid] = in_partial_hi[tid];               shm_lo[tid] = in_partial_lo[tid];
    shm_hi[tid + 1024] = in_partial_hi[tid + 1024]; shm_lo[tid + 1024] = in_partial_lo[tid + 1024];
    __syncthreads();

    // 🌟 안전하게 수정된 Reduction 트리
    for (int s = 8; s <= 18; s++) {
        int stride = 1 << (s - 8);
        int index = 2 * stride * tid;
        
        if (index < 2048) {
            uint64_t temp_hi, temp_lo;
            gf_mul_64(shm_hi[index], shm_lo[index], d_h_pow_hi[s], d_h_pow_lo[s], temp_hi, temp_lo);
            shm_hi[index] = temp_hi ^ shm_hi[index + stride];
            shm_lo[index] = temp_lo ^ shm_lo[index + stride];
        }
        __syncthreads();
    }

    if (tid == 0) {
        uint64_to_bytes(shm_hi[0], shm_lo[0], final_mac);
    }
}

// =========================================================================
// [6] Host 측 초기화 (Precomputation)
// =========================================================================
void host_expand_key(const uint8_t* key, uint8_t* expanded_key) {
    static const uint8_t rcon[7] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };
    memcpy(expanded_key, key, 32);
    int bytes_gen = 32, rcon_idx = 0;
    while (bytes_gen < 240) {
        uint8_t temp[4]; memcpy(temp, &expanded_key[bytes_gen - 4], 4);
        if (bytes_gen % 32 == 0) {
            uint8_t t = temp[0]; temp[0] = h_sbox[temp[1]] ^ rcon[rcon_idx++];
            temp[1] = h_sbox[temp[2]]; temp[2] = h_sbox[temp[3]]; temp[3] = h_sbox[t];
        } else if (bytes_gen % 32 == 16) {
            temp[0] = h_sbox[temp[0]]; temp[1] = h_sbox[temp[1]]; temp[2] = h_sbox[temp[2]]; temp[3] = h_sbox[temp[3]];
        }
        for (int j = 0; j < 4; ++j) expanded_key[bytes_gen++] = expanded_key[bytes_gen - 32 - 1] ^ temp[j];
    }
}

void precompute_h_powers(uint8_t* h_key) {
    uint64_t cur_hi, cur_lo;
    bytes_to_uint64(h_key, cur_hi, cur_lo);

    uint64_t h_pow_hi[32], h_pow_lo[32];
    h_pow_hi[0] = cur_hi; h_pow_lo[0] = cur_lo;

    for (int i = 1; i < 20; i++) {
        gf_mul_64(h_pow_hi[i-1], h_pow_lo[i-1], h_pow_hi[i-1], h_pow_lo[i-1], h_pow_hi[i], h_pow_lo[i]);
    }

    CUDA_CHECK(cudaMemcpyToSymbol(d_h_pow_hi, h_pow_hi, sizeof(uint64_t) * 20));
    CUDA_CHECK(cudaMemcpyToSymbol(d_h_pow_lo, h_pow_lo, sizeof(uint64_t) * 20));
}

extern "C" {
    void init_gpu_crypto_engine() {
        uint8_t h_key[32] = {0x01}; uint8_t h_iv[12] = {0x0A};
        uint8_t h_hash_key[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        uint8_t h_expanded_key[240];
        host_expand_key(h_key, h_expanded_key);
        cudaMemcpyToSymbol(d_sbox, h_sbox, 256);
        cudaMemcpyToSymbol(d_round_keys, h_expanded_key, 240);
        cudaMemcpyToSymbol(d_iv, h_iv, 12);
        precompute_h_powers(h_hash_key);
    }

    void run_gpu_gcm(uint8_t* d_data, size_t total_bytes, uint8_t* out_mac, cudaStream_t stream) {
        int blocks_pass1 = total_bytes / 16 / 256;      
        uint64_t *d_partial_hi, *d_partial_lo;
        cudaMalloc(&d_partial_hi, blocks_pass1 * sizeof(uint64_t));
        cudaMalloc(&d_partial_lo, blocks_pass1 * sizeof(uint64_t));
        
        aes_gcm_pass1_kernel<<<blocks_pass1, 256, 0, stream>>>(d_data, d_partial_hi, d_partial_lo);
        aes_gcm_pass2_kernel<<<1, 1024, 0, stream>>>(d_partial_hi, d_partial_lo, out_mac);
        
        // 주의: 프로덕션 코드에서는 비동기 해제를 위해 메모리 풀(Pool)을 사용하지만, 
        // PoC 검증을 위해 동기화 후 해제합니다.
        cudaStreamSynchronize(stream); 
        cudaFree(d_partial_hi); cudaFree(d_partial_lo);
    }
}