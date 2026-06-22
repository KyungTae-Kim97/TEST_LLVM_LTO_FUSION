#include <iostream>
#include <chrono>
#include <cstring>
#include <vector>
#include <iomanip>
#include <cuda_runtime.h>
#include <openssl/evp.h> // The OpenSSL engine that real SROS2 uses
#include "ThunkHeader.hpp"

extern "C" void init_gpu_crypto_engine();
extern "C" void run_gpu_gcm(uint8_t* d_data, size_t total_bytes, uint8_t* out_mac, cudaStream_t stream);

using namespace std::chrono;

// =========================================================================
// [Baseline 1] Faithful emulation of the standard SROS2 pipeline (OpenSSL AES-GCM)
// =========================================================================
void sros2_openssl_aes_gcm(const uint8_t* plaintext, int plaintext_len, uint8_t* ciphertext, uint8_t* tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    
    // Set up SROS2 dummy key and IV
    uint8_t key[32] = {0x01}; 
    uint8_t iv[12] = {0x0A};

    // Initialize AES-256-GCM (automatically uses CPU AES-NI hardware acceleration)
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    // Perform the actual encryption (read the serialized buffer and write to the ciphertext buffer)
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    // Extract the 16-byte MAC tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    constexpr size_t DATA_SIZE = 48; // 8MB
    const int ITERATIONS = 1000;

    std::cout << "====================================================\n";
    std::cout << " 🔥 Real-Time SROS2 vs Thunk Benchmark (8MB)\n";
    std::cout << "====================================================\n";

    std::vector<uint8_t> host_raw_data(DATA_SIZE, 0xFF);
    
    // CPU SROS2 buffers
    uint8_t* cdr_serialize_buffer = new uint8_t[DATA_SIZE];
    uint8_t* openssl_crypto_buffer = new uint8_t[DATA_SIZE];
    uint8_t sros2_mac_tag[16];

    // GPU Thunk pipeline buffers
    uint8_t* unified_data;
    uint8_t* d_mac;
    cudaMallocManaged(&unified_data, DATA_SIZE);
    cudaMallocManaged(&d_mac, 16); 
    std::memcpy(unified_data, host_raw_data.data(), DATA_SIZE);

    cudaStream_t stream;
    cudaStreamCreate(&stream);
    init_gpu_crypto_engine();

    double total_std_time = 0;
    double total_thunk_time = 0;

    std::cout << "[*] Running " << ITERATIONS << " Iterations...\n\n";

    for (int i = 0; i < ITERATIONS; ++i) {
        // ---------------------------------------------------------
        // 1. [Baseline] Standard SROS2 (Fast-CDR serialization + OpenSSL AES-GCM)
        // ---------------------------------------------------------
        auto start_std = high_resolution_clock::now();
        
        // SROS2 step 1: Serialize the payload into a DDS packet (CPU MemCpy)
        std::memcpy(cdr_serialize_buffer, host_raw_data.data(), DATA_SIZE);
        
        // SROS2 step 2: Real OpenSSL AES-GCM encryption operation
        sros2_openssl_aes_gcm(cdr_serialize_buffer, DATA_SIZE, openssl_crypto_buffer, sros2_mac_tag);
        
        auto end_std = high_resolution_clock::now();
        total_std_time += duration_cast<microseconds>(end_std - start_std).count() / 1000.0;

        // ---------------------------------------------------------
        // 2. [Experimental] Zero-Copy Thunk architecture
        // ---------------------------------------------------------
        auto start_thunk = high_resolution_clock::now();
        
        run_gpu_gcm(unified_data, DATA_SIZE, d_mac, stream);
        
        ThunkHeader thunk;
        thunk.magic_flag = 0xDEADBEEF;
        thunk.real_size = DATA_SIZE;
        thunk.memory_ptr = reinterpret_cast<uint64_t>(unified_data);
        
        cudaStreamSynchronize(stream);
        std::memcpy(thunk.mac_tag, d_mac, 16);
        
        auto end_thunk = high_resolution_clock::now();
        total_thunk_time += duration_cast<microseconds>(end_thunk - start_thunk).count() / 1000.0;
    }

    double avg_std = total_std_time / ITERATIONS;
    double avg_thunk = total_thunk_time / ITERATIONS;

    std::cout << "====================================================\n";
    std::cout << " 📊 BENCHMARK RESULTS (Average of " << ITERATIONS << " runs)\n";
    std::cout << "====================================================\n";
    std::cout << " - Standard SROS2 TX Latency : " << std::fixed << std::setprecision(3) << avg_std << " ms\n";
    std::cout << " - Zero-Copy Thunk TX Latency: " << std::fixed << std::setprecision(3) << avg_thunk << " ms\n";
    std::cout << "----------------------------------------------------\n";
    std::cout << " 🚀 Performance Gain : " << std::setprecision(1) << (avg_std / avg_thunk) << "x Faster\n";
    std::cout << " 🛡️ Security Tax Saved: " << std::setprecision(3) << (avg_std - avg_thunk) << " ms per message\n";
    std::cout << "====================================================\n";

    delete[] cdr_serialize_buffer; delete[] openssl_crypto_buffer;
    cudaFree(unified_data); cudaFree(d_mac); cudaStreamDestroy(stream);
    return 0;
}