#include "FusedCryptoPayload.h"
#include <string.h>
#include <stdio.h> 


extern "C" {
    __attribute__((visibility("default"))) FusedCryptoPayload g_crypto_engine;
    __attribute__((visibility("default"))) size_t tl_aad_len = 0;
    __attribute__((visibility("default"))) size_t tl_payload_len = 0;

    // [Core Switch] The unique global switch linking both spaces together
    __attribute__((visibility("default"))) bool g_fuse_active = false;

    // [Modification] Replaced alignas(16) with __attribute__((aligned(16))) inside the declaration for symbol merging
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
// Internal Helper Functions
// =========================================================================
inline __attribute__((always_inline)) void tx_generate_keystream() {
    // Invoke the dedicated 128-byte keystream generation function optimized for ARM architectures.
    g_crypto_engine.generate_keystream_128bytes_arm(tx_keystream_buf); 
    tx_ks_pos = 0; // Reset the index buffer once populated
}

extern "C" {
    // =====================================================================
    // Common Initialization
    // =====================================================================
    void fuse_init(const uint8_t* key, const uint8_t* iv) {
        g_crypto_engine.init(key, iv);
        tl_aad_len = 0;
        tl_payload_len = 0;
        
        // Reset the transmitter streaming state
        tx_ks_pos = 128; 
        tx_gmac_pos = 0;

        // Since this routine runs right after SROS2 finishes serializing the security header, 
        // LTO inline encryption is now activated.
        g_fuse_active = true;
    }

    // =====================================================================
    // Plugin-Level Bulk Encryption (Fallback for TX / Intended for AAD)
    // =====================================================================
    void fuse_update_enc(const uint8_t* src, uint8_t* dest, size_t len) {
        // If dest is not a nullptr, it indicates that the Security plugin has passed down a payload.
        // However, since we have already finalized encryption at the serialization phase via LTO, 
        // we return early to prevent double encryption.
        if (dest != nullptr) {
            return; 
        }

        // Process GHASH calculation only if dest == nullptr (implying AAD ingestion)
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
    // LLVM LTO Injection Interface - Inline Streaming Encryption
    // =====================================================================
    
    // 8-bit (1 byte) Inline Encryption
    uint8_t fuse_inline_enc_8(uint8_t pt) {
        if (!g_fuse_active) return pt;

        // Maximize branch prediction performance by optimizing for sequential execution paths
        if (tx_ks_pos == 128) tx_generate_keystream();

        uint8_t ct = pt ^ tx_keystream_buf[tx_ks_pos++];
        tx_gmac_buf[tx_gmac_pos++] = ct;
        
        // Accumulate GMAC hash blocks whenever 16 bytes (1 block) are filled
        if (tx_gmac_pos == 128) {
             for(int i=0; i<8; i++){
                 g_crypto_engine.accumulate_gmac(tx_gmac_buf + i*16);
             }
             tx_gmac_pos = 0;
        }

        tl_payload_len += 1;
        return ct;
    }

    // 16-bit (2 bytes) Inline Encryption
    uint16_t fuse_inline_enc_16(uint16_t pt) {
        if (!g_fuse_active) return pt;

        uint8_t* pt_bytes = (uint8_t*)&pt;
        uint16_t ct;
        uint8_t* ct_bytes = (uint8_t*)&ct;
        
        ct_bytes[0] = fuse_inline_enc_8(pt_bytes[0]);
        ct_bytes[1] = fuse_inline_enc_8(pt_bytes[1]);
        return ct;
    }

    // 32-bit (4 bytes) Inline Encryption
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

    // 64-bit (8 bytes) Inline Encryption
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
    // Inline Encryption Routines designed to override standard MemCpy structures
    // =====================================================================
    // Explicitly enforce C linkage name mangling prevention and disable compiler function optimizations
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
        // [NEON Acceleration] Removed fake header generation; direct payload acceleration.
        // Source and destination mappings align cleanly 1:1 with no offset tracking.
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
        // [Tail Block] Process residual trailing data blocks
        // =====================================================================
        size_t tail_len = len - offset;
        if (tail_len > 0) {
            g_crypto_engine.process_tail_fused(src + offset, dest + offset, tail_len);
            tl_payload_len += tail_len;
        }

        asm volatile("" ::: "memory");
    }
    
    // =====================================================================
    // Final Tag Serialization (Transmitter Context Only)
    // =====================================================================
    void fuse_finalize_enc(uint8_t* out_tag) {
        // Slice and process residual contents remaining inside the 128-byte tracking buffer into 16-byte chunks
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