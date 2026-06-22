#include "FusedCryptoPayload.h"
#include <string.h>
#include <stdio.h> 
#include <array>
#include <atomic> 

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
// [Phase 1 Connection Point] Change the ownership of the wormhole storage to this .so file!
// =========================================================================
struct ZeroCopyCryptoContext {
    std::array<uint8_t, 32> precomputed_session_key;
    std::array<uint8_t, 12> initialization_vector;
    std::atomic<bool> is_ready{false}; // Lock-free synchronization
};

__attribute__((visibility("default"))) ZeroCopyCryptoContext g_zero_copy_ctx;

// Internal helper function
inline __attribute__((always_inline)) void tx_generate_keystream() {
    g_crypto_engine.generate_keystream_128bytes_arm(tx_keystream_buf); 
    tx_ks_pos = 0;
}

extern "C" {
    
    // [New Receiver Part] FastDDS's ZeroCopyHeist injects the stolen key here.
    __attribute__((visibility("default"))) 
    void stash_stolen_key(const uint8_t* key, const uint8_t* iv) {
        memcpy(g_zero_copy_ctx.precomputed_session_key.data(), key, 32);
        memcpy(g_zero_copy_ctx.initialization_vector.data(), iv, 12);
        g_zero_copy_ctx.is_ready.store(true, std::memory_order_release); // Armed and ready!
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

    // 💡 [Hardware Safety Fix] Use a dedicated atomic counter instead of pointer casting.
    // This prevents strict aliasing violations and guarantees safe memory alignment on ARM.
    static std::atomic<uint64_t> g_tx_iv_counter{1};

    __attribute__((noinline, used))
    void fuse_inline_enc_memcpy(uint8_t* dest, const uint8_t* src, size_t len) {
        asm volatile("" ::: "memory");
        bool auto_ignited = false;

        // [TX Modification] Save the IV counter acquired by this thread context into a local variable.
        uint64_t my_tx_iv = 0;

        if (!g_fuse_active) {
            if (g_zero_copy_ctx.is_ready.load(std::memory_order_acquire)) {
                
                // 1. Atomically acquire a unique, monotonically increasing counter for this payload.
                // memory_order_relaxed is sufficient here because it only guarantees uniqueness.
                my_tx_iv = g_tx_iv_counter.fetch_add(1, std::memory_order_relaxed);
                
                // 2. Construct the 12-byte IV in a local array to prevent concurrency race conditions.
                alignas(16) uint8_t temp_iv[12] = {0};
                
                // [Spatial Separation] 4 Bytes: Copy the Public Sender ID derived from the Master Sender Key.
                // This guarantees zero IV collisions between different Writer instances.
                memcpy(temp_iv, g_zero_copy_ctx.initialization_vector.data(), 4); 
                
                // [Temporal Separation] 8 Bytes: Append the self-acquired atomic counter.
                // This guarantees zero IV collisions across time for the same Writer instance.
                memcpy(temp_iv + 4, &my_tx_iv, 8); 
                
                // 3. Initialize the hardware SIMD engine with the session key and the newly assembled IV.
                fuse_init(g_zero_copy_ctx.precomputed_session_key.data(), temp_iv);
                auto_ignited = true;
            } else {
                // [Fallback] If the crypto context is not yet armed, perform a standard memory copy.
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
            // [Modification] Removed the dummy_tag discarded into the void, 
            // and write the actual MAC directly to the position right after the ciphertext ends in SHM (dest)!
            uint8_t* mac_dest_ptr = dest + len;
            fuse_finalize_enc(mac_dest_ptr); 

            // [Core Addition] Explicitly write the IV counter (8 bytes) used by TX right behind the MAC (16 bytes)!
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
    // [Receiver State Buffer] Allocation of an independent RX buffer for decryption
    // =========================================================================
    __attribute__((visibility("default"), aligned(16))) uint8_t rx_keystream_buf[128] = {0}; 
    __attribute__((visibility("default"), aligned(16))) uint8_t rx_gmac_buf[128] = {0};      
    __attribute__((visibility("default"))) uint8_t rx_ks_pos = 128;   
    __attribute__((visibility("default"))) uint8_t rx_gmac_pos = 0;
}

// Keystream generation helper for the receiver
inline __attribute__((always_inline)) void rx_generate_keystream() {
    g_crypto_engine.generate_keystream_128bytes_arm(rx_keystream_buf); 
    rx_ks_pos = 0;
}

extern "C" {

    // AAD (Additional Authenticated Data) processing is identical for encryption/decryption, so just provide a wrapper
    void fuse_update_dec(const uint8_t* src, size_t len) {
        fuse_update_enc(src, nullptr, len);
    }

    // =========================================================================
    // [Inline Decryption Hook] Accumulate ciphertext (CT) into GMAC first, then return plaintext (PT)
    // =========================================================================
    uint8_t fuse_inline_dec_8(uint8_t ct) {
        if (!g_fuse_active) return ct;
        if (rx_ks_pos == 128) rx_generate_keystream();
        
        // CRITICAL: AES-GCM decryption must accumulate the raw incoming ciphertext (CT)
        rx_gmac_buf[rx_gmac_pos++] = ct;
        if (rx_gmac_pos == 128) {
             for(int i=0; i<8; i++) g_crypto_engine.accumulate_gmac(rx_gmac_buf + i*16);
             rx_gmac_pos = 0;
        }
        
        // After accumulation, XOR with the Keystream to derive plaintext (PT)
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
    // [Large Data Decryption Hook] Thunk Payload and Variable Data Processing
    // =========================================================================
    // =====================================================================
    // [Receiver (RX) Fusion] SHM -> Local Memory Decryption Function
    // =====================================================================
    extern "C" __attribute__((noinline, used))
    void fuse_inline_dec_memcpy(uint8_t* dest, const uint8_t* src, size_t len) {
        
        asm volatile("" ::: "memory");
        bool auto_ignited = false;

        if (!g_fuse_active) {
            // What if the real key hasn't arrived yet? (Asynchronous Handling)
            if (g_zero_copy_ctx.is_ready.load(std::memory_order_acquire)) {
                
                // [RX Core Modification] Instead of incrementing the counter on our own, 
                // steal the exact IV sequence number written by TX at the SHM tail (len + 16 bytes location)!
                uint64_t rx_explicit_iv = 0;
                memcpy(&rx_explicit_iv, src + len + 16, sizeof(uint64_t));

                uint8_t temp_iv[12] = {0};
                memcpy(temp_iv, g_zero_copy_ctx.initialization_vector.data(), 4);
                memcpy(temp_iv + 4, &rx_explicit_iv, 8); // Setup the exact same IV as TX!
                
                fuse_init(g_zero_copy_ctx.precomputed_session_key.data(), temp_iv);
                auto_ignited = true;
            } else {
                // Asynchronous dilemma perfectly overcome! Drop the initial 1-2 frames by filling them with 0 until the key arrives. (Prevents garbage data values)
                static bool wait_msg = false;
                if (!wait_msg) {
                    printf("\n[DEBUG RX]  Waiting Asynchronous Key exchange \n\n");
                    wait_msg = true;
                }
                memset(dest, 0, len); 
                asm volatile("" ::: "memory");
                return;
            }
        }

        size_t offset = 0;

        // =====================================================================
        // [NEON Blast] Direct 128-byte decryption acceleration update!
        // =====================================================================
        if (tx_gmac_pos == 0 && tx_ks_pos == 128) {
            // 1. 128-byte unit ultra-fast decryption (Applying your newly added function!)
            while (offset + 128 <= len) {
                g_crypto_engine.decrypt_128bytes_fused_arm(src + offset, dest + offset);
                offset += 128;
                tl_payload_len += 128;
            }
            // 2. 64-byte unit decryption
            while (offset + 64 <= len) {
                g_crypto_engine.decrypt_64bytes_fused(src + offset, dest + offset);
                offset += 64;
                tl_payload_len += 64;
            }
            // 3. 16-byte unit decryption
            while (offset + 16 <= len) {
                g_crypto_engine.decrypt_16bytes_fused(src + offset, dest + offset);
                offset += 16;
                tl_payload_len += 16;
            }
        }
        
        // =====================================================================
        // [Tail Block] Process remaining trailing alignment fragments
        // =====================================================================
        size_t tail_len = len - offset;
        if (tail_len > 0) {
            g_crypto_engine.decrypt_tail_fused(src + offset, dest + offset, tail_len);
            tl_payload_len += tail_len;
        }

        // =====================================================================
        // [Engine Cleanup & MAC Integrity Verification] 
        // =====================================================================
        if (auto_ignited) {
            // 1. Point to the 16-byte MAC tag located right behind the SHM ciphertext (src + len).
            const uint8_t* expected_mac_ptr = src + len;
            
            // 2. Instruct the AES-GCM engine to verify if the decrypted data matches this tag!
            bool is_mac_valid = fuse_verify_dec(expected_mac_ptr);

            if (!is_mac_valid) {
                // 3. [Anti-Tamper Countermeasure] MAC verification failed! (Data tampered or key mismatch)
                printf("\n[ERROR RX]  Fail to verify MAC \n\n");
                // Clear memory to zero so the local application doesn't read corrupted garbage data.
                memset(dest, 0, len); 
            } 
        }

        asm volatile("" ::: "memory");
    }
    
    // =========================================================================
    // [Tag Verification] Final confirmation of incoming ciphertext integrity
    // =========================================================================
    bool fuse_verify_dec(const uint8_t* expected_tag) {
        size_t processed = 0;
        
        // Accumulate remaining ciphertext fragments left in the residual buffer into GHASH
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