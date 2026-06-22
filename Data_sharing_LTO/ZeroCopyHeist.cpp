#include <security/cryptography/AESGCMGMAC_KeyFactory.h>
#include <security/cryptography/AESGCMGMAC_Types.h>
#include <security/cryptography/AESGCMGMAC_Transform.h>

#include <array>
#include <cstring>
#include <cstdio>
#include <mutex>

using namespace eprosima::fastrtps::rtps::security;

extern "C" void stash_stolen_key(const uint8_t* key, const uint8_t* iv);

#ifndef PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED
#define PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED (1UL << 0)
#endif

// =====================================================================
// [Transmitter (TX) Phase 2] Public Sender Key ID based synchronization
// =====================================================================
extern "C" void steal_and_bake_key(void* raw_handle) {
    if (raw_handle == nullptr) return;
    AESGCMGMAC_WriterCryptoHandle* local_writer = static_cast<AESGCMGMAC_WriterCryptoHandle*>(raw_handle);
    if (local_writer->nil()) return;

    std::unique_lock<std::mutex> lock((*local_writer)->mutex_);
    
    uint32_t attrs = (*local_writer)->EndpointPluginAttributes;
    if ((attrs & PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED) == 0) return;

    if ((*local_writer)->EntityKeyMaterial.empty()) return;
    auto& keyMat = (*local_writer)->EntityKeyMaterial.back();

    // Extract the public identifier (sender_key_id) instead of the secret key
    uint32_t deterministic_sync_id = 0;
    std::memcpy(&deterministic_sync_id, keyMat.sender_key_id.data(), 4);

    std::array<uint8_t, 32> precomputed_session_key;
    AESGCMGMAC_Transform temp_transform;
    temp_transform.compute_sessionkey(precomputed_session_key, keyMat, deterministic_sync_id);

    // Base IV construction: [4 Bytes: Public Sender ID] + [8 Bytes: 0 (Reserved for acceleration engine counter)]
    std::array<uint8_t, 12> iv = {0};
    std::memcpy(iv.data(), &deterministic_sync_id, 4);
    
    stash_stolen_key(precomputed_session_key.data(), iv.data());

}

// =====================================================================
// [Receiver (RX) Phase 4] Public Sender Key ID based synchronization
// =====================================================================
extern "C" void steal_and_bake_key_rx(void* raw_handle) {
    if (raw_handle == nullptr) return;
    
    DatawriterCryptoHandle* base_handle = static_cast<DatawriterCryptoHandle*>(raw_handle);
    AESGCMGMAC_WriterCryptoHandle& remote_writer = AESGCMGMAC_WriterCryptoHandle::narrow(*base_handle);
    if (remote_writer.nil()) return;

    std::unique_lock<std::mutex> lock(remote_writer->mutex_);
    
    uint32_t attrs = remote_writer->EndpointPluginAttributes;
    if ((attrs & PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED) == 0) return;

    // The receiver references the Key Material of the Remote Writer
    if (remote_writer->Entity2RemoteKeyMaterial.empty()) return;
    auto& keyMat = remote_writer->Entity2RemoteKeyMaterial.back();

    // Extract the public identifier (sender_key_id) identically on the receiver side
    uint32_t deterministic_sync_id = 0;
    std::memcpy(&deterministic_sync_id, keyMat.sender_key_id.data(), 4);

    std::array<uint8_t, 32> precomputed_session_key;
    AESGCMGMAC_Transform temp_transform;
    temp_transform.compute_sessionkey(precomputed_session_key, keyMat, deterministic_sync_id);

    // Base IV construction: [4 Bytes: Public Sender ID] + [8 Bytes: 0 (Reserved for acceleration engine counter)]
    std::array<uint8_t, 12> iv = {0};
    std::memcpy(iv.data(), &deterministic_sync_id, 4);
    
    stash_stolen_key(precomputed_session_key.data(), iv.data());

}