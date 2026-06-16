#pragma once
#include <cstdint>

#pragma pack(push, 1)
struct ThunkHeader {
    uint32_t magic_flag;     // 4 Bytes: 0xDEADBEEF
    uint32_t real_size;      // 4 Bytes: 실제 데이터 크기 (예: 8388608)
    uint64_t memory_ptr;     // 8 Bytes: Unified Memory 상의 8MB 데이터 주소
    uint8_t  mac_tag[16];    // 16 Bytes: GPU가 생성한 AES-GCM 무결성 태그
};
#pragma pack(pop)

static_assert(sizeof(ThunkHeader) == 32, "ThunkHeader MUST be exactly 32 bytes!");