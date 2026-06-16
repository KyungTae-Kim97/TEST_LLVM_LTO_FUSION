#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp> // 추가
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>
#include <fastdds/dds/topic/Topic.hpp>              // 추가
#include <cuda_runtime.h>
#include <iostream>
#include <iomanip>
#include <thread>

#include "ThunkPubSubType.hpp"

using namespace eprosima::fastdds::dds;

// 🌟 CUDA 엔진과 통신하기 위한 C 브릿지 (parallel_gcm.cu 에 구현되어 있어야 함)
extern "C" void init_gpu_crypto_engine();
extern "C" void run_gpu_gcm(uint8_t* d_data, size_t total_bytes, uint8_t* out_mac, cudaStream_t stream);

struct HeavyImage { uint8_t data[8 * 1024 * 1024]; };

int main() {
    std::cout << "[Fused Publisher] Initializing Hardware Crypto Engine..." << std::endl;
    init_gpu_crypto_engine(); // 상수 메모리 (H의 거듭제곱 등) 세팅

    DomainParticipant* participant = DomainParticipantFactory::get_instance()->create_participant(0, PARTICIPANT_QOS_DEFAULT);
    TypeSupport thunk_type(new ThunkPubSubType<HeavyImage>());
    thunk_type.register_type(participant);

    Publisher* publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT, nullptr);
    Topic* topic = participant->create_topic("V2X_Camera_Stream", thunk_type.get_type_name(), TOPIC_QOS_DEFAULT);
    DataWriter* writer = publisher->create_datawriter(topic, DATAWRITER_QOS_DEFAULT, nullptr);

    std::cout << "[Fused Publisher] Waiting for Subscriber matching..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // =========================================================================
    // 💡 1. 통합 메모리(Unified Memory) 할당 및 시뮬레이션
    // =========================================================================
    HeavyImage* unified_image;
    cudaMallocManaged(&unified_image, sizeof(HeavyImage));
    std::memset(unified_image->data, 0xAA, sizeof(HeavyImage)); // 카메라 원본 데이터 모사

    uint8_t* d_final_mac;
    cudaMallocManaged(&d_final_mac, 16); // MAC 태그도 통합 메모리에 올려 CPU가 바로 읽게 함

    cudaStream_t compute_stream;
    cudaStreamCreate(&compute_stream);

    std::cout << "\n---------------------------------------------------" << std::endl;
    std::cout << "🎯 UNIFIED IMAGE PTR : 0x" << std::hex << reinterpret_cast<uint64_t>(unified_image) << std::dec << std::endl;

    // =========================================================================
    // 💡 2. GPU GCM 암호화 및 무결성 태그 생성 (비동기)
    // =========================================================================
    run_gpu_gcm(unified_image->data, sizeof(HeavyImage), d_final_mac, compute_stream);
    
    // 이 시점에서 GPU가 1.9ms 동안 연산하는 것을 기다립니다.
    // (실제 시스템에서는 여기서 CPU가 다음 프레임을 준비하거나 네트워크 헤더를 조립합니다)
    cudaStreamSynchronize(compute_stream);

    std::cout << "🎯 GENERATED MAC TAG : 0x";
    for(int i=0; i<16; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)d_final_mac[i];
    std::cout << std::dec << "\n";

    // =========================================================================
    // 💡 3. Thunk 조립 및 32바이트 Zero-Copy 전송
    // =========================================================================
    ThunkHeader my_thunk;
    my_thunk.magic_flag = 0xDEADBEEF;
    my_thunk.real_size = sizeof(HeavyImage);
    my_thunk.memory_ptr = reinterpret_cast<uint64_t>(unified_image);
    std::memcpy(my_thunk.mac_tag, d_final_mac, 16);

    // Fast-DDS는 8MB를 읽지 않고 오직 my_thunk 구조체(32바이트)만 읽어서 전송합니다.
    writer->write(static_cast<void*>(&my_thunk));
    std::cout << "[Fused Publisher] 32-byte Authenticated Thunk Dispatched!" << std::endl;
    std::cout << "---------------------------------------------------\n" << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(1));

    cudaFree(unified_image); cudaFree(d_final_mac); cudaStreamDestroy(compute_stream);
    participant->delete_contained_entities();
    DomainParticipantFactory::get_instance()->delete_participant(participant);

    return 0;
}