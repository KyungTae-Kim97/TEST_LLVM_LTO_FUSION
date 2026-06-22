#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp> // added
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>
#include <fastdds/dds/topic/Topic.hpp>              // added
#include <cuda_runtime.h>
#include <iostream>
#include <iomanip>
#include <thread>

#include "ThunkPubSubType.hpp"

using namespace eprosima::fastdds::dds;

// C bridge for communicating with the CUDA engine (must be implemented in parallel_gcm.cu)
extern "C" void init_gpu_crypto_engine();
extern "C" void run_gpu_gcm(uint8_t* d_data, size_t total_bytes, uint8_t* out_mac, cudaStream_t stream);

struct HeavyImage { uint8_t data[8 * 1024 * 1024]; };

int main() {
    std::cout << "[Fused Publisher] Initializing Hardware Crypto Engine..." << std::endl;
    init_gpu_crypto_engine(); // Set up constant memory (powers of H, etc.)

    DomainParticipant* participant = DomainParticipantFactory::get_instance()->create_participant(0, PARTICIPANT_QOS_DEFAULT);
    TypeSupport thunk_type(new ThunkPubSubType<HeavyImage>());
    thunk_type.register_type(participant);

    Publisher* publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT, nullptr);
    Topic* topic = participant->create_topic("V2X_Camera_Stream", thunk_type.get_type_name(), TOPIC_QOS_DEFAULT);
    DataWriter* writer = publisher->create_datawriter(topic, DATAWRITER_QOS_DEFAULT, nullptr);

    std::cout << "[Fused Publisher] Waiting for Subscriber matching..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // =========================================================================
    // 1. Allocate Unified Memory and simulate
    // =========================================================================
    HeavyImage* unified_image;
    cudaMallocManaged(&unified_image, sizeof(HeavyImage));
    std::memset(unified_image->data, 0xAA, sizeof(HeavyImage)); // Mimic raw camera data

    uint8_t* d_final_mac;
    cudaMallocManaged(&d_final_mac, 16); // Put the MAC tag in Unified Memory too so the CPU can read it directly

    cudaStream_t compute_stream;
    cudaStreamCreate(&compute_stream);

    std::cout << "\n---------------------------------------------------" << std::endl;
    std::cout << "🎯 UNIFIED IMAGE PTR : 0x" << std::hex << reinterpret_cast<uint64_t>(unified_image) << std::dec << std::endl;

    // =========================================================================
    // 2. GPU GCM encryption and integrity tag generation (asynchronous)
    // =========================================================================
    run_gpu_gcm(unified_image->data, sizeof(HeavyImage), d_final_mac, compute_stream);
    
    // At this point we wait for the GPU to compute for ~1.9ms.
    // (In a real system, the CPU would prepare the next frame or assemble network headers here)
    cudaStreamSynchronize(compute_stream);

    std::cout << "🎯 GENERATED MAC TAG : 0x";
    for(int i=0; i<16; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)d_final_mac[i];
    std::cout << std::dec << "\n";

    // =========================================================================
    // 3. Assemble the Thunk and perform a 32-byte Zero-Copy transmission
    // =========================================================================
    ThunkHeader my_thunk;
    my_thunk.magic_flag = 0xDEADBEEF;
    my_thunk.real_size = sizeof(HeavyImage);
    my_thunk.memory_ptr = reinterpret_cast<uint64_t>(unified_image);
    std::memcpy(my_thunk.mac_tag, d_final_mac, 16);

    // Fast-DDS does not read the 8MB; it only reads and transmits the my_thunk struct (32 bytes).
    writer->write(static_cast<void*>(&my_thunk));
    std::cout << "[Fused Publisher] 32-byte Authenticated Thunk Dispatched!" << std::endl;
    std::cout << "---------------------------------------------------\n" << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(1));

    cudaFree(unified_image); cudaFree(d_final_mac); cudaStreamDestroy(compute_stream);
    participant->delete_contained_entities();
    DomainParticipantFactory::get_instance()->delete_participant(participant);

    return 0;
}