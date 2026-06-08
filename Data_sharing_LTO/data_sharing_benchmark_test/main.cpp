#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/DataReaderListener.hpp>
#include <fastrtps/rtps/attributes/PropertyPolicy.h>

// 새로 생성한 가변 페이로드 헤더 인클루드
#include "VariablePayloadPubSubTypes.h"
#include "VariablePayload.h"

#include <chrono>
#include <vector>
#include <numeric>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <thread>

using namespace eprosima::fastdds::dds;
using namespace eprosima::fastrtps::rtps;

// 벤치마크 결과를 저장할 구조체
struct BenchResult {
    size_t size;
    double throughput;
    double avg;
    double p50;
    double p99;
};

class SubListener : public DataReaderListener {
public:
    void on_data_available(DataReader* reader) override {
        VariablePayload msg;
        SampleInfo info;
        if (reader->take_next_sample(&msg, &info) == ReturnCode_t::RETCODE_OK && info.valid_data) {
            // 수신 확인용 (성능에 영향을 주지 않도록 크기만 출력하거나 주석 처리 권장)
            // std::cout << "[RX] Received data size: " << msg.data().size() << " bytes\n";
        }
    }
};

int main(int argc, char** argv) {
    if(argc < 2) { std::cout << "Usage: ./Benchmark [publisher|subscriber]\n"; return 1; }
    std::string mode = argv[1];

    DomainParticipantQos pqos;
    pqos.name(mode == "publisher" ? "ScalePub" : "ScaleSub");
    PropertyPolicy& props = pqos.properties();

    // SROS2 플러그인 로드 (기존과 동일)
    props.properties().emplace_back("dds.sec.auth.plugin", "builtin.PKI-DH");
    props.properties().emplace_back("dds.sec.access.plugin", "builtin.Access-Permissions");
    props.properties().emplace_back("dds.sec.crypto.plugin", "builtin.AES-GCM-GMAC");

    std::string keystore_dir = "/home/ubuntu/sros2_keystore/enclaves/"; 
    std::string enclave_name = (mode == "publisher") ? "TwistPub" : "TwistSub";
    std::string cert_dir = keystore_dir + enclave_name + "/";

    props.properties().emplace_back("dds.sec.auth.builtin.PKI-DH.identity_ca", "file://" + cert_dir + "identity_ca.cert.pem");
    props.properties().emplace_back("dds.sec.auth.builtin.PKI-DH.identity_certificate", "file://" + cert_dir + "cert.pem");
    props.properties().emplace_back("dds.sec.auth.builtin.PKI-DH.private_key", "file://" + cert_dir + "key.pem");
    props.properties().emplace_back("dds.sec.access.builtin.Access-Permissions.permissions_ca", "file://" + cert_dir + "permissions_ca.cert.pem");
    props.properties().emplace_back("dds.sec.access.builtin.Access-Permissions.governance", "file://" + cert_dir + "governance.p7s");
    props.properties().emplace_back("dds.sec.access.builtin.Access-Permissions.permissions", "file://" + cert_dir + "permissions.p7s");

//  FastDDS 자체가 원래(By design) 1차(Payload)와 2차(Message)에 걸쳐 이중 암호화를 수행하도록 기본 설정이 되어 있었던 것입니다.
//  이 현상을 막고 LTO 퓨전의 진정한 성능을 끌어내려면, 이전 답변에서 말씀드린 대로 QoS 설정에서 RTPS Message 보호 수준을 낮춰야 합니다.
    props.properties().emplace_back("rtps.protection_kind", "SIGN"); // 또는 "NONE"
    props.properties().emplace_back("rtps.payload.protection_kind", "ENCRYPT");
//
	
    DomainParticipant* participant = DomainParticipantFactory::get_instance()->create_participant(0, pqos);

    TypeSupport type(new VariablePayloadPubSubType());
    
    // 💡 [핵심 해결책] Data-Sharing 공유 메모리 청크(방) 크기를 강제로 확장!
    // 미들웨어가 기본적으로 약 1MB로 잡혀있던 한계치를 5MB로 넉넉하게 늘려줍니다.
    // 2MB(2048KB) 데이터 + 헤더 + MAC(16) + IV(8)가 모두 들어가고도 남습니다.
    type->m_typeSize = 5 * 1024 * 1024;
    
    type.register_type(participant);
    Topic* topic = participant->create_topic("rt/TwistTopic", type.get_type_name(), TOPIC_QOS_DEFAULT);

    if (mode == "publisher") {
        Publisher* pub = participant->create_publisher(PUBLISHER_QOS_DEFAULT);
        DataWriter* writer = pub->create_datawriter(topic, DATAWRITER_QOS_DEFAULT);
        
        std::cout << "🚀 Starting Payload Scaling Benchmark..." << std::endl;
        std::cout << "⏳ Waiting 3 seconds for SROS2 Handshake..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3)); 

        // 💡 벤치마크할 데이터 크기 배열 (64 ~ 4MB)
        std::vector<size_t> sizes = {1024 * 64, 1024 * 128, 1024 * 256, 1024 * 512, 1024 * 1024 * 1, 1024 * 1024 * 2, 1024 * 1024 * 4 };
        std::vector<BenchResult> all_results;
        
        const int WARMUP_ITERS = 100;
        const int BENCHMARK_ITERS = 1000; // 큰 데이터의 경우 반복 횟수 조정 필요

        VariablePayload msg;

        for (size_t current_size : sizes) {
            //std::cout << "\n=========================================================\n";
            std::cout << " 📐 Testing Payload Size: " << current_size << " Bytes (" << current_size / 1024 << " KB)\n";
            //std::cout << "=========================================================\n";

            // 페이로드 크기 할당 및 더미 데이터 초기화
            msg.data().resize(current_size);
            std::fill(msg.data().begin(), msg.data().end(), 0xAA); 

            std::vector<double> latencies;
            latencies.reserve(BENCHMARK_ITERS);

            //std::cout << "🔥 Warming up..." << std::endl;
            for (int i = 0; i < WARMUP_ITERS; ++i) {
                writer->write(&msg);
                std::this_thread::sleep_for(std::chrono::milliseconds(10)); 
            }

            //std::cout << "⏱️ Measuring Latency..." << std::endl;
            for (int i = 0; i < BENCHMARK_ITERS; ++i) {
                auto t1 = std::chrono::high_resolution_clock::now();
                writer->write(&msg);
                auto t2 = std::chrono::high_resolution_clock::now();

                std::chrono::duration<double, std::nano> diff = t2 - t1;
                latencies.push_back(diff.count());

                // 수신부 처리를 위한 대기 (레이턴시 측정에는 포함되지 않음)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            // auto end_total = std::chrono::high_resolution_clock::now(); // 💡 전체 타이머 제거

            // 통계 계산
            std::sort(latencies.begin(), latencies.end());
            double p50 = latencies[BENCHMARK_ITERS * 0.50];
            double p99 = latencies[BENCHMARK_ITERS * 0.99];
            
            // 평균(Average) 계산 및 순수 처리 시간(Sum) 산출
            double sum_ns = std::accumulate(latencies.begin(), latencies.end(), 0.0);
            double avg = sum_ns / latencies.size();

            // 💡 [핵심 수정] 수면 시간(sleep)을 완전히 배제하고, 순수 CPU 처리 시간의 합으로 Throughput 계산
            double total_active_sec = sum_ns / 1e9; // 나노초(ns) -> 초(s) 변환
            
            // 처리량 방어 코드 (0으로 나누기 방지)
            double throughput = (total_active_sec > 0.0) ? (BENCHMARK_ITERS / total_active_sec) : 0.0;

            std::cout << " - Throughput: " << throughput << " msgs/sec\n";
            std::cout << " - Average: " << avg << " ns\n"; 
            std::cout << " - Median (P50): " << p50 << " ns\n";
            std::cout << " - Tail (P99): " << p99 << " ns\n";

            // 결과 저장
            all_results.push_back({current_size, throughput, avg, p50, p99});
            
            // 시스템 안정화를 위한 짧은 대기
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        // =========================================================================
        // 📊 최종 논문용 테이블 출력
        // =========================================================================
        std::cout << "\n\n🏆 [Final Benchmark Results Table]\n";
        std::cout << "---------------------------------------------------------------------------------------------\n";
        std::cout << std::setw(15) << "Payload (Bytes)" 
                  << std::setw(20) << "Throughput (msg/s)" 
                  << std::setw(20) << "Avg Latency (ns)"   // 💡 추가됨
                  << std::setw(20) << "P50 Latency (ns)" 
                  << std::setw(20) << "P99 Latency (ns)" << "\n";
        std::cout << "---------------------------------------------------------------------------------------------\n";
        
        for (const auto& res : all_results) {
            std::cout << std::fixed << std::setprecision(2);
            std::cout << std::setw(15) << res.size 
                      << std::setw(20) << res.throughput 
                      << std::setw(20) << res.avg          // 💡 추가됨
                      << std::setw(20) << res.p50 
                      << std::setw(20) << res.p99 << "\n";
        }
        std::cout << "---------------------------------------------------------------------------\n";
        std::cout << "✅ Benchmark finished. Press Ctrl+C to exit." << std::endl;
        while(true) { std::this_thread::sleep_for(std::chrono::seconds(1)); }
        
    } else {
        Subscriber* sub = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT);
        SubListener* listener = new SubListener();
        sub->create_datareader(topic, DATAREADER_QOS_DEFAULT, listener);
        
        std::cout << "🎧 Listening for VariablePayload messages..." << std::endl;
        while(true) { std::this_thread::sleep_for(std::chrono::seconds(1)); }
    }
    return 0;
}