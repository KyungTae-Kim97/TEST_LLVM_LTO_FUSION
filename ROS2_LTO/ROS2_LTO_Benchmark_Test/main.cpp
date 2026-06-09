#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/DataReaderListener.hpp>
#include <fastrtps/rtps/attributes/PropertyPolicy.h>

// Include the newly created variable payload header
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

// Structure to store benchmark results
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
            
        }
    }
};

int main(int argc, char** argv) {
    if(argc < 2) { std::cout << "Usage: ./Benchmark [publisher|subscriber]\n"; return 1; }
    std::string mode = argv[1];

    DomainParticipantQos pqos;
    pqos.name(mode == "publisher" ? "ScalePub" : "ScaleSub");
    PropertyPolicy& props = pqos.properties();

    // Load SROS2 plugins (Identical to previous configuration)
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

    DomainParticipant* participant = DomainParticipantFactory::get_instance()->create_participant(0, pqos);

    TypeSupport type(new VariablePayloadPubSubType());
    type.register_type(participant);
    Topic* topic = participant->create_topic("rt/TwistTopic", type.get_type_name(), TOPIC_QOS_DEFAULT);

    if (mode == "publisher") {
        Publisher* pub = participant->create_publisher(PUBLISHER_QOS_DEFAULT);
        DataWriter* writer = pub->create_datawriter(topic, DATAWRITER_QOS_DEFAULT);
        
        std::cout << "Starting Payload Scaling Benchmark..." << std::endl;
        std::cout << "Waiting 3 seconds for SROS2 Handshake..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3)); 

        // Array of payload sizes to benchmark (48 Bytes to 32 KB)
        // std::vector<size_t> sizes = { 48, 64, 128, 256, 512, 1024, 2048, 4096};
        std::vector<size_t> sizes = { 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 16384*2};
        std::vector<BenchResult> all_results;
        
        const int WARMUP_ITERS = 500;
        const int BENCHMARK_ITERS = 10000; // Total iterations can be adjusted for large payloads if necessary

        VariablePayload msg;

        for (size_t current_size : sizes) {
            std::cout << "\n=========================================================\n";
            std::cout << " Testing Payload Size: " << current_size << " Bytes (" << current_size / 1024 << " KB)\n";
            std::cout << "=========================================================\n";

            // Allocate payload size and initialize with dummy data
            msg.data().resize(current_size);
            std::fill(msg.data().begin(), msg.data().end(), 0xAA); 

            std::vector<double> latencies;
            latencies.reserve(BENCHMARK_ITERS);

            std::cout << "Warming up..." << std::endl;
            for (int i = 0; i < WARMUP_ITERS; ++i) {
                writer->write(&msg);
            }

            std::cout << "Measuring Latency..." << std::endl;
            auto start_total = std::chrono::high_resolution_clock::now();

            for (int i = 0; i < BENCHMARK_ITERS; ++i) {
                auto t1 = std::chrono::high_resolution_clock::now();
                writer->write(&msg);
                auto t2 = std::chrono::high_resolution_clock::now();

                std::chrono::duration<double, std::nano> diff = t2 - t1;
                latencies.push_back(diff.count());
            }
            auto end_total = std::chrono::high_resolution_clock::now();

            // Calculate statistics
            std::sort(latencies.begin(), latencies.end());
            double p50 = latencies[BENCHMARK_ITERS * 0.50];
            double p99 = latencies[BENCHMARK_ITERS * 0.99];
            
            // Calculate Average Latency (Utilizing std::accumulate)
            double sum = std::accumulate(latencies.begin(), latencies.end(), 0.0);
            double avg = sum / latencies.size();

            std::chrono::duration<double> total_sec = end_total - start_total;
            double throughput = BENCHMARK_ITERS / total_sec.count();

            std::cout << " - Throughput: " << throughput << " msgs/sec\n";
            std::cout << " - Average: " << avg << " ns\n"; 
            std::cout << " - Median (P50): " << p50 << " ns\n";
            std::cout << " - Tail (P99): " << p99 << " ns\n";

            // Store measurement results
            all_results.push_back({current_size, throughput, avg, p50, p99});
            
            // Short delay to allow system stabilization
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        // =========================================================================
        // Final Benchmark Results Table (Optimized for Paper/Thesis Output)
        // =========================================================================
        std::cout << "\n\n [Final Benchmark Results Table]\n";
        std::cout << "---------------------------------------------------------------------------------------------\n";
        std::cout << std::setw(15) << "Payload (Bytes)" 
                  << std::setw(20) << "Throughput (msg/s)" 
                  << std::setw(20) << "Avg Latency (ns)"   
                  << std::setw(20) << "P50 Latency (ns)" 
                  << std::setw(20) << "P99 Latency (ns)" << "\n";
        std::cout << "---------------------------------------------------------------------------------------------\n";
        
        for (const auto& res : all_results) {
            std::cout << std::fixed << std::setprecision(2);
            std::cout << std::setw(15) << res.size 
                      << std::setw(20) << res.throughput 
                      << std::setw(20) << res.avg          
                      << std::setw(20) << res.p50 
                      << std::setw(20) << res.p99 << "\n";
        }
        std::cout << "---------------------------------------------------------------------------\n";
        std::cout << "Benchmark finished. Press Ctrl+C to exit." << std::endl;
        while(true) { std::this_thread::sleep_for(std::chrono::seconds(1)); }
        
    } else {
        Subscriber* sub = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT);
        SubListener* listener = new SubListener();
        sub->create_datareader(topic, DATAREADER_QOS_DEFAULT, listener);
        
        std::cout << "Listening for VariablePayload messages..." << std::endl;
        while(true) { std::this_thread::sleep_for(std::chrono::seconds(1)); }
    }
    return 0;
}