#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp>  // added
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/SampleInfo.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>         // added
#include <fastdds/dds/topic/Topic.hpp>               // added
#include <iostream>
#include <iomanip>

#include "ThunkPubSubType.hpp"

using namespace eprosima::fastdds::dds;
struct HeavyImage { uint8_t data[8 * 1024 * 1024]; };

class ThunkListener : public DataReaderListener {
public:
    void on_data_available(DataReader* reader) override {
        SampleInfo info;
        ThunkHeader received_thunk;

        if (reader->take_next_sample(&received_thunk, &info) == ReturnCode_t::RETCODE_OK) {
            if (info.valid_data && received_thunk.magic_flag == 0xDEADBEEF) {
                std::cout << "\n---------------------------------------------------" << std::endl;
                std::cout << "[Fused Subscriber] 🎯 THUNK RECEIVED & VERIFIED!" << std::endl;
                std::cout << "🎯 RECONSTRUCTED PTR : 0x" << std::hex << received_thunk.memory_ptr << std::dec << std::endl;
                
                std::cout << "🎯 RECEIVED MAC TAG  : 0x";
                for(int i=0; i<16; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)received_thunk.mac_tag[i];
                std::cout << std::dec << "\n";
                std::cout << "---------------------------------------------------\n" << std::endl;
            }
        }
    }
};

int main() {
    DomainParticipant* participant = DomainParticipantFactory::get_instance()->create_participant(0, PARTICIPANT_QOS_DEFAULT);
    TypeSupport thunk_type(new ThunkPubSubType<HeavyImage>());
    thunk_type.register_type(participant);

    Subscriber* subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT, nullptr);
    Topic* topic = participant->create_topic("V2X_Camera_Stream", thunk_type.get_type_name(), TOPIC_QOS_DEFAULT);
    
    ThunkListener listener;
    DataReader* reader = subscriber->create_datareader(topic, DATAREADER_QOS_DEFAULT, &listener);

    std::cout << "[Fused Subscriber] Listening for Authenticated Thunks..." << std::endl;
    std::cin.get();
    return 0;
}