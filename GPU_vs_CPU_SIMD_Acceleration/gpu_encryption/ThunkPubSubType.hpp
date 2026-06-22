#pragma once
#include <fastdds/dds/topic/TopicDataType.hpp>
#include <cstring>
#include <functional>
#include "ThunkHeader.hpp"

template <typename T>
class ThunkPubSubType : public eprosima::fastdds::dds::TopicDataType {
public:
    ThunkPubSubType() {
        setName("Fused_V2X_Stream"); 
        m_typeSize = sizeof(ThunkHeader); // Now we fool the middleware with just 32 bytes!
        m_isGetKeyDefined = false;
    }
    virtual ~ThunkPubSubType() override {}

    bool serialize(void* data, eprosima::fastrtps::rtps::SerializedPayload_t* payload) override {
        // Assume the data pointer is a pointer to a ThunkHeader object filled in directly by the application
        std::memcpy(payload->data, data, sizeof(ThunkHeader));
        payload->length = sizeof(ThunkHeader); 
        return true;
    }

    bool deserialize(eprosima::fastrtps::rtps::SerializedPayload_t* payload, void* data) override {
        std::memcpy(data, payload->data, sizeof(ThunkHeader));
        return true;
    }

    std::function<uint32_t()> getSerializedSizeProvider(void* data) override {
        return []() -> uint32_t { return sizeof(ThunkHeader); };
    }
    void* createData() override { return static_cast<void*>(new ThunkHeader()); }
    void deleteData(void* data) override { delete static_cast<ThunkHeader*>(data); }
    bool getKey(void* data, eprosima::fastrtps::rtps::InstanceHandle_t* ihandle, bool force_md5 = false) override { return false; }
};