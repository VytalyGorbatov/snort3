//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// mqtt.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt.h"

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "search_engines/search_tool.h"
#include "stream/stream.h"
#include "utils/util_cstring.h"

#include "mqtt_message.h"
#include "mqtt_module.h"
#include "mqtt_paf.h"
#include "mqtt_utils.h"

#include <iostream>
#include <algorithm>

using namespace snort;

THREAD_LOCAL ProfileStats mqttPerfStats;
THREAD_LOCAL MqttStats mqttstats;

const PegInfo mqtt_peg_names[] =
{
    { CountType::SUM, "packets", "total packets processed" },
    { CountType::SUM, "sessions", "total mqtt sessions" },
    { CountType::END, nullptr, nullptr }
};

MqttFlowData::MqttFlowData() : FlowData(inspector_id)
{
    memset(&session, 0, sizeof(session));
}

MqttFlowData::~MqttFlowData()
{

}

unsigned MqttFlowData::inspector_id = 0;

MQTTData* get_session_data(Flow* flow)
{
    MqttFlowData* fd = (MqttFlowData*)flow->get_flow_data(MqttFlowData::inspector_id);
    return fd ? &fd->session : nullptr;
}

static MQTTData* SetNewMQTTData(Packet* p)
{
    MQTTData* mqtt_ssn;
    MqttFlowData* fd = new MqttFlowData;

    p->flow->set_flow_data(fd);
    mqtt_ssn = &fd->session;

    mqttstats.sessions++;

    if (p->packet_flags & SSNFLAG_MIDSTREAM)
        mqtt_ssn->state = MQTT_SESSION_START;

    return mqtt_ssn;
}

static uint32_t MQTT_parse_variable_int(const uint8_t*& encoded_byte)
{
    if (!encoded_byte)
        return UINT32_MAX;

    uint8_t multiplier = 1;
    uint32_t value = 0;

    do
    {
        value += (*encoded_byte & 127) * multiplier;
        multiplier *= 128;
        if (multiplier > 128 * 128 * 128)
            return UINT32_MAX;
    }
    while ((*encoded_byte++ & 128) != 0);

    return value;
}

static MQTTFixedHeader MQTT_parse_fixed_header(const uint8_t*& data, uint32_t max_len)
{
    MQTTFixedHeader hdr;
    uint8_t header_byte = *data;

    hdr.pkt_type = MqttCommandType(header_byte >> 4);

    hdr.bit0 = header_byte & 0b00000001;
    hdr.bit1 = header_byte & 0b00000010;
    hdr.bit2 = header_byte & 0b00000100;
    hdr.bit3 = header_byte & 0b00001000;

    hdr.remaining_len = std::min(MQTT_parse_variable_int(++data), max_len - 1);

    std::cout << " type: " << (int)hdr.pkt_type << " bits:" << hdr.bit3 << hdr.bit2 << hdr.bit1 << hdr.bit0 << " remainig len:" << hdr.remaining_len << std::endl;

    return hdr;
}

static void snort_mqtt(MQTT_PROTO_CONF* config, Packet* p)
{
    MQTTData* session = get_session_data(p->flow);

    if (session == nullptr)
    {
        /* Check the stream session. If it does not currently
         * have our IMAP data-block attached, create one.
         */
        session = SetNewMQTTData(p);

        if ( !session )
        {
            /* Could not get/create the session data for this packet. */
            return;
        }
    }

    if ((!p->is_from_server()) and (p->packet_flags & PKT_REBUILT_STREAM) and 
        (Stream::missing_in_reassembled(p->flow, SSN_DIR_FROM_CLIENT) == SSN_MISSING_BEFORE))
            session->state = MQTT_STATE_NULL;

    const uint8_t* data_ptr = p->data;

    MQTTFixedHeader header = MQTT_parse_fixed_header(data_ptr, config->max_msg_len);

    uint64_t len = header.remaining_len > p->dsize ? p->dsize : header.remaining_len;

    CharBuff buff((char*)data_ptr, (char*)(data_ptr + len));
    std::istream stream(&buff);

    uint8_t ret = 0;

    switch (header.pkt_type)
    {
    case CMD_RESERVED:
    {
        DetectionEngine::queue_event(GID_MQTT, MQTT_PROTO_VIOLATION);
        break;
    }
    case CMD_CONNECT:
    {
        session->current_command = new MQTTConnectCommand(header, session);
        ret = session->current_command->parse(stream);
        break;
    }
    case CMD_CONNACK:
    {
        session->current_command = new MQTTConnackCommand(header, session);
        ret = session->current_command->parse(stream);
        break;
    }
    case CMD_PUBLISH:
    {
        session->current_command = new MQTTPublishCommand(header, session);
        ret = session->current_command->parse(stream);
        break;
    }
    case CMD_PUBACK:
    {
        session->current_command = new MQTTPubResponseCommand(header, session);
        ret = session->current_command->parse(stream);
        break;
    }
    case CMD_PUBREC:
    {
        session->current_command = new MQTTPubResponseCommand(header, session);
        ret = session->current_command->parse(stream);
        break;
    }
    case CMD_PUBREL:
    {
        session->current_command = new MQTTPubResponseCommand(header, session);
        ret = session->current_command->parse(stream);
        break;
    }
    case CMD_PUBCOMP:
    {
        session->current_command = new MQTTPubResponseCommand(header, session);
        ret = session->current_command->parse(stream);
        break;
    }
    case CMD_SUBSCRIBE:
    {
        session->current_command = new MQTTSubscribeCommand(header, session);
        ret = session->current_command->parse(stream);
        break;
    }
    case CMD_SUBACK:
    {
        session->current_command = new MQTTSubackCommand(header, session);
        ret = session->current_command->parse(stream);
        break;
    }
    case CMD_UNSUBSCRIBE:
    {
        session->current_command = new MQTTUnsubscribeCommand(header, session);
        ret = session->current_command->parse(stream);
        break;
    }
    case CMD_PINGREQ:
    case CMD_PINGRESP:
    case CMD_DISCONNECT:
    {
        session->current_command = new MQTTEmptyCommand(header, session);
        break;
    }
    
    default:
        DetectionEngine::queue_event(GID_MQTT, MQTT_UNKNOWN_MSG_TYPE);
    }

    if (ret != 0)
    {
        if (ret != MQTT_EOF)
            DetectionEngine::queue_event(GID_MQTT, ret);

    }
    else
    {
        session->prev_command = header.pkt_type;
    }
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Mqtt : public Inspector
{
public:
    Mqtt(MQTT_PROTO_CONF*);
    ~Mqtt() override;

    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;
    void eval(Packet*) override;

    StreamSplitter* get_splitter(bool c2s) override
    { return new MqttSplitter(c2s); }

private:
    MQTT_PROTO_CONF* config;
};

Mqtt::Mqtt(MQTT_PROTO_CONF* pc)
{
    config = pc;
}

Mqtt::~Mqtt()
{
    if ( config )
        delete config;
}

bool Mqtt::configure(SnortConfig*)
{
    return true;
}

void Mqtt::show(const SnortConfig*) const
{

}

void Mqtt::eval(Packet* p)
{
    Profile profile(mqttPerfStats);

    // precondition - what we registered for
    assert(p->has_tcp_data());
    assert(p->flow);

    ++mqttstats.packets;

    snort_mqtt(config, p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new MqttModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void mqtt_init()
{
    MqttFlowData::init();
}

static void mqtt_term()
{
}

static Inspector* mqtt_ctor(Module* m)
{
    MqttModule* mod = (MqttModule*)m;
    return new Mqtt(mod->get_data());
}

static void mqtt_dtor(Inspector* p)
{
    delete p;
}

static const char* mqtt_bufs[] =
{
    "mqtt_clientid",
    "mqtt_password",
    "mqtt_username",
    "mqtt_will_message",
    "mqtt_will_topic",
    "mqtt_message",
    "mqtt_topic",
    nullptr
};


const InspectApi mqtt_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MQTT_NAME,
        MQTT_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    mqtt_bufs,
    "mqtt",
    mqtt_init,
    mqtt_term, // pterm
    nullptr, // tinit
    nullptr, // tterm
    mqtt_ctor,
    mqtt_dtor,
    nullptr, // ssn
    nullptr  // reset
};

extern const BaseApi* ips_mqtt_client_id;
extern const BaseApi* ips_mqtt_passwd;
extern const BaseApi* ips_mqtt_uname;
extern const BaseApi* ips_mqtt_will_msg;
extern const BaseApi* ips_mqtt_will_topic;
extern const BaseApi* ips_mqtt_msg;
extern const BaseApi* ips_mqtt_topic;
extern const BaseApi* ips_mqtt_type;


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_mqtt[] =
#endif
{
    &mqtt_api.base,
    ips_mqtt_client_id,
    ips_mqtt_passwd,
    ips_mqtt_uname,
    ips_mqtt_will_msg,
    ips_mqtt_will_topic,
    ips_mqtt_msg,
    ips_mqtt_topic,
    ips_mqtt_type,
    nullptr
};