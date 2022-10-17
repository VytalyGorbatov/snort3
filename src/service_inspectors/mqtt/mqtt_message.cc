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

// mqtt_message.cc author Vitalii Horbatov <vhorbato@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt_message.h"

#include <string>
#include <iostream>

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/ssl.h"
#include "pub_sub/opportunistic_tls_event.h"
#include "search_engines/search_tool.h"
#include "stream/stream.h"
#include "utils/util_cstring.h"

#include "mqtt_utils.h"

using namespace snort;


MqttCommandType MQTTCommand::get_type()
{ return header.pkt_type; }

static bool parse_enc_string(std::istream& stream, std::string& str)
{
    char len_bytes[2];
    
    if(!stream.read(len_bytes, 2))
        return false;

    uint16_t len = len_bytes[0] << 8 | len_bytes[1];

    char* data_bytes = new char[len];
    if(!stream.read(data_bytes, len))
        return false;

    str = std::string(data_bytes, len);
    delete[] data_bytes;
    return true;
}

uint8_t MQTTConnectCommand::parse(std::istream& stream)
{    
    if (!parse_enc_string(stream, protocol_string))
        return MQTT_EOF;
    if (protocol_string != "MQTT")
        return MQTT_PROTO_VIOLATION;

    char protocol_version_ch = 0;
    
    if (!stream.get(protocol_version_ch))
        return MQTT_EOF;

    protocol_version = (uint8_t)protocol_version_ch;
    if (protocol_version > 4)
        return MQTT_PROTO_VERSION;

    char flags;
    if (!stream.get(flags))
        return MQTT_EOF;

    username_flag = flags & 0b10000000;
    password_flag = flags & 0b01000000;
    will_retain   = flags & 0b0010000;
    will_qos      = flags & 0b00011000;
    will_flag     = flags & 0b00000100;
    clean_session = flags & 0b00000010;
    if (flags & 0b00000001)
        return MQTT_PROTO_VIOLATION;

    char keepalive_bytes[2];
    
    if (!stream.read(keepalive_bytes, 2))
        return MQTT_EOF;

    keepalive = keepalive_bytes[0] << 8 | keepalive_bytes[1];

    if (!parse_enc_string(stream, client_id))
        return MQTT_EOF;

    if(will_flag)
    {
        parse_enc_string(stream, will_topic);
        parse_enc_string(stream, will_message);
    }

    if(username_flag)
        parse_enc_string(stream, username);

    if(password_flag)
        parse_enc_string(stream, password);

    std::cout << "protocol_string: " << protocol_string << "|" <<
    "protocol_version: " << (int)protocol_version << "|" <<
    "username_flag: " << username_flag << "|" <<
    "password_flag: " << password_flag << "|" <<
    "will_retain: " << will_retain << "|" <<
    "will_qos: " << (int)will_qos << "|" <<
    "will_flag: " << will_flag << "|" <<
    "clean_session: " << clean_session << "|" <<
    "keepalive: " << keepalive << "|" <<
    "client_id: " << client_id << "|" <<
    "will_topic: " << will_topic << "|" <<
    "will_message: " << will_message << "|" <<
    "username: " << username << "|" <<
    "password: " << password << std::endl;

    return 0;
}

uint8_t MQTTConnackCommand::parse(std::istream& stream)
{    
    char SP_byte;
    if (stream.get(SP_byte))
        session_present = SP_byte;
    else
        return MQTT_EOF;

    char return_byte;
    if (stream.get(return_byte))
        return_code = return_byte;
    else
        return MQTT_EOF;

    std::cout << "session_present: " << session_present << "| " <<
    "return_code:" << return_code << std::endl;

    return 0;
}

uint8_t MQTTPublishCommand::parse(std::istream& stream)
{
    std::streampos start_pos = stream.tellg();

    if (!parse_enc_string(stream, topic))
        return MQTT_EOF;

    if(topic.size() == 0 or topic.find("*") != topic.npos)
        return MQTT_PROTO_VIOLATION;
    // The Topic Name in a PUBLISH Packet sent by a Server to a subscribing Client MUST match the Subscription’s Topic Filter according to the matching process defined in Section 4.7

    ssn->qos = header.bit2 & header.bit1;
    if (ssn->qos == 1 or ssn->qos == 2)
    {
        char message_id_bytes[2];
        if (!stream.read(message_id_bytes, 2))
            return MQTT_EOF;

        message_id = message_id_bytes[0] << 8 | message_id_bytes[1];
    }
    // else
    //     return MQTT_PROTO_VIOLATION;

    msg_len = header.remaining_len - (stream.tellg() - start_pos);
    
    message = new char[msg_len];
    if (!stream.read(message, msg_len))
        return MQTT_EOF;
    

    std::cout << "topic: " << topic << "| ";
    if( ssn->qos == 1 or ssn->qos == 2)
        std::cout << "message_id:" << message_id<< "| ";
    std::cout << "message: " << std::string(message, msg_len) << "| " << std::endl;

    return 0;
}

uint8_t MQTTPubResponseCommand::parse(std::istream& stream)
{
    char message_id_bytes[2];
    if (!stream.read(message_id_bytes, 2))
        return MQTT_EOF;

    message_id = message_id_bytes[0] << 8 | message_id_bytes[1];

    std::cout << "message_id: " << message_id << std::endl;

    return 0;
}

static inline bool parse_topic(std::istream& stream, std::string& topic)
{
    char length_bytes[2];
    if (!stream.read(length_bytes, 2))
        return false;

    uint16_t topic_length = length_bytes[0] << 8 | length_bytes[1];
    
    char* topic_name = new char[topic_length];
    if (!stream.read(topic_name, topic_length))
        return false;

    topic = std::string(topic_name, topic_length);
    delete[] topic_name;

    return true;
}

uint8_t MQTTSubscribeCommand::parse(std::istream& stream)
{
    char message_id_bytes[2];
    if (!stream.read(message_id_bytes, 2))
        return MQTT_EOF;

    message_id = message_id_bytes[0] << 8 | message_id_bytes[1];

    std::string topic;

    while (parse_topic(stream, topic))
    {
        char qos_byte;
        if (!stream.get(qos_byte))
            return MQTT_EOF;

        if (qos_byte > 2)
            return MQTT_PROTO_VIOLATION;

        topics.push_back({topic, qos_byte});
    }

    if (topic.size() == 0)
        return MQTT_EOF;

    std::cout << "message_id: " << message_id << " |";
    for (auto topic : topics )
        std::cout << "topic_name: " << topic.first << "| "
    << "qos: " << topic.second << std::endl;

    return 0;
}

uint8_t MQTTUnsubscribeCommand::parse(std::istream& stream)
{
    char message_id_bytes[2];
    if (!stream.read(message_id_bytes, 2))
        return MQTT_EOF;

    message_id = message_id_bytes[0] << 8 | message_id_bytes[1];

    std::string topic;

    while (parse_topic(stream, topic))
        topics.push_back(topic);

    if (topic.size() == 0)
        return MQTT_EOF;

    std::cout << "message_id: " << message_id << " |";
    for (auto topic : topics )
        std::cout << "topic_name: " << topic << std::endl;

    return 0;
}

uint8_t MQTTSubackCommand::parse(std::istream& stream)
{
    char message_id_bytes[2];
    if (!stream.read(message_id_bytes, 2))
        return MQTT_EOF;

    message_id = message_id_bytes[0] << 8 | message_id_bytes[1];

    char return_code;

    while (stream.get(return_code))
    {
        // if (return_code > 2 and return_code != 128) return err

        return_codes.push_back(return_code);
    }

    std::cout << "message_id: " << message_id << " |";
    for (auto code : return_codes )
        std::cout << "return_code: " << code << std::endl;

    return 0;
}

uint8_t MQTTUnsubackCommand::parse(std::istream& stream)
{
    char message_id_bytes[2];
    if (!stream.read(message_id_bytes, 2))
        return MQTT_EOF;

    message_id = message_id_bytes[0] << 8 | message_id_bytes[1];

    std::cout << "message_id: " << message_id << " |";

    return 0;
}

uint8_t MQTTEmptyCommand::parse(std::istream& stream)
{ return 0; }

// -----------------

bool MQTTConnectCommand::get_buffer(MqttOptBuffer buf, uint8_t*& start, uint32_t& len)
{
    switch (buf)
    {
    case CLIENT_ID:
        start = (uint8_t*)client_id.c_str();
        len = client_id.length();
        break;

    case PASSWORD:
        if (!password_flag)
            return false;
        start = (uint8_t*)password.c_str();
        len = password.length();
        break;

    case USERNAME:
        if (!username_flag)
            return false;
        start = (uint8_t*)username.c_str();
        len = username.length();
        break;

    case WILL_MESSAGE:
        if (!will_flag)
            return false;
        start = (uint8_t*)will_message.c_str();
        len = will_message.length();
        break;

    case WILL_TOPIC:
        if (!will_flag)
            return false;
        start = (uint8_t*)will_topic.c_str();
        len = will_topic.length();
        break;

    case TOPIC:
    case MESSAGE:
    default:
        return false;
    }

    return true;
}

bool MQTTPublishCommand::get_buffer(MqttOptBuffer buf, uint8_t*& start, uint32_t& len)
{
    switch (buf)
    {
    case TOPIC:
        start = (uint8_t*)topic.c_str();
        len = topic.length();
        break;

    case MESSAGE:
        start = (uint8_t*)message;
        len = msg_len;
        break;

    case CLIENT_ID:
    case PASSWORD:
    case USERNAME:
    case WILL_MESSAGE:
    case WILL_TOPIC:
    default:
        return false;
    }

    return true;
}
