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

// mqtt.h author Vitalii Horbatov <vhorbato@cisco.com>

#ifndef MQTT_MESSAGE_H
#define MQTT_MESSAGE_H

#include <string>
#include <iostream>

#include "flow/flow.h"
#include "protocols/packet.h"

#include "mqtt.h"

struct MQTTFixedHeader
{
    MqttCommandType pkt_type = CMD_RESERVED;
    bool bit0 = false;
    bool bit1 = false;
    bool bit2 = false;
    bool bit3 = false;
    uint32_t remaining_len = 0;
};

class MQTTCommand
{
public:
    MQTTCommand(const MQTTFixedHeader& header, MQTTData* ssn)
        : header(header), ssn(ssn) {}

    virtual uint8_t parse(std::istream&)
    { return MQTT_ERROR; }

    virtual bool get_buffer(MqttOptBuffer, uint8_t*&, uint32_t&)
    { return false; }

    MqttCommandType get_type();

protected:
    MQTTFixedHeader header;
    MQTTData* ssn;
};

class MQTTConnectCommand : public MQTTCommand
{
public:
    MQTTConnectCommand(const MQTTFixedHeader& header, MQTTData* ssn)
        : MQTTCommand(header, ssn) {}

    uint8_t parse(std::istream& stream) override;

    bool get_buffer(MqttOptBuffer buf, uint8_t*& start, uint32_t& len) override;

private:
    std::string protocol_string;
    uint8_t protocol_version;
    bool username_flag;
    bool password_flag;
    bool will_retain;
    uint8_t will_qos;
    bool will_flag;
    bool clean_session;
    uint16_t keepalive;
    std::string client_id;
    std::string will_topic;
    std::string will_message; //FIXIT should be uint8_t vec, not string
    std::string username;
    std::string password; //FIXIT should be uint8_t vec, not string
};

class MQTTConnackCommand : public MQTTCommand
{
public:
    MQTTConnackCommand(const MQTTFixedHeader& header, MQTTData* ssn)
        : MQTTCommand(header, ssn) {}

    uint8_t parse(std::istream& stream) override;

private:
    uint8_t return_code;
    bool session_present;
};

class MQTTPublishCommand : public MQTTCommand
{
public:
    MQTTPublishCommand(const MQTTFixedHeader& header, MQTTData* ssn)
        : MQTTCommand(header, ssn) {}

    uint8_t parse(std::istream& stream) override;   
    bool get_buffer(MqttOptBuffer buf, uint8_t*& start, uint32_t& len) override;

private:
    std::string topic;
    uint16_t message_id;
    char* message;
    uint32_t msg_len;
};

class MQTTPubResponseCommand : public MQTTCommand
{
public:
    MQTTPubResponseCommand(const MQTTFixedHeader& header, MQTTData* ssn)
        : MQTTCommand(header, ssn) {}

    uint8_t parse(std::istream& stream) override;

private:
    uint16_t message_id;
};

class MQTTSubscribeCommand : public MQTTCommand
{
public:
    MQTTSubscribeCommand(const MQTTFixedHeader& header, MQTTData* ssn)
        : MQTTCommand(header, ssn) {}

    uint8_t parse(std::istream& stream) override;

private:
    uint16_t message_id;

    using TopicRequest = std::pair<std::string, uint8_t>;
    std::vector<TopicRequest> topics;
};

class MQTTUnsubscribeCommand : public MQTTCommand
{
public:
    MQTTUnsubscribeCommand(const MQTTFixedHeader& header, MQTTData* ssn)
        : MQTTCommand(header, ssn) {}

    uint8_t parse(std::istream& stream) override;

private:
    uint16_t message_id;
    std::vector<std::string> topics;
};

class MQTTSubackCommand : public MQTTCommand
{
public:
    MQTTSubackCommand(const MQTTFixedHeader& header, MQTTData* ssn)
        : MQTTCommand(header, ssn) {}

    uint8_t parse(std::istream& stream) override;

private:
    uint16_t message_id;
    std::vector<uint8_t> return_codes;
};

class MQTTUnsubackCommand : public MQTTCommand
{
public:
    MQTTUnsubackCommand(const MQTTFixedHeader& header, MQTTData* ssn)
        : MQTTCommand(header, ssn) {}
    
    uint8_t parse(std::istream& stream) override;

private:
    uint16_t message_id;
};

// DOSCONNECT, PINGREQ, PINGRESP commands
class MQTTEmptyCommand : public MQTTCommand
{
public:
    MQTTEmptyCommand(const MQTTFixedHeader& header, MQTTData* ssn)
        : MQTTCommand(header, ssn) {}
    
    uint8_t parse(std::istream& stream) override;
};

#endif
