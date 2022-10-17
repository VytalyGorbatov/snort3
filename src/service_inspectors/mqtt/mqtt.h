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

#ifndef MQTT_H
#define MQTT_H

#include "flow/flow.h"

#define MQTT_PKT_FROM_UNKNOWN    0
#define MQTT_PKT_FROM_CLIENT     1
#define MQTT_PKT_FROM_SERVER     2

#define MQTT_SESSION_START        0
#define MQTT_SESSION_ESTABLISHED  1
#define MQTT_SESSION_SUBSCRIBED   2
#define MQTT_SESSION_UNSUBSCRIBED 3
#define MQTT_SESSION_DISCONNECTED 4

#define MQTT_STATE_NULL           0
#define MQTT_STATE_VAR_HEADER     1
#define MQTT_STATE_DATA           2

#define MQTT_UNKNOWN_MSG_TYPE   1
#define MQTT_PROTO_VIOLATION    2
#define MQTT_PROTO_VERSION      3
#define MQTT_EOF                4
#define MQTT_ERROR              5

class MQTTCommand;


enum MqttCommandType
{
    CMD_RESERVED = 0,
    CMD_CONNECT,
    CMD_CONNACK,
    CMD_PUBLISH,
    CMD_PUBACK,
    CMD_PUBREC,
    CMD_PUBREL,
    CMD_PUBCOMP,
    CMD_SUBSCRIBE,
    CMD_SUBACK,
    CMD_UNSUBSCRIBE,
    CMD_UNSUBACK,
    CMD_PINGREQ,
    CMD_PINGRESP,
    CMD_DISCONNECT,
    CMD_LAST
};

enum MqttOptBuffer
{
    CLIENT_ID = 0,
    PASSWORD,
    USERNAME,
    WILL_MESSAGE,
    WILL_TOPIC,
    TOPIC,
    MESSAGE,
    BUF_MAX
};

struct MQTTData
{
    uint32_t state;
    uint32_t session_flags;
    MqttCommandType prev_command;
    MQTTCommand* current_command;
    uint32_t bytes_processed;
    uint8_t qos;
};

class MqttFlowData : public snort::FlowData
{
public:
    MqttFlowData();
    ~MqttFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;

    MQTTData session;
};

MQTTData* get_session_data(snort::Flow*);

#endif
