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

// mqtt_module.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt_module.h"
#include "mqtt.h"

#include <cassert>

#include "log/messages.h"

using namespace snort;
using namespace std;

static const Parameter s_params[] =
{
    { "max_msg_len", Parameter::PT_INT, "0:268435455", "0",
      "max payload size possible in bytes" },
      
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap mqtt_rules[] =
{
    { MQTT_UNKNOWN_MSG_TYPE, "unknown MQTT control message" },
    { MQTT_PROTO_VIOLATION, "MQTT protocol requirements violation" },
    { MQTT_PROTO_VERSION, "unsupported MQTT protocol version" },

    { 0, nullptr }
};

//-------------------------------------------------------------------------
// mqtt module
//-------------------------------------------------------------------------

MqttModule::MqttModule() : Module(MQTT_NAME, MQTT_HELP, s_params)
{
    config = nullptr;
}

MqttModule::~MqttModule()
{
    if ( config )
        delete config;
}

const RuleMap* MqttModule::get_rules() const
{ return mqtt_rules; }

const PegInfo* MqttModule::get_pegs() const
{ return mqtt_peg_names; }

PegCount* MqttModule::get_counts() const
{ return (PegCount*)&mqttstats; }

ProfileStats* MqttModule::get_profile() const
{ return &mqttPerfStats; }

bool MqttModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("max_msg_len") )
        config->max_msg_len = v.get_uint64();

    return true;
}

MQTT_PROTO_CONF* MqttModule::get_data()
{
    MQTT_PROTO_CONF* tmp = config;
    config = nullptr;
    return tmp;
}

bool MqttModule::begin(const char*, int, SnortConfig*)
{
    assert(!config);
    config = new MQTT_PROTO_CONF;
    return true;
}

bool MqttModule::end(const char*, int, SnortConfig*)
{
    return true;
}

