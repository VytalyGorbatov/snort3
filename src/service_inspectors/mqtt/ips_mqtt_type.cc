//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// Authors:
// Hui Cao <huica@cisco.com>
// Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <map>
#include <string>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "mqtt.h"
#include "mqtt_message.h"

using namespace snort;

static THREAD_LOCAL ProfileStats mqtt_type_ps;

#define s_name "mqtt_type"
#define s_help "detection option for MQTT control message type"
#define s_types "CONNECT|CONNACK|PUBLISH|PUBACK|PUBREC|PUBREL|PUBCOMP" \
            "SUBSCRIBE|SUBACK|UNSUBSCRIBE|UNSUBACK|PINGREQ|PINGRESP|DISCONNECT"

static std::map<std::string, MqttCommandType> str_type_dict = {
    {"CONNECT", MqttCommandType::CMD_CONNECT},
    {"CONNACK", MqttCommandType::CMD_CONNACK},
    {"PUBLISH", MqttCommandType::CMD_PUBLISH},
    {"PUBACK", MqttCommandType::CMD_PUBACK},
    {"PUBREC", MqttCommandType::CMD_PUBREC},
    {"PUBREL", MqttCommandType::CMD_PUBREL},
    {"PUBCOMP", MqttCommandType::CMD_PUBCOMP},
    {"SUBSCRIBE", MqttCommandType::CMD_SUBSCRIBE},
    {"SUBACK", MqttCommandType::CMD_SUBACK},
    {"UNSUBSCRIBE", MqttCommandType::CMD_UNSUBSCRIBE},
    {"UNSUBACK", MqttCommandType::CMD_UNSUBACK},
    {"PINGREQ", MqttCommandType::CMD_PINGREQ},
    {"PINGRESP", MqttCommandType::CMD_PINGRESP},
    {"DISCONNECT", MqttCommandType::CMD_DISCONNECT}
};

//-------------------------------------------------------------------------
// generic buffer stuffer
//-------------------------------------------------------------------------

class MqttTypeOption : public IpsOption
{
public:
    MqttTypeOption(MqttCommandType cmd) :
    IpsOption(s_name), type(cmd)
    { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    MqttCommandType type;
};

uint32_t MqttTypeOption::hash() const
{
    uint32_t a = type;
    uint32_t b = IpsOption::hash();
    uint32_t c = 0;

    mix(a,b,c);
    finalize(a,b,c);
    return c;
}

bool MqttTypeOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    return type == ((const MqttTypeOption&)ips).type;
}

IpsOption::EvalStatus MqttTypeOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(mqtt_type_ps);

    if ((!p->has_tcp_data()) || !p->flow || !p->dsize)
        return NO_MATCH;

    MQTTData* session = get_session_data(p->flow);

    if (!session)
        return NO_MATCH;

    MQTTCommand* cmd = session->current_command;

    if (!cmd)
        return NO_MATCH;

    if (cmd->get_type() == type)
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~type", Parameter::PT_SELECT, s_types, nullptr, "mqtt control packet type" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class MqttTypeModule : public Module
{
public:
    MqttTypeModule( ) :
        Module(s_name, s_help, s_params)
    { }
    
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &mqtt_type_ps; }

    Usage get_usage() const override
    { return DETECT; }

    MqttCommandType type;
};

bool MqttTypeModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~type"));

    auto type_it = str_type_dict.find(v.get_unquoted_string());

    if ( type_it == str_type_dict.end() )
    {
        ParseError("MQTT control packet type not supported");
        return false;
    }
    
    type = type_it->second;

    return true;
}

//-------------------------------------------------------------------------
// API
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new MqttTypeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}


static IpsOption* opt_ctor(Module* mod, OptTreeNode*)
{
    return new MqttTypeOption(((MqttTypeModule*)mod)->type);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}


static const IpsApi mqtt_type_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_mqtt_type = &mqtt_type_api.base;