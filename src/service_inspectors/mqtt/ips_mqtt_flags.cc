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

#include <array>

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "mqtt.h"
#include "mqtt_message.h"

using namespace snort;

static THREAD_LOCAL std::array<ProfileStats, MqttOptBuffer::BUF_MAX> mqtt_ps;

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class MqttCursorModule : public Module
{
public:
    MqttCursorModule(const char* s, const char* h, MqttOptBuffer buf_type) :
        Module(s, h), buf_type(buf_type)
        { }

    ProfileStats* get_profile() const override
    { return &mqtt_ps[buf_type]; }

    Usage get_usage() const override
    { return DETECT; }

private:
    MqttOptBuffer buf_type;
};

static void mod_dtor(Module* m)
{
    delete m;
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

//-------------------------------------------------------------------------
// generic buffer stuffer
//-------------------------------------------------------------------------

class MqttIpsOption : public IpsOption
{
public:
    MqttIpsOption(const char* s, MqttOptBuffer buf_type, CursorActionType c) :
    IpsOption(s), key(s), cat(c), buf_type(buf_type)
    { }

    CursorActionType get_cursor_type() const override
    { return cat; }

    EvalStatus eval(Cursor&, Packet*) override;

private:
    const char* key;
    CursorActionType cat;
    MqttOptBuffer buf_type;
};

IpsOption::EvalStatus MqttIpsOption::eval(Cursor& c, Packet* p)
{
    RuleProfile profile(mqtt_ps[buf_type]);

    if ((!p->has_tcp_data()) || !p->flow || !p->dsize)
        return NO_MATCH;

    MQTTData* session = get_session_data(p->flow);

    if (!session)
        return NO_MATCH;

    MQTTCommand* cmd = session->current_command;
    uint8_t* data = nullptr;
    unsigned len = 0;

    if (!cmd)
        return NO_MATCH;

    if (cmd->get_buffer(buf_type, data, len))
    {
        c.set(key, data, len);
        return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// mqtt_client_id
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "mqtt_clientid"

#define client_id_help \
    "rule option to set the detection cursor to the MQTT client id buffer"

static Module* client_id_mod_ctor()
{
    return new MqttCursorModule(IPS_OPT, client_id_help, CLIENT_ID);
}

static IpsOption* client_id_opt_ctor(Module*, OptTreeNode*)
{
    return new MqttIpsOption(IPS_OPT, CLIENT_ID, CAT_SET_FAST_PATTERN);
}

static const IpsApi client_id_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        client_id_help,
        client_id_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    client_id_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// mqtt_password
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "mqtt_password"

#define passwd_help \
    "rule option to set the detection cursor to the MQTT password"

static Module* passwd_mod_ctor()
{
    return new MqttCursorModule(IPS_OPT, passwd_help, PASSWORD);
}

static IpsOption* passwd_opt_ctor(Module*, OptTreeNode*)
{
    return new MqttIpsOption(IPS_OPT, PASSWORD, CAT_SET_FAST_PATTERN);
}

static const IpsApi passwd_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        passwd_help,
        passwd_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    passwd_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// mqtt_username
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "mqtt_username"

#define uname_help \
    "rule option to set the detection cursor to the MQTT username"

static Module* uname_mod_ctor()
{
    return new MqttCursorModule(IPS_OPT, uname_help, USERNAME);
}

static IpsOption* uname_opt_ctor(Module*, OptTreeNode*)
{
    return new MqttIpsOption(IPS_OPT, USERNAME, CAT_SET_FAST_PATTERN);
}

static const IpsApi uname_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        uname_help,
        uname_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    uname_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// mqtt_will_message
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "mqtt_will_message"

#define will_msg_help \
    "rule option to set the detection cursor to the MQTT will message"

static Module* will_msg_mod_ctor()
{
    return new MqttCursorModule(IPS_OPT, will_msg_help, WILL_MESSAGE);
}

static IpsOption* will_msg_opt_ctor(Module*, OptTreeNode*)
{
    return new MqttIpsOption(IPS_OPT, WILL_MESSAGE, CAT_SET_FAST_PATTERN);
}

static const IpsApi will_msg_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        will_msg_help,
        will_msg_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    will_msg_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// mqtt_will_topic
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "mqtt_will_topic"

#define will_topic_help \
    "rule option to set the detection cursor to the MQTT will topic"

static Module* will_topic_mod_ctor()
{
    return new MqttCursorModule(IPS_OPT, will_topic_help, WILL_TOPIC);
}

static IpsOption* will_topic_opt_ctor(Module*, OptTreeNode*)
{
    return new MqttIpsOption(IPS_OPT, WILL_TOPIC, CAT_SET_FAST_PATTERN);
}

static const IpsApi will_topic_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        will_topic_help,
        will_topic_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    will_topic_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// mqtt_message
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "mqtt_message"

#define msg_help \
    "rule option to set the detection cursor to the MQTT message"

static Module* msg_mod_ctor()
{
    return new MqttCursorModule(IPS_OPT, msg_help, MESSAGE);
}

static IpsOption* msg_opt_ctor(Module*, OptTreeNode*)
{
    return new MqttIpsOption(IPS_OPT, MESSAGE, CAT_SET_FAST_PATTERN);
}

static const IpsApi msg_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        msg_help,
        msg_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    msg_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// mqtt_topic
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "mqtt_topic"

#define topic_help \
    "rule option to set the detection cursor to the MQTT topic"

static Module* topic_mod_ctor()
{
    return new MqttCursorModule(IPS_OPT, topic_help, TOPIC);
}

static IpsOption* topic_opt_ctor(Module*, OptTreeNode*)
{
    return new MqttIpsOption(IPS_OPT, TOPIC, CAT_SET_FAST_PATTERN);
}

static const IpsApi topic_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        topic_help,
        topic_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    topic_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

// added to snort_plugins in mqtt.cc
const BaseApi* ips_mqtt_client_id = &client_id_api.base;
const BaseApi* ips_mqtt_passwd = &passwd_api.base;
const BaseApi* ips_mqtt_uname = &uname_api.base;
const BaseApi* ips_mqtt_will_msg = &will_msg_api.base;
const BaseApi* ips_mqtt_will_topic = &will_topic_api.base;
const BaseApi* ips_mqtt_msg = &msg_api.base;
const BaseApi* ips_mqtt_topic = &topic_api.base;

