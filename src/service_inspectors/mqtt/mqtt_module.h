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

// mqtt_module.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef MQTT_MODULE_H
#define MQTT_MODULE_H

// Interface to the MQTT service inspector

#include "framework/module.h"
#include "mqtt_config.h"

#define GID_MQTT 156

#define MQTT_UNKNOWN_CMD            1
#define MQTT_BAD_VERSION            2

#define MQTT_NAME "mqtt"
#define MQTT_HELP "mqtt inspection"

namespace snort
{
struct SnortConfig;
}

extern THREAD_LOCAL snort::ProfileStats mqttPerfStats;

class MqttModule : public snort::Module
{
public:
    MqttModule();
    ~MqttModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_MQTT; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }

    MQTT_PROTO_CONF* get_data();

private:
    MQTT_PROTO_CONF* config;
};

#endif
