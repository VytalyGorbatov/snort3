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

// mqtt_paf.h author Hui Cao <huica@cisco.com>

#ifndef MQTT_PAF_H
#define MQTT_PAF_H

// Protocol aware flushing for MQTT

#include "stream/stream_splitter.h"

// States for MQTT PAF
enum MqttPafState
{
    MQTT_PAF_FIX_HEAD_STATE = 0,    // parses fixed header
    MQTT_PAF_REM_LEN1_STATE,        // parses first byte of remaining length
    MQTT_PAF_REM_LEN2_STATE,        // parses second byte of remaining length
    MQTT_PAF_REM_LEN3_STATE,        // parses third byte of remaining length
    MQTT_PAF_REM_LEN4_STATE,        // parses fourth byte of remaining length
    MQTT_PAF_VAR_DATA_STATE,        // search and flush on var header and payload
};

class MqttSplitter : public snort::StreamSplitter
{
public:
    MqttSplitter(bool c2s);

    Status scan(snort::Packet*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override { return true; }

public:
    MqttPafState mqtt_state;      // The current MQTT paf state
    uint32_t remain_data_len;
};

#endif

