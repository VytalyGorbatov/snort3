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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt_paf.h"

#include "protocols/packet.h"
#include "stream/stream.h"

#include "mqtt.h"

using namespace snort;

MqttSplitter::MqttSplitter(bool c2s) : StreamSplitter(c2s)
{
    mqtt_state = MQTT_PAF_FIX_HEAD_STATE;
    remain_data_len = 0;
}

StreamSplitter::Status MqttSplitter::scan(
    Packet*, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t* fp)
{
    uint32_t n = 0;

    while (n < len)
    {
        switch (mqtt_state)
        {
        case MQTT_PAF_FIX_HEAD_STATE:
        {
            uint8_t command_type = data[n] >> 4;
            if (command_type == 0 or command_type > 15)
                return StreamSplitter::ABORT;
            
            mqtt_state = MQTT_PAF_REM_LEN1_STATE;
            break;
        }

        case MQTT_PAF_REM_LEN1_STATE:
            remain_data_len += (data[n] & 127);

            if ((data[n] & 128) != 0)
                mqtt_state = MQTT_PAF_REM_LEN2_STATE;
            else
            {
                if (remain_data_len != 0)
                {
                    mqtt_state = MQTT_PAF_VAR_DATA_STATE;
                    break;
                }
                else
                {
                    mqtt_state = MQTT_PAF_FIX_HEAD_STATE;
                    *fp = n;
                    return StreamSplitter::FLUSH;
                }
            }

            break;

        case MQTT_PAF_REM_LEN2_STATE:
            remain_data_len += (data[n] & 127) * 128;

            if ((data[n] & 128) != 0)
                mqtt_state = MQTT_PAF_REM_LEN3_STATE;
            else
                mqtt_state = MQTT_PAF_VAR_DATA_STATE;

            break;

        case MQTT_PAF_REM_LEN3_STATE:
            remain_data_len += (data[n] & 127) * 128 * 128;

            if ((data[n] & 128) != 0)
                mqtt_state = MQTT_PAF_REM_LEN4_STATE;
            else
                mqtt_state = MQTT_PAF_VAR_DATA_STATE;

            break;

        case MQTT_PAF_REM_LEN4_STATE:
            remain_data_len += (data[n] & 127) * 128 * 128 * 128;

            if ((data[n] & 128) != 0)
                return StreamSplitter::ABORT;
            else
                mqtt_state = MQTT_PAF_VAR_DATA_STATE;
            
            break;

        case MQTT_PAF_VAR_DATA_STATE:
        {
            uint32_t skip_len = ((len-n) > remain_data_len) ? remain_data_len : (len - n);
            
            remain_data_len -= skip_len;
            n += skip_len;

            if (remain_data_len == 0)
            {
                mqtt_state = MQTT_PAF_FIX_HEAD_STATE;
                *fp = n;
                return StreamSplitter::FLUSH;
            }

            --n;
            break;
        }
            

        default:
            return StreamSplitter::ABORT;
        }
        
        n++;
    }

    return StreamSplitter::SEARCH;
}
