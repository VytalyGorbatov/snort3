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

// mqtt_utils.h author Vitalii Horbatov <vhorbato@cisco.com>

#ifndef MQTT_UTILS_H
#define MQTT_UTILS_H

class MqttByteStream
{
public:
    MqttByteStream(const uint8_t* ptr, const uint8_t* end)
        : ptr(ptr), end(end)
    { }

    const uint8_t* GetBytes(uint32_t count)
    {
        if (ptr + count <= end)
        {
            ptr += count;
            return ptr - count;
        }
        else
            return nullptr;
    }

private:
    const uint8_t* ptr;
    const uint8_t* end;
};

#include <istream>
#include <streambuf>

struct CharBuff : std::streambuf
{
    CharBuff(char* begin, char* end) {
        this->setg(begin, begin, end);
    }

    pos_type seekoff(off_type off,
                 std::ios_base::seekdir dir,
                 std::ios_base::openmode which = std::ios_base::in) {
        if (dir == std::ios_base::cur)
            gbump(off);
        else if (dir == std::ios_base::end)
            setg(eback(), egptr() + off, egptr());
        else if (dir == std::ios_base::beg)
            setg(eback(), eback() + off, egptr());
        return gptr() - eback();
    }
};

#endif