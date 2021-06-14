//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

/*  I N C L U D E S  ************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iomanip>
#include "iostream"
#include <sstream>
#include <unordered_map>
#include <memory>
#include <bitset>

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/tcp.h"
#include "protocols/eth.h"
#include "protocols/packet.h"
#include "sfip/sf_ip.h"
#include "packet_io/active_action.h"
#include "packet_io/active.h"
#include "flow/flow.h"

#include "tcp_splicer_module.h"

using namespace snort;

THREAD_LOCAL ProfileStats tcps_perf_stats;

#define SEND_FIN 0x1
#define GET_ACK 0x2
#define GET_FIN 0x3
#define SEND_ACK 0x4

//-------------------------------------------------------------------------
// implementation stuff
//-------------------------------------------------------------------------

class TCPSession {
public:
    TCPSession( ) : seq_offset(0)
    { }

    void set_seq_offset(uint32_t offset)
    { seq_offset = offset; }

    uint32_t get_seq_offset()
    { return seq_offset; }

private:
    uint32_t seq_offset;
    std::bitset<4> fin_pointers;
};

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class TCPSplicer : public Inspector
{
public:
    TCPSplicer(TCPSplicerModule*);
    ~TCPSplicer() override;

    void show(const SnortConfig*) const override;
    void eval(Packet*) override;

private:
    TCPSplicerConfig* config;

private:
    static void exec_callback(IpsContext* context);
    static void safe_drop(Packet* packet);
    static void rewrite_data(Packet* packet);
};

TCPSplicer::TCPSplicer(TCPSplicerModule* mod)
{
    config = mod->get_config();
}

TCPSplicer::~TCPSplicer ()
{
    delete config;
}

void TCPSplicer::show(const SnortConfig*) const
{
    if ( config )
        return ;
}

void TCPSplicer::eval(Packet* p)
{
    Profile profile(tcps_perf_stats);

    p->context->register_post_callback(exec_callback);
    ++tcp_splicer_stats.total_packets;

    return ;
}

void TCPSplicer::exec_callback(IpsContext* context)
{
    if (!context or !context->packet or !context->packet->ptrs.tcph)
        return;

    switch (context->packet->ptrs.tcph->th_flags)
    {
    case (TH_PUSH | TH_ACK): 
    {
        if (context->packet->active->packet_was_dropped())
        {
            safe_drop(context->packet);
        }
        else
        {
            rewrite_data(context->packet);
        }
        break;
    }
    
    default:
        break;
    }
}

void TCPSplicer::safe_drop(Packet* packet)
{
    return ;
}

void TCPSplicer::rewrite_data(Packet* packet)
{
    uint8_t* start = const_cast<uint8_t*>(packet->data);
    const uint8_t* end = packet->data + packet->dsize;
    unsigned len;

    if ( (start + 5) >= end )
        len = packet->dsize;
    else
        len = 5;

    memcpy(start, "QWER", len);

    packet->packet_flags |= PKT_MODIFIED;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new TCPSplicerModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* as_ctor(Module* m)
{
    return new TCPSplicer((TCPSplicerModule*)m);
}

static void as_dtor(Inspector* p)
{ delete p; }

static const InspectApi as_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MOD_NAME,
        MOD_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PROBE,
    PROTO_BIT__TCP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    as_ctor,
    as_dtor,
    nullptr, // ssn
    nullptr, // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_tcp_splicer[] =
#endif
{
    &as_api.base,
    nullptr
};
