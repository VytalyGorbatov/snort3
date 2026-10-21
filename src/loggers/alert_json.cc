//--------------------------------------------------------------------------
// Copyright (C) 2017-2025 Cisco and/or its affiliates. All rights reserved.
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

// alert_json.cc author Russ Combs <rucombs@cisco.com>
//

// preliminary version based on hacking up alert_csv.cc.  should probably
// share a common implementation class.

// if a more sophisticated solution is needed, for example to escape \ or
// whatever, look at this from Joel: https://github.com/jncornett/alert_json,
// which is also more OO implemented.  should pull in that at some point.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>
#include <cassert>

#include "detection/detection_engine.h"
#include "events/event.h"
#include "flow/flow.h"
#include "flow/flow_key.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "helpers/base64_encoder.h"
#include "log/log_text.h"
#include "log/text_log.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "protocols/cisco_meta_data.h"
#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"

using namespace snort;
using namespace std;

#define LOG_BUFFER (4*K_BYTES)

static THREAD_LOCAL TextLog* json_log;

#define S_NAME "alert_json"
#define F_NAME S_NAME ".txt"

//-------------------------------------------------------------------------
// field formatting functions
//-------------------------------------------------------------------------

class JsonLogger;

namespace
{
struct BufferEntry
{
    std::string name;
    std::string data;
};

struct Args
{
    Packet* pkt;
    const char* msg;
    const Event& event;
    bool comma;
    const JsonLogger* logger;
    mutable bool buffers_collected = false;
    mutable std::vector<BufferEntry> cached_buffers;
    unsigned long buffers_depth = 0;
    int buffers_opt = 0;
};
}

static void print_label(const Args& a, const char* label)
{
    if ( a.comma )
        TextLog_Print(json_log, ",");

    TextLog_Print(json_log, " \"%s\" : ", label);
}

static bool ff_action(const Args& a)
{
    print_label(a, "action");
    TextLog_Quote(json_log, a.pkt->active->get_action_string());
    return true;
}

static bool ff_class(const Args& a)
{
    const char* cls = a.event.get_class_type();
    if ( !cls ) cls = "none";

    print_label(a, "class");
    TextLog_Quote(json_log, cls);
    return true;
}

static bool ff_b64_data(const Args& a)
{
    if ( !a.pkt->dsize )
        return false;

    const unsigned block_size = 2048;
    char out[2*block_size];
    const uint8_t* in = a.pkt->data;

    unsigned nin = 0;
    Base64Encoder b64;

    print_label(a, "b64_data");
    TextLog_Putc(json_log, '"');

    while ( nin < a.pkt->dsize )
    {
        unsigned kin = min(a.pkt->dsize-nin, block_size);
        unsigned kout = b64.encode(in+nin, kin, out);
        TextLog_Write(json_log, out, kout);
        nin += kin;
    }

    if ( unsigned kout = b64.finish(out) )
        TextLog_Write(json_log, out, kout);

    TextLog_Putc(json_log, '"');
    return true;
}

static void escape_json_buffer(std::string& out, const char* data, size_t len)
{
    size_t start = 0;
    for ( size_t i = 0; i < len; ++i )
    {
        uint8_t c = (uint8_t)data[i];
        if ( c >= 0x20 && c <= 0x7E && c != '"' && c != '\\' )
            continue;

        if ( i > start )
            out.append(data + start, i - start);

        switch ( c )
        {
        case '"':  out.append("\\\""); break;
        case '\\': out.append("\\\\"); break;
        case '\b': out.append("\\b"); break;
        case '\f': out.append("\\f"); break;
        case '\n': out.append("\\n"); break;
        case '\r': out.append("\\r"); break;
        case '\t': out.append("\\t"); break;
        default:
            char hex[8];
            snprintf(hex, sizeof(hex), "\\u%04x", c);
            out.append(hex);
            break;
        }
        start = i + 1;
    }
    if ( len > start )
        out.append(data + start, len - start);
}

static void escape_json_buffer(TextLog* log, const char* data, size_t len)
{
    std::string s;
    escape_json_buffer(s, data, len);
    TextLog_Write(log, s.data(), s.size());
}

static void collect_buffers(const Args& a);

#define BUFFER_SEPARATOR "\\30"

static bool ff_buffer_names_common(const Args& a, const char* label)
{
    collect_buffers(a);
    print_label(a, label);
    TextLog_Putc(json_log, '"');

    for ( const auto& b : a.cached_buffers )
    {
        escape_json_buffer(json_log, b.name.data(), b.name.size());
        TextLog_Puts(json_log, BUFFER_SEPARATOR);
    }

    TextLog_Putc(json_log, '"');
    return true;
}

static bool ff_buffer_names(const Args& a)
{
    return ff_buffer_names_common(a, "buffer_names");
}

static bool ff_buffers_names(const Args& a)
{
    return ff_buffer_names_common(a, "buffers_names");
}

static bool ff_buffers(const Args& a)
{
    collect_buffers(a);
    print_label(a, "buffers");
    TextLog_Putc(json_log, '"');

    std::string out;
    for ( const auto& b : a.cached_buffers )
    {
        escape_json_buffer(out, b.data.data(), b.data.size());
        out.append(BUFFER_SEPARATOR);
    }

    size_t depth = a.buffers_depth;
    if ( depth > 0 )
    {
        if ( out.size() < depth )
        {
            out.append(depth - out.size(), '0');
        }
        else if ( out.size() > depth )
        {
            out.resize(depth);
            for ( size_t k = 1; k <= 5 && k <= out.size(); ++k )
            {
                if ( out[out.size() - k] == '\\' )
                {
                    if ( k == 1 || out[out.size() - k + 1] == 'u' )
                    {
                        size_t b = 0;
                        while ( b + k < out.size() && out[out.size() - k - 1 - b] == '\\' )
                            b++;
                        if ( b % 2 == 0 )
                        {
                            for ( size_t j = out.size() - k; j < out.size(); ++j )
                                out[j] = '0';
                        }
                    }
                    break;
                }
            }
            size_t backslashes = 0;
            while ( backslashes < out.size() && out[out.size() - 1 - backslashes] == '\\' )
                backslashes++;
            if ( backslashes % 2 != 0 )
                out.back() = '0';
        }
    }

    TextLog_Write(json_log, out.data(), out.size());
    TextLog_Putc(json_log, '"');
    return true;
}

static bool ff_client_bytes(const Args& a)
{
    if (a.pkt->flow)
    {
        print_label(a, "client_bytes");
        TextLog_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.client_bytes);
        return true;
    }
    return false;
}

static bool ff_client_pkts(const Args& a)
{
    if (a.pkt->flow)
    {
        print_label(a, "client_pkts");
        TextLog_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.client_pkts);
        return true;
    }
    return false;
}

static bool ff_dir(const Args& a)
{
    const char* dir;

    if ( a.pkt->is_from_application_client() )
        dir = "C2S";
    else if ( a.pkt->is_from_application_server() )
        dir = "S2C";
    else
        dir = "UNK";

    print_label(a, "dir");
    TextLog_Quote(json_log, dir);
    return true;
}

static bool ff_dst_addr(const Args& a)
{
    if ( a.pkt->has_ip() or a.pkt->is_data() )
    {
        SfIpString ip_str;
        print_label(a, "dst_addr");
        TextLog_Quote(json_log, a.pkt->ptrs.ip_api.get_dst()->ntop(ip_str));
        return true;
    }
    return false;
}

static bool ff_dst_ap(const Args& a)
{
    SfIpString addr = "";
    unsigned port = 0;

    if ( a.pkt->has_ip() or a.pkt->is_data() )
        a.pkt->ptrs.ip_api.get_dst()->ntop(addr);

    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
        port = a.pkt->ptrs.dp;

    print_label(a, "dst_ap");
    TextLog_Print(json_log, "\"%s:%u\"", addr, port);
    return true;
}

static bool ff_dst_port(const Args& a)
{
    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
    {
        print_label(a, "dst_port");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.dp);
        return true;
    }
    return false;
}

static bool ff_eth_dst(const Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    print_label(a, "eth_dst");
    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);

    TextLog_Print(json_log, "\"%02X:%02X:%02X:%02X:%02X:%02X\"", eh->ether_dst[0],
        eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
        eh->ether_dst[4], eh->ether_dst[5]);

    return true;
}

static bool ff_eth_len(const Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    print_label(a, "eth_len");
    TextLog_Print(json_log, "%u", a.pkt->pkth->pktlen);
    return true;
}

static bool ff_eth_src(const Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    print_label(a, "eth_src");
    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);

    TextLog_Print(json_log, "\"%02X:%02X:%02X:%02X:%02X:%02X\"", eh->ether_src[0],
        eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
        eh->ether_src[4], eh->ether_src[5]);
    return true;
}

static bool ff_eth_type(const Args& a)
{
    if ( !(a.pkt->proto_bits & PROTO_BIT__ETH) )
        return false;

    const eth::EtherHdr* eh = layer::get_eth_layer(a.pkt);

    print_label(a, "eth_type");
    TextLog_Print(json_log, "\"0x%X\"", ntohs(eh->ether_type));
    return true;
}

static bool ff_flowstart_time(const Args& a)
{
    if (a.pkt->flow)
    {
        print_label(a, "flowstart_time");
        TextLog_Print(json_log, "%ld", a.pkt->flow->flowstats.start_time.tv_sec);
        return true;
    }
    return false;
}

static bool ff_geneve_vni(const Args& a)
{
    if (a.pkt->proto_bits & PROTO_BIT__GENEVE)
    {
        print_label(a, "geneve_vni");
        TextLog_Print(json_log, "%u", a.pkt->get_flow_geneve_vni());
    }
    return true;
}

static bool ff_gid(const Args& a)
{
    print_label(a, "gid");
    TextLog_Print(json_log, "%u",  a.event.get_gid());
    return true;
}

static bool ff_icmp_code(const Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_code");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.icmph->code);
        return true;
    }
    return false;
}

static bool ff_icmp_id(const Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_id");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.icmph->s_icmp_id));
        return true;
    }
    return false;
}

static bool ff_icmp_seq(const Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_seq");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.icmph->s_icmp_seq));
        return true;
    }
    return false;
}

static bool ff_icmp_type(const Args& a)
{
    if (a.pkt->ptrs.icmph )
    {
        print_label(a, "icmp_type");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.icmph->type);
        return true;
    }
    return false;
}

static bool ff_iface(const Args& a)
{
    print_label(a, "iface");
    TextLog_Quote(json_log, SFDAQ::get_input_spec());
    return true;
}

static bool ff_ip_id(const Args& a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "ip_id");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.id());
        return true;
    }
    return false;
}

static bool ff_ip_len(const Args& a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "ip_len");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.pay_len());
        return true;
    }
    return false;
}

static bool ff_msg(const Args& a)
{
    print_label(a, "msg");
    TextLog_Puts(json_log, a.msg);
    return true;
}

static bool ff_mpls(const Args& a)
{
    uint32_t mpls;

    if (a.pkt->flow)
        mpls = a.pkt->flow->key->mplsLabel;

    else if ( a.pkt->proto_bits & PROTO_BIT__MPLS )
        mpls = a.pkt->ptrs.mplsHdr.label;

    else
        return false;

    print_label(a, "mpls");
    TextLog_Print(json_log, "%u", mpls);
    return true;
}

static bool ff_pkt_gen(const Args& a)
{
    print_label(a, "pkt_gen");
    TextLog_Quote(json_log, a.pkt->get_pseudo_type());
    return true;
}

static bool ff_pkt_len(const Args& a)
{
    print_label(a, "pkt_len");

    if (a.pkt->has_ip())
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.dgram_len());
    else
        TextLog_Print(json_log, "%u", a.pkt->dsize);

    return true;
}

static bool ff_pkt_num(const Args& a)
{
    print_label(a, "pkt_num");
    TextLog_Print(json_log, STDu64, a.pkt->context->packet_number);
    return true;
}

static bool ff_priority(const Args& a)
{
    print_label(a, "priority");
    TextLog_Print(json_log, "%u", a.event.get_priority());
    return true;
}

static bool ff_proto(const Args& a)
{
    print_label(a, "proto");
    TextLog_Quote(json_log, a.pkt->get_type());
    return true;
}

static bool ff_rev(const Args& a)
{
    print_label(a, "rev");
    TextLog_Print(json_log, "%u",  a.event.get_rev());
    return true;
}

static bool ff_rule(const Args& a)
{
    print_label(a, "rule");

    uint32_t gid, sid, rev;
    a.event.get_sig_ids(gid, sid, rev);

    TextLog_Print(json_log, "\"%u:%u:%u\"", gid, sid, rev);
    return true;
}

static bool ff_seconds(const Args& a)
{
    print_label(a, "seconds");
    TextLog_Print(json_log, "%ld",  a.pkt->pkth->ts.tv_sec);
    return true;
}

static bool ff_server_bytes(const Args& a)
{
    if (a.pkt->flow)
    {
        print_label(a, "server_bytes");
        TextLog_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.server_bytes);
        return true;
    }
    return false;
}

static bool ff_server_pkts(const Args& a)
{
    if (a.pkt->flow)
    {
        print_label(a, "server_pkts");
        TextLog_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.server_pkts);
        return true;
    }
    return false;
}

static bool ff_service(const Args& a)
{
    const char* svc = "unknown";

    if ( a.pkt->flow and a.pkt->flow->service )
        svc = a.pkt->flow->service;

    print_label(a, "service");
    TextLog_Quote(json_log, svc);
    return true;
}

static bool ff_sgt(const Args& a)
{
    if (a.pkt->proto_bits & PROTO_BIT__CISCO_META_DATA)
    {
        const cisco_meta_data::CiscoMetaDataHdr* cmdh = layer::get_cisco_meta_data_layer(a.pkt);
        print_label(a, "sgt");
        TextLog_Print(json_log, "%hu", cmdh->sgt_val());
        return true;
    }
    return false;
}

static bool ff_sid(const Args& a)
{
    print_label(a, "sid");
    TextLog_Print(json_log, "%u",  a.event.get_sid());
    return true;
}

static bool ff_src_addr(const Args& a)
{
    if ( a.pkt->has_ip() or a.pkt->is_data() )
    {
        SfIpString ip_str;
        print_label(a, "src_addr");
        TextLog_Quote(json_log, a.pkt->ptrs.ip_api.get_src()->ntop(ip_str));
        return true;
    }
    return false;
}

static bool ff_src_ap(const Args& a)
{
    SfIpString addr = "";
    unsigned port = 0;

    if ( a.pkt->has_ip() or a.pkt->is_data() )
        a.pkt->ptrs.ip_api.get_src()->ntop(addr);

    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
        port = a.pkt->ptrs.sp;

    print_label(a, "src_ap");
    TextLog_Print(json_log, "\"%s:%u\"", addr, port);
    return true;
}

static bool ff_src_port(const Args& a)
{
    if ( a.pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
    {
        print_label(a, "src_port");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.sp);
        return true;
    }
    return false;
}

static bool ff_target(const Args& a)
{
    SfIpString addr = "";
    bool src;

    if ( !a.event.get_target(src) )
        return false;

    if ( src )
        a.pkt->ptrs.ip_api.get_src()->ntop(addr);

    else
        a.pkt->ptrs.ip_api.get_dst()->ntop(addr);

    print_label(a, "target");
    TextLog_Quote(json_log, addr);
    return true;
}

static bool ff_tcp_ack(const Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_ack");
        TextLog_Print(json_log, "%u", ntohl(a.pkt->ptrs.tcph->th_ack));
        return true;
    }
    return false;
}

static bool ff_tcp_flags(const Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        char tcpFlags[9];
        a.pkt->ptrs.tcph->stringify_flags(tcpFlags);

        print_label(a, "tcp_flags");
        TextLog_Quote(json_log, tcpFlags);
        return true;
    }
    return false;
}

static bool ff_tcp_len(const Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_len");
        TextLog_Print(json_log, "%u", (a.pkt->ptrs.tcph->off()));
        return true;
    }
    return false;
}

static bool ff_tcp_seq(const Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_seq");
        TextLog_Print(json_log, "%u", ntohl(a.pkt->ptrs.tcph->th_seq));
        return true;
    }
    return false;
}

static bool ff_tcp_win(const Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        print_label(a, "tcp_win");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.tcph->th_win));
        return true;
    }
    return false;
}

static bool ff_timestamp(const Args& a)
{
    print_label(a, "timestamp");
    TextLog_Putc(json_log, '"');
    LogTimeStamp(json_log, a.pkt);
    TextLog_Putc(json_log, '"');
    return true;
}

static bool ff_tos(const Args& a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "tos");
        TextLog_Print(json_log, "%u", a.pkt->ptrs.ip_api.tos());
        return true;
    }
    return false;
}

static bool ff_ttl(const Args& a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "ttl");
        TextLog_Print(json_log, "%u",a.pkt->ptrs.ip_api.ttl());
        return true;
    }
    return false;
}

static bool ff_udp_len(const Args& a)
{
    if (a.pkt->ptrs.udph )
    {
        print_label(a, "udp_len");
        TextLog_Print(json_log, "%u", ntohs(a.pkt->ptrs.udph->uh_len));
        return true;
    }
    return false;
}

static bool ff_vlan(const Args& a)
{
    print_label(a, "vlan");
    TextLog_Print(json_log, "%hu", a.pkt->get_flow_vlan_id());
    return true;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

typedef bool (*JsonFunc)(const Args&);

static const JsonFunc json_func[] =
{
    ff_action, ff_class, ff_b64_data, ff_buffer_names, ff_buffers, ff_buffers_names,
    ff_client_bytes, ff_client_pkts, ff_dir,
    ff_dst_addr, ff_dst_ap, ff_dst_port, ff_eth_dst, ff_eth_len, ff_eth_src,
    ff_eth_type, ff_flowstart_time, ff_geneve_vni, ff_gid, ff_icmp_code, ff_icmp_id, ff_icmp_seq,
    ff_icmp_type, ff_iface, ff_ip_id, ff_ip_len, ff_msg, ff_mpls, ff_pkt_gen, ff_pkt_len,
    ff_pkt_num, ff_priority, ff_proto, ff_rev, ff_rule, ff_seconds, ff_server_bytes,
    ff_server_pkts, ff_service, ff_sgt, ff_sid, ff_src_addr, ff_src_ap, ff_src_port,
    ff_target, ff_tcp_ack, ff_tcp_flags,ff_tcp_len, ff_tcp_seq, ff_tcp_win, ff_timestamp,
    ff_tos, ff_ttl, ff_udp_len, ff_vlan
};

#define json_range \
    "action | class | b64_data | buffer_names | buffers | buffers_names | client_bytes | client_pkts | dir | " \
    "dst_addr | dst_ap | dst_port | eth_dst | eth_len | eth_src | " \
    "eth_type | flowstart_time | geneve_vni | gid | icmp_code | icmp_id | icmp_seq | " \
    "icmp_type | iface | ip_id | ip_len | msg | mpls | pkt_gen | pkt_len | " \
    "pkt_num | priority | proto | rev | rule | seconds | server_bytes | " \
    "server_pkts | service | sgt| sid | src_addr | src_ap | src_port | " \
    "target | tcp_ack | tcp_flags | tcp_len | tcp_seq | tcp_win | timestamp | " \
    "tos | ttl | udp_len | vlan"

#define json_deflt \
    "timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action"

//-------------------------------------------------------------------------
// translation stuff
//-------------------------------------------------------------------------

enum BuffersToOutput
{
    BUFFERS_NONE = 0,
    BUFFERS_RULE,
    BUFFERS_INSPECTOR,
    BUFFERS_BOTH,
};

static const Parameter s_params[] =
{
    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },

    { "fields", Parameter::PT_MULTI, json_range, json_deflt,
      "selected fields will be output in given order left to right" },

    { "buffers", Parameter::PT_ENUM, "none | rule | inspector | both", "both",
      "output IPS buffer dump (evaluated by IPS rule or an inspector)" },

    { "buffers_depth", Parameter::PT_INT, "0:maxSZ", "0",
      "number of IPS buffer bytes to dump per buffer (0 is unlimited)" },

    { "limit", Parameter::PT_INT, "0:maxSZ", "0",
      "set maximum size in MB before rollover (0 is unlimited)" },

    { "separator", Parameter::PT_STRING, nullptr, ", ",
      "separate fields with this character sequence" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event in json format"

class JsonModule : public Module
{
public:
    JsonModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

public:
    bool file = false;
    size_t limit = 0;
    string sep;
    vector<JsonFunc> fields;
    size_t buffers_depth = 0;
    int buffers_opt = BUFFERS_BOTH;
};

bool JsonModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("fields") )
    {
        string tok;
        v.set_first_token();
        fields.clear();

        while ( v.get_next_token(tok) )
        {
            int i = Parameter::index(json_range, tok.c_str());
            if ( i >= 0 )
                fields.emplace_back(json_func[i]);
        }
    }

    else if ( v.is("buffers") )
        buffers_opt = v.get_uint8();

    else if ( v.is("limit") )
        limit = v.get_size() * 1024 * 1024;

    else if ( v.is("buffers_depth") )
        buffers_depth = v.get_size();

    else if ( v.is("separator") )
        sep = v.get_string();

    return true;
}

bool JsonModule::begin(const char*, int, SnortConfig*)
{
    file = false;
    limit = 0;
    sep = ", ";
    buffers_opt = BUFFERS_BOTH;
    buffers_depth = 0;

    if ( fields.empty() )
    {
        Value v(json_deflt);
        string tok;
        v.set_first_token();

        while ( v.get_next_token(tok) )
        {
            int i = Parameter::index(json_range, tok.c_str());
            if ( i >= 0 )
                fields.emplace_back(json_func[i]);
        }
    }
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class JsonLogger : public Logger
{
public:
    JsonLogger(JsonModule*);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, const Event&) override;

public:
    string file;
    unsigned long limit;
    vector<JsonFunc> fields;
    string sep;
    unsigned long buffers_depth;
    int buffers_opt;
};

JsonLogger::JsonLogger(JsonModule* m) : file(m->file ? F_NAME : "stdout"), limit(m->limit),
    fields(std::move(m->fields)), sep(m->sep), buffers_depth(m->buffers_depth),
    buffers_opt(m->buffers_opt)
{ }

void JsonLogger::open()
{
    json_log = TextLog_Init(file.c_str(), LOG_BUFFER, limit);
}

void JsonLogger::close()
{
    if ( json_log )
        TextLog_Term(json_log);
}

void JsonLogger::alert(Packet* p, const char* msg, const Event& event)
{
    Args a = { p, msg, event, false, this, false, {}, buffers_depth, buffers_opt };
    TextLog_Putc(json_log, '{');

    for ( JsonFunc f : fields )
    {
        f(a);
        a.comma = true;
    }

    TextLog_Print(json_log, " }\n");
    TextLog_Flush(json_log);
}

//-------------------------------------------------------------------------
// buffer collection helpers
//-------------------------------------------------------------------------

static bool should_dump_buffer(const char* buf_name, const char** buffs_to_dump)
{
    if ( !buf_name or !buffs_to_dump )
        return false;

    size_t cmp_idx = 0;

    while ( buffs_to_dump[cmp_idx] )
        if ( !strcmp(buf_name, buffs_to_dump[cmp_idx++]) )
            return true;

    return false;
}

static void add_buffer(std::vector<BufferEntry>& list, const char* buf_name, const char* data, size_t len)
{
    if ( !buf_name or !buf_name[0] or !data )
        return;

    std::string buf_data(data, len);

    auto it = std::find_if(list.begin(), list.end(), [buf_name](const BufferEntry& e) {
        return e.name == buf_name;
    });

    if ( it != list.end() )
    {
        if ( it->data == buf_data )
            return;
        if ( buf_data.size() > it->data.size() && buf_data.find(it->data) != std::string::npos )
        {
            it->data = std::move(buf_data);
            return;
        }
        if ( it->data.find(buf_data) != std::string::npos )
            return;
    }

    list.push_back({ buf_name, std::move(buf_data) });
}

static void collect_buffers(const Args& a)
{
    if ( a.buffers_collected )
        return;
    a.buffers_collected = true;

    Packet* p = a.pkt;
    if ( !p )
        return;

    int opt = a.buffers_opt;
    unsigned long depth = a.buffers_depth;

    if ( opt == BUFFERS_NONE )
        return;

    bool do_rule = (opt == BUFFERS_RULE || opt == BUFFERS_BOTH || opt == -1);
    bool do_insp = (opt == BUFFERS_INSPECTOR || opt == BUFFERS_BOTH || opt == -1);

    if ( do_rule and p->context )
    {
        const char** buffs_to_dump = a.event.get_buffers();
        if ( buffs_to_dump and buffs_to_dump[0] )
        {
            auto& all_buffs = p->context->matched_buffers;
            std::vector<MatchedBuffer*> to_dump;

            for ( auto& b : all_buffs )
            {
                if ( should_dump_buffer(b.name, buffs_to_dump) and to_dump.cend() ==
                    find_if(to_dump.begin(), to_dump.end(), [b](MatchedBuffer*& cmp_b)
                    {
                        bool same_buffers = cmp_b->name == b.name and cmp_b->data == b.data;
                        if ( same_buffers and cmp_b->size < b.size )
                        {
                            cmp_b->size = b.size;
                            return true;
                        }
                        return same_buffers;
                    }) )
                    to_dump.push_back(&b);
            }

            for ( auto b : to_dump )
            {
                const char* buf_name = b->name;
                if ( !buf_name or !b->data )
                    continue;

                size_t log_depth = depth && depth < b->size ? depth : b->size;
                add_buffer(a.cached_buffers, buf_name, (const char*)b->data, log_depth);
            }
        }
    }

    if ( do_insp and p->flow and p->flow->gadget )
    {
        Inspector* gadget = p->flow->gadget;
        const char** buffers = gadget->get_api()->buffers;

        if ( buffers )
        {
            for ( ; *buffers; buffers++ )
            {
                InspectionBuffer buf;
                if ( gadget->get_buf(*buffers, p, buf) and buf.data and buf.len > 0 )
                {
                    size_t log_depth = depth && depth < buf.len ? depth : buf.len;
                    add_buffer(a.cached_buffers, *buffers, (const char*)buf.data, log_depth);
                }
            }
        }
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new JsonModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* json_ctor(Module* mod)
{ return new JsonLogger((JsonModule*)mod); }

static void json_dtor(Logger* p)
{ delete p; }

static LogApi json_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    json_ctor,
    json_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* alert_json[] =
#endif
{
    &json_api.base,
    nullptr
};

