//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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

// tcp_spliceer_module.h author Vytalii Horbatov <vhorba@softserveinc.com>

#ifndef TCP_SPLICER_MODULE_H
#define TCP_SPLICER_MODULE_H

#include "framework/module.h"

#define MOD_NAME "tcp_splicer"
#define MOD_HELP "stands between clients of TCP session"

#define GID_TCP_SPLICER 152

extern THREAD_LOCAL SimpleStats tcp_splicer_stats;
extern THREAD_LOCAL snort::ProfileStats tcps_perf_stats;

struct TCPSplicerConfig
{
    uint32_t max_entries_in_table;
};

class TCPSplicerModule : public snort::Module
{
public:
    TCPSplicerModule();
    ~TCPSplicerModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    TCPSplicerConfig* get_config();

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    unsigned get_gid() const override
    { return GID_TCP_SPLICER; }

    const snort::RuleMap* get_rules() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return INSPECT; }

private:
    TCPSplicerConfig* config;
};

#endif

