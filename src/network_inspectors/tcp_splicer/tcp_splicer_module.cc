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

// tcp_spliceer_module.cc author Vytalii Horbatov <vhorba@softserveinc.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_splicer_module.h"

using namespace snort;

THREAD_LOCAL SimpleStats tcp_splicer_stats;

//-------------------------------------------------------------------------
// tcp_splicer stuff
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "max_entries_in_table", Parameter::PT_INT, "0:4294967295", nullptr,
      "configure size of cache" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap s_rules[] =
{
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// tcp_splicer module
//-------------------------------------------------------------------------

TCPSplicerModule::TCPSplicerModule() :
    Module(MOD_NAME, MOD_HELP, s_params)
{
    config = nullptr;
}

TCPSplicerModule::~TCPSplicerModule()
{
    if ( config )
        delete config;
}

const RuleMap* TCPSplicerModule::get_rules() const
{ return s_rules; }

ProfileStats* TCPSplicerModule::get_profile() const
{ return &tcps_perf_stats; }

bool TCPSplicerModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("max_entries_in_table") )
        return true;
    else
        return false;

    return true;
}

TCPSplicerConfig* TCPSplicerModule::get_config()
{
    TCPSplicerConfig* temp = config;
    config = nullptr;
    return temp;
}

bool TCPSplicerModule::begin(const char*, int, SnortConfig*)
{
    if ( !config )
    {
        config = new TCPSplicerConfig;
    }
    return true;
}

bool TCPSplicerModule::end(const char*, int idx, SnortConfig*)
{
    return true;
}

const PegInfo* TCPSplicerModule::get_pegs() const
{ return simple_pegs; }

PegCount* TCPSplicerModule::get_counts() const
{ return (PegCount*)&tcp_splicer_stats; }

