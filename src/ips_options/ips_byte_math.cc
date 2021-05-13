//--------------------------------------------------------------------------
// Copyright (C) 2015-2021 Cisco and/or its affiliates. All rights reserved.
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
// ips_byte_math.cc authors  Maya Dagon   <mdagon@cisco.com>
//                           Krishnakanth <vkambala@cisco.com>
//                           Seshaiah     <serugu@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/endianness.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "utils/util.h"

#include "extract.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#include "service_inspectors/dce_rpc/dce_common.h"
#endif

using namespace snort;
using namespace std;

#define s_name "byte_math"

#define s_help \
    "rule option to perform mathematical operations on extracted value and a specified \
value or existing variable"

enum BM_Oper // must match the exact order in Parameter table - i.e "+|-|*|/|<<|>>"
{
    BM_PLUS = 0,
    BM_MINUS,
    BM_MULTIPLY,
    BM_DIVIDE,
    BM_LEFT_SHIFT,
    BM_RIGHT_SHIFT
};

static THREAD_LOCAL ProfileStats byteMathPerfStats;

struct ByteMathData
{
    uint32_t bytes_to_extract;
    uint32_t rvalue;
    int32_t offset;
    uint32_t bitmask_val;
    char* result_name;
    BM_Oper oper;
    bool relative_flag;
    bool string_convert_flag;
    uint8_t base;
    uint8_t endianess;
    int8_t result_var;
    int8_t rvalue_var;
    int8_t offset_var;
};

class ByteMathOption : public IpsOption
{
public:
    ByteMathOption(const ByteMathData& c) : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_USE),
        config(c) { }

    ~ByteMathOption() override
    { snort_free(config.result_name); }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return config.relative_flag; }

    EvalStatus eval(Cursor&, Packet*) override;

private:
    const ByteMathData config;
};

uint32_t ByteMathOption::hash() const
{
    uint32_t a = config.bytes_to_extract;
    uint32_t b = config.rvalue;
    uint32_t c = config.oper;

    mix(a,b,c);

    a += config.offset;
    b += ((uint32_t) config.rvalue_var << 24 |
        (uint32_t) config.offset_var << 16 |
        (uint32_t) config.result_var << 8 |
        config.endianess);
    c += config.base;

    mix(a,b,c);

    a += config.bitmask_val;
    b += config.relative_flag;
    c += config.string_convert_flag;

    mix(a,b,c);

    a += IpsOption::hash();

    finalize(a,b,c);
    return c;
}

bool ByteMathOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const ByteMathOption& rhs = (const ByteMathOption&)ips;
    const ByteMathData* left = &config;
    const ByteMathData* right = &rhs.config;

    if (( left->bytes_to_extract == right->bytes_to_extract) &&
        ( left->rvalue == right->rvalue) &&
        ( left->oper == right->oper) &&
        ( left->offset == right->offset) &&
        ( left->relative_flag == right->relative_flag) &&
        ( left->string_convert_flag == right->string_convert_flag) &&
        ( left->endianess == right->endianess) &&
        ( left->base == right->base) &&
        ( left->bitmask_val == right->bitmask_val) &&
        ( left->rvalue_var == right->rvalue_var) &&
        ( left->offset_var == right->offset_var) &&
        ( left->result_var == right->result_var))
    {
        return true;
    }

    return false;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

IpsOption::EvalStatus ByteMathOption::eval(Cursor& c, Packet* p)
{
    RuleProfile profile(byteMathPerfStats);

    if (p == nullptr)
        return NO_MATCH;

    const uint8_t* start = c.buffer();
    int dsize = c.size();

    const uint8_t* ptr = config.relative_flag ? c.start() : c.buffer();
    const uint8_t* end = start + dsize;

    /* Get values from ips options variables, if present. */
    uint32_t rvalue;
    if (config.rvalue_var >= 0 && config.rvalue_var < NUM_IPS_OPTIONS_VARS)
    {
        GetVarValueByIndex(&rvalue, config.rvalue_var);
        if (rvalue == 0 and config.oper == BM_DIVIDE)
            return NO_MATCH;
    }
    else
        rvalue = config.rvalue;

    int32_t offset;
    if (config.offset_var >= 0 && config.offset_var < NUM_IPS_OPTIONS_VARS)
    {
        // Rule options variables are kept as uint32_t,
        // in order to support full range for unsigned options.
        // Signed options do a cast to int32_t after getting the value.
        // The range limitation should be taken into consideration when writing a rule
        // with an option that is read from a variable.
        uint32_t extract_offset;
        GetVarValueByIndex(&extract_offset, config.offset_var);
        offset = (int32_t)extract_offset;
    }
    else
        offset = config.offset;

    ptr += offset;

    // check bounds
    if (ptr < start || ptr >= end)
        return NO_MATCH;

    uint8_t endian = config.endianess;
    if (config.endianess == ENDIAN_FUNC)
    {
        if (!p->endianness ||
            !p->endianness->get_offset_endianness(ptr - p->data, endian))
            return NO_MATCH;
    }

    // do the extraction
    uint32_t value;

    if (!config.string_convert_flag)
    {
        if (byte_extract(endian, config.bytes_to_extract, ptr, start, end, &value) < 0)
            return NO_MATCH;
    }
    else
    {
        if (string_extract(config.bytes_to_extract, config.base, ptr, start, end, &value) < 0)
            return NO_MATCH;
    }

    if (config.bitmask_val != 0)
    {
        uint32_t num_tailing_zeros_bitmask = getNumberTailingZerosInBitmask(config.bitmask_val);
        value = value & config.bitmask_val;
        if ( value && num_tailing_zeros_bitmask )
        {
            value = value >> num_tailing_zeros_bitmask;
        }
    }

    // Note: all of the operations are done on uint32_t.
    // If the rule isn't written correctly, there is a risk for wrap around.
    switch (config.oper)
    {
    case BM_PLUS:
        if( value + rvalue < value )
        {
            return NO_MATCH;
        }
        else
        {
            value += rvalue;
            break;
        }
    case BM_MINUS:
        if( value < rvalue )
        {
            return NO_MATCH;
        }
        else
        {
            value -= rvalue;
            break;
        }
    case BM_MULTIPLY:
        if ( value != 0 and rvalue != 0 and (((value * rvalue) / rvalue) != value) )
        {
            return NO_MATCH;
        }
        else
        {
            value *= rvalue;
            break;
        }
    case BM_DIVIDE: value /= rvalue;
            break;

    case BM_LEFT_SHIFT: value <<= rvalue;
            break;

    case BM_RIGHT_SHIFT: value >>= rvalue;
            break;
    }

    SetVarValueByIndex(value, config.result_var);

    return MATCH;
}

//-------------------------------------------------------------------------
// Parsing utils - used by ::set
//-------------------------------------------------------------------------

static void parse_base(uint8_t value, ByteMathData& idx)
{
    assert(value <= 2);
    int base[] = { 16, 10, 8 };
    idx.base = base[value];
}

static void parse_endian(uint8_t value, ByteMathData& idx)
{
    assert(value <= 1);
    int endian[] = { ENDIAN_BIG, ENDIAN_LITTLE };
    set_byte_order(idx.endianess, endian[value], "byte_math");
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "bytes", Parameter::PT_INT, "1:10", nullptr,
      "number of bytes to pick up from the buffer" },

    { "offset", Parameter::PT_STRING, nullptr, nullptr,
      "number of bytes into the buffer to start processing" },

    { "oper", Parameter::PT_ENUM, "+|-|*|/|<<|>>", nullptr,
      "mathematical operation to perform" },

    { "rvalue", Parameter::PT_STRING, nullptr, nullptr,
      "value to use mathematical operation against" },

    { "result", Parameter::PT_STRING, nullptr, nullptr,
      "name of the variable to store the result" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "offset from cursor instead of start of buffer" },

    { "endian", Parameter::PT_ENUM, "big|little", nullptr,
      "specify big/little endian" },

    { "dce", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dcerpc2 determines endianness" },

    { "string", Parameter::PT_ENUM, "hex|dec|oct", nullptr,
      "convert extracted string to dec/hex/oct" },

    { "bitmask", Parameter::PT_INT, "0x1:0xFFFFFFFF", nullptr,
      "applies as bitwise AND to the extracted value before storage in 'name'" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ByteMathModule : public Module
{
public:
    ByteMathModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &byteMathPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    ByteMathData data = {};
    string rvalue_var;
    string off_var;
};

bool ByteMathModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    rvalue_var.clear();
    off_var.clear();
    return true;
}


bool ByteMathModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("bytes") )
        data.bytes_to_extract = v.get_uint8();

    else if ( v.is("oper") )
        data.oper = (BM_Oper)v.get_uint8();

    else if ( v.is("rvalue") )
    {
        long n;
        if ( v.strtol(n) )
        {
            if (n == 0)
                return false;
            data.rvalue = n;
        }
        else
            rvalue_var = v.get_string();
    }
    else if ( v.is("offset") )
    {
        long n;
        if ( v.strtol(n) )
            data.offset = n;
        else
            off_var = v.get_string();
    }
    else if ( v.is("relative") )
        data.relative_flag = true;

    else if ( v.is("dce") )
        set_byte_order(data.endianess, ENDIAN_FUNC, "byte_math");

    else if ( v.is("string") )
    {
        data.string_convert_flag = true;
        parse_base(v.get_uint8(), data);
    }
    else if ( v.is("endian") )
        parse_endian(v.get_uint8(), data);

    else if ( v.is("bitmask") )
        data.bitmask_val = v.get_uint32();

    else if ( v.is("result") )
        data.result_name = snort_strdup(v.get_string());

    else
        return false;

    return true;
}

/* Checks a ByteMathData instance for errors. */
static bool ByteMathVerify(ByteMathData* data)
{
    if (!data->result_name)
    {
        ParseError("result variable missing");
        return false;
    }

    if (isdigit(data->result_name[0]))
    {
        ParseError("byte_math rule option has a name which starts with a digit. "
            "Variable names must start with a letter.");
        return false;
    }

    if ( ((data->oper == BM_LEFT_SHIFT) || (data->oper == BM_RIGHT_SHIFT)) &&
        (data->rvalue > 32))
    {
        ParseError("Number of bits in rvalue input [%u] should be less than 32 "
            "bits for operator", data->rvalue);
        return false;
    }

    if (((data->oper == BM_LEFT_SHIFT) || (data->oper == BM_RIGHT_SHIFT)) &&
        (data->bytes_to_extract > 4))
    {
        ParseError("for operators << and  >> valid bytes_to_extract input range is"
            " 1 to 4 bytes");
        return false;
    }

    if (data->bytes_to_extract > MAX_BYTES_TO_GRAB && !data->string_convert_flag)
    {
        ParseError("byte_math rule option cannot extract more than %d bytes without valid"
            " string prefix.", MAX_BYTES_TO_GRAB);
        return false;
    }

    if (numBytesInBitmask(data->bitmask_val) > data->bytes_to_extract)
    {
        ParseError("Number of bytes in \"bitmask\" value is greater than bytes to extract.");
        return false;
    }

    return true;
}

bool ByteMathModule::end(const char*, int, SnortConfig*)
{
    if ( rvalue_var.empty() )
        data.rvalue_var = IPS_OPTIONS_NO_VAR;
    else
    {
        data.rvalue_var = GetVarByName(rvalue_var.c_str());

        if (data.rvalue_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "byte_math", rvalue_var.c_str());
            return false;
        }
    }

    if ( off_var.empty() )
        data.offset_var = IPS_OPTIONS_NO_VAR;
    else
    {
        data.offset_var = GetVarByName(off_var.c_str());

        if (data.offset_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "byte_math", off_var.c_str());
            return false;
        }
    }

    if ( !data.endianess )
        data.endianess = ENDIAN_BIG;

    return ByteMathVerify(&data);
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ByteMathModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* byte_math_ctor(Module* p, OptTreeNode*)
{
    ByteMathModule* m = (ByteMathModule*)p;
    ByteMathData& data = m->data;

    data.result_var = AddVarNameToList(data.result_name);
    if (data.result_var == IPS_OPTIONS_NO_VAR)
    {
        ParseError("Rule has more than %d variables.", NUM_IPS_OPTIONS_VARS);
        return nullptr;
    }
    return new ByteMathOption(m->data);
}

static void byte_math_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi byte_math_api =
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
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    byte_math_ctor,
    byte_math_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_byte_math[] =
#endif
{
    &byte_math_api.base,
    nullptr
};

//-------------------------------------------------------------------------
// UNIT TESTS
//-------------------------------------------------------------------------
#ifdef UNIT_TEST

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------
class ByteMathDataMatcher
    : public Catch::Matchers::Impl::MatcherBase<ByteMathData>
{
   public:
    ByteMathDataMatcher(const ByteMathData& value) : m_value(value) {}

    bool match(ByteMathData const& rhs) const override
    {
        return ((m_value.bytes_to_extract == rhs.bytes_to_extract) &&
                (m_value.rvalue == rhs.rvalue) && (m_value.oper == rhs.oper) &&
                (m_value.offset == rhs.offset) &&
                (m_value.relative_flag == rhs.relative_flag) &&
                (m_value.string_convert_flag == rhs.string_convert_flag) &&
                (m_value.endianess == rhs.endianess) &&
                (m_value.base == rhs.base) &&
                (m_value.bitmask_val == rhs.bitmask_val) &&
                (m_value.rvalue_var == rhs.rvalue_var) &&
                (m_value.offset_var == rhs.offset_var) &&
                (m_value.result_var == rhs.result_var));
    }

    std::string describe() const override
    {
        std::ostringstream ss;
        ss << "settings is equals to:\n";
        ss << "bytes_to_extract : " << m_value.bytes_to_extract << ";\n";
        ss << "rvalue : " << m_value.rvalue << ";\n";
        ss << "oper : " << m_value.oper << ";\n";
        ss << "offset : " << m_value.offset << ";\n";
        ss << "relative_flag : " << m_value.relative_flag << ";\n";
        ss << "string_convert_flag : " << m_value.string_convert_flag << ";\n";
        ss << "endianess : " << m_value.endianess << ";\n";
        ss << "base : " << m_value.base << ";\n";
        ss << "bitmask_val : " << m_value.bitmask_val << ";\n";
        ss << "rvalue_var : " << m_value.rvalue_var << ";\n";
        ss << "offset_var : " << m_value.offset_var << ";\n";
        ss << "result_var : " << m_value.result_var << ";\n";
        return ss.str();
    }

   private:
    ByteMathData m_value;
};

ByteMathDataMatcher ByteMathDataEquals(const ByteMathData& value)
{
    return {value};
}

class SetBufferOptionHelper : public IpsOption
{
   public:
    SetBufferOptionHelper(const char* value)
        : IpsOption(value, RULE_OPTION_TYPE_BUFFER_SET)
    {
    }
};

//-------------------------------------------------------------------------
// option tests
//-------------------------------------------------------------------------

TEST_CASE("ByteMathOption::operator== valid", "[byte_math_tests]")
{
    SetBufferOptionHelper set_buf("test");

    char* lhs_name = new char[9];
    strcpy(lhs_name, "test_lhs");
    ByteMathData data_lhs = {0,25, 0, 0, lhs_name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
    IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
    ByteMathOption lhs(data_lhs);

    char* rhs_name = new char[9];
    strcpy(rhs_name, "test_rhs");
    ByteMathData data_rhs = {0, 25, 0, 0, rhs_name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
        IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
    ByteMathOption rhs(data_rhs);

    CHECK(lhs == lhs);
    CHECK(lhs == rhs);
    CHECK(rhs == lhs);
}

TEST_CASE("ByteMathOption::operator== invalid", "[byte_math_tests]")
{
    SetBufferOptionHelper set_buf("test");

    char* lhs_name = new char[5];
    strcpy(lhs_name, "test");
    ByteMathData data_lhs = {0, 25, 0, 0, lhs_name, BM_PLUS, 0, 0, 0, ENDIAN_BIG, 
        IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
    ByteMathOption lhs = (data_lhs);

    char* rhs_name = new char[5];
    strcpy(rhs_name, "test");

    SECTION("not equal to IpsOption object") { CHECK(!(lhs == set_buf)); }
    SECTION("all fields is differ")
    {
        delete rhs_name;
        char* rhs_name = new char[5];
        strcpy(rhs_name, "tset");
        ByteMathData data_rhs = {2, 25, 2, 255, rhs_name, BM_MULTIPLY, 1,  
            1, 8, ENDIAN_LITTLE, 1, 1, 1};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("bytes_to_grab is differ")
    {
        ByteMathData data_rhs = {2, 25, 0, 0, rhs_name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("rvalue is differ")
    {
        ByteMathData data_rhs = {0, 15, 0, 0, rhs_name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("offset is differ")
    {
        ByteMathData data_rhs = {0, 25, 3, 0, rhs_name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("bitmask is differ")
    {
        ByteMathData data_rhs = {0, 25, 0, 255, rhs_name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("result_name is differ")
    {
        delete rhs_name;
        char* rhs_name = new char[5];
        strcpy(rhs_name, "tset");
        ByteMathData data_rhs = {0, 25, 0, 255, rhs_name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("operation is differ")
    {
        ByteMathData data_rhs = {0, 25, 0, 0, rhs_name, BM_DIVIDE, 0, 0, 0, ENDIAN_BIG,
            IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("relative_flag is differ")
    {
        ByteMathData data_rhs = {0, 25, 0, 0, rhs_name, BM_PLUS, 1, 0, 0, ENDIAN_BIG,
            IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("string_convert_flag is differ")
    {
        ByteMathData data_rhs = {0, 25, 0, 0, rhs_name, BM_PLUS, 0, 1, 0, ENDIAN_BIG,
            IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("base is differ")
    {
        ByteMathData data_rhs = {0, 25, 0, 0, rhs_name, BM_PLUS, 0, 0, 8, ENDIAN_BIG,
            IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("endianess is differ")
    {
        ByteMathData data_rhs = {0, 25, 0, 0, rhs_name, BM_PLUS, 0, 0, 0, ENDIAN_LITTLE,
            IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("result_var is differ")
    {
        ByteMathData data_rhs = {0, 25, 0, 0, rhs_name, BM_PLUS, 0, 0, 0,  ENDIAN_BIG, 
            0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("rvalue_var is differ")
    {
        ByteMathData data_rhs = {0, 25, 0, 0, rhs_name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            IPS_OPTIONS_NO_VAR, 1, IPS_OPTIONS_NO_VAR};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
    SECTION("offset_var is differ")
    {
        ByteMathData data_rhs = {0, 25, 0, 0, rhs_name, BM_PLUS, 0, 0,  0, ENDIAN_BIG,
            IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR, 0};
        ByteMathOption rhs(data_rhs);
        CHECK(!(lhs == rhs));
        CHECK(!(rhs == lhs));
    }
}

TEST_CASE("ByteMathOption::hash", "[byte_math_tests]")
{
    SetBufferOptionHelper set_buf("test");

    char* lhs_name = new char[5];
    strcpy(lhs_name, "test");
    ByteMathData data_lhs = {2, 25, 2, 255, lhs_name, BM_MULTIPLY, 1, 1, 8,
        ENDIAN_LITTLE, 1, 1, 1};
    ByteMathOption lhs(data_lhs);

    SECTION("hash codes of any two equal objects are equal")
    {
        char* rhs_name = new char[5];
        strcpy(rhs_name, "test");
        ByteMathData data_rhs = {2, 25, 2, 255, rhs_name, BM_MULTIPLY, 1, 1, 8,
            ENDIAN_LITTLE, 1, 1,  1};
        ByteMathOption rhs = (data_rhs);

        CHECK(lhs.hash() == lhs.hash());
        CHECK(lhs.hash() == rhs.hash());
    }
}

TEST_CASE("ByteMathOption::eval valid", "[byte_math_tests]")
{
    Packet p;
    p.data = (const uint8_t*)"Lorem 12345";
    p.dsize = 11;
    Cursor c(&p);

    for (unsigned i = 0; i < NUM_IPS_OPTIONS_VARS; ++i)
    {
        SetVarValueByIndex(0, i);
    }
    ClearIpsOptionsVars();

    char* name = new char[5];
    strcpy(name, "test");

    SECTION("1 byte read, all off, operation \"+\", rvalue 1")
    {
        ByteMathData data = {1, 1, 0, 0, name, BM_PLUS, 0, 0, 0, 
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 77);
    }
    SECTION("1 byte read, offset 3, operation \"*\", rvalue 2")
    {
        ByteMathData data = {1, 2, 3, 0, name, BM_MULTIPLY, 0, 0, 0,
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 202);
    }
    SECTION(
        "1 byte read, offset 3, relative, cursor 3, operation \"-\", rvalue 3")
    {
        ByteMathData data = {1, 3, 3, 0, name, BM_MINUS, 1, 0, 0,
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        c.set_pos(3);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 46);
    }
    SECTION(
        "cursor 3, 1 byte read, offset -3, relative, operation \"/\", rvalue 4")
    {
        ByteMathData data = {1, 4, -3, 0, name, BM_DIVIDE, 1, 0, 0,
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        c.set_pos(3);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 19);
    }
    SECTION(
        "1 byte read, offset 6, string conv, base 10, operation \"+\", rvalue 4")
    {
        ByteMathData data = {1, 4, 6, 0, name, BM_PLUS, 0, 1, 10,
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 5);
    }
    SECTION(
        "1 byte read, offset 6, string conv, base 10, operation \"<<\", rvalue 2")
    {
        ByteMathData data = {1, 2, 6, 0, name, BM_LEFT_SHIFT, 0, 1, 10,
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 4);
    }
    SECTION(
        "3 byte read, offset 6, string conv, base 10, operation \">>\", rvalue 1")
    {
        ByteMathData data = {3, 1, 6, 0, name, BM_RIGHT_SHIFT, 0, 1, 10,
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 61);
    }
    SECTION("2 byte read, bitmask 1100110011100011, operation \"+\", rvalue 1")
    {
        ByteMathData data = {2, 1, 0, 52451, name, BM_PLUS, 0, 0, 0,
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 19556);
    }
    SECTION("2 byte read, bitmask 1100110011100000, operation \"-\", rvalue 5")
    {
        ByteMathData data = {2, 5, 0, 52448, name, BM_MINUS, 0, 0, 0,
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 606);
    }
    SECTION("4 bytes read, ENDIAN_LITTLE, operation \"-\", rvalue 5")
    {
        ByteMathData data = {4, 5, 0, 0, name, BM_MINUS, 0, 0, 0, 
            ENDIAN_LITTLE, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 1701998407);
    }
    SECTION("4 bytes read, ENDIAN_FUNC, packet.endianness = "
        "DCERPC_BO_FLAG__LITTLE_ENDIAN, operation \"/\", rvalue 2")
    {
        DceEndianness* auto_endian = new DceEndianness();
        auto_endian->hdr_byte_order = DCERPC_BO_FLAG__LITTLE_ENDIAN;
        auto_endian->data_byte_order = DCERPC_BO_FLAG__LITTLE_ENDIAN;
        p.endianness = auto_endian;
        ByteMathData data = {4, 2, 0, 0, name, BM_DIVIDE, 0, 0, 0,
            ENDIAN_FUNC, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 850999206);
    }
    SECTION("2 bytes read, operation \">>\", result_var = 0, rvalue_var = 1")
    {
        SetVarValueByIndex(3, 1);
        ByteMathData data = {2, 0, 0, 0, name, BM_RIGHT_SHIFT, 0,
            0, 0, ENDIAN_BIG, 0, 1, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 2445);
    }
    SECTION("1 byte read, operation \"<<\", offset_var = 0, result_var = 1")
    {
        SetVarValueByIndex(1, 0);
        ByteMathData data = {1, 1, 0, 0, name, BM_LEFT_SHIFT,
            0, 0, 0, ENDIAN_BIG, 1, IPS_OPTIONS_NO_VAR, 0};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 1);
        CHECK(res == 222);
    }
}

TEST_CASE("ByteMathOption::eval invalid", "[byte_math_tests]")
{
    Packet p;
    p.data = (const uint8_t*)"Lorem 9876";
    p.dsize = 11;
    Cursor c(&p);

    for (unsigned i = 0; i < NUM_IPS_OPTIONS_VARS; ++i)
    {
        SetVarValueByIndex(0, i);
    }
    ClearIpsOptionsVars();

    char* name = new char[5];
    strcpy(name, "test");

    SECTION("packet = nullptr")
    {
        ByteMathData data = {1, 1, 0, 0, name, BM_PLUS, 0, 0, 0,
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, nullptr) == IpsOption::NO_MATCH);
    }
    SECTION("read more than 4 bytes")
    {
        ByteMathData data = {6, 1, 0, 0, name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
    }
    SECTION("check bounds of packet, offset > packet size")
    {
        ByteMathData data = {1, 1, 20, 0, name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
    }
    SECTION("negative offset, without relative flag")
    {
        ByteMathData data = {1, 1, -20, 0, name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
    }
    SECTION("negative offset, out of bounds")
    {
        ByteMathData data = {1, 1, -20, 0, name, BM_PLUS, 1, 0, 0, ENDIAN_BIG,
            0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
    }
    SECTION("check bounds of packet, read 2 bytes, empty packet")
    {
        p.data = (const uint8_t*)"";
        p.dsize = 0;
        Cursor c2(&p);
        ByteMathData data = {2, 1, 0, 0, name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c2, &p) == IpsOption::NO_MATCH);
    }
    SECTION("ENDIAN_FUNC, without definition of endianness in packet")
    {
        ByteMathData data = {1, 1, 0, 0, name, BM_PLUS, 0, 0, 0, ENDIAN_FUNC,
            0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
    }
    SECTION("conversion from string, decimal number, base = 8")
    {
        ByteMathData data = {3, 1, 6, 0, name, BM_PLUS, 0, 1, 8, ENDIAN_BIG,
            0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
    }
    SECTION("rvalue_variable didn't exist")
    {
        ByteMathData data = {1, 1, 0, 0, name, BM_PLUS, 0,
            0, 0, ENDIAN_BIG, 0, 1, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 76);
    }
    SECTION("offset_variable didn't exist")
    {
        ByteMathData data = {1, 1, 1, 0, name, BM_PLUS, 0, 
            0, 0, ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, 1};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 77);
    }
    SECTION("rvalue_variable_index > NUM_IPS_OPTIONS_VARS")
    {
        ByteMathData data = {1, 1, 0, 0, name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            0, NUM_IPS_OPTIONS_VARS + 1, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 77);
    }
    SECTION("offset_variable_index > NUM_IPS_OPTIONS_VARS")
    {
        ByteMathData data = {1, 1, 1, 0, name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            0, IPS_OPTIONS_NO_VAR, NUM_IPS_OPTIONS_VARS + 1};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::MATCH);
        uint32_t res = 0;
        GetVarValueByIndex(&res, 0);
        CHECK(res == 112);
    }
    SECTION("get negative number with MINUS")
    {
        ByteMathData data = {1, 256, 0, 0, name, BM_MINUS, 0, 0, 0, ENDIAN_BIG,
            0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
    }
    SECTION("out of bounds of unit_32t, PLUS")
    {
        ByteMathData data = {1, 4294967295, 0, 0, name, BM_PLUS, 0, 0, 0,
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
    }
    SECTION("out of bounds of unit_32t, MULTIPLY")
    {
        ByteMathData data = {1, 2147483647, 0, 0, name, BM_MULTIPLY, 0, 0, 0,
            ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
    }
    SECTION("dividing on zero in rvalue_var")
    {
        SetVarValueByIndex(1, 0);
        ByteMathData data = {1, 0, 0, 0, name, BM_DIVIDE, 0,
            0, 0, ENDIAN_BIG, 0, 1, IPS_OPTIONS_NO_VAR};
        ByteMathOption opt(data);
        CHECK(opt.eval(c, &p) == IpsOption::NO_MATCH);
    }
}

//-------------------------------------------------------------------------
// module tests
//-------------------------------------------------------------------------

TEST_CASE("ByteMathModule::begin", "[byte_math_tests]")
{
    ByteMathModule obj;
    SECTION("test of \"begin\" method")
    {
        CHECK(obj.begin(nullptr, 0, nullptr));
        ByteMathData expected = {0, 0, 0, 0, 0, BM_PLUS, 0, 0, 0, 0, 0, 0, 0};

        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
}

TEST_CASE("ByteMathModule::end", "[byte_math_tests]")
{
    ByteMathModule obj;

    obj.begin(nullptr, 0, nullptr);

    Value v_name("test");
    Parameter p_name = {"result", Parameter::PT_STRING, nullptr, nullptr,
        "name of the variable to store the result"};
    v_name.set(&p_name);
    obj.set(nullptr, v_name, nullptr);

    Value v_bytes(4.0);
    Parameter p_bytes = {"bytes", Parameter::PT_INT, "1:10", nullptr,
        "number of bytes to pick up from the buffer"};
    v_bytes.set(&p_bytes);
    obj.set(nullptr, v_bytes, nullptr);

    Value v_operation(0.0);
    Parameter p_operation = {"oper", Parameter::PT_ENUM, "+|-|*|/|<<|>>",
        nullptr, "mathematical operation to perform"};
    v_operation.set(&p_operation);
    obj.set(nullptr, v_operation, nullptr);

    char* name = new char[5];
    strcpy(name, "test");

    SECTION("without variables")
    {
        Value v_rvalue("7");
        Parameter p_rvalue = {"rvalue", Parameter::PT_STRING, nullptr, nullptr,
            "value to use mathematical operation against"};
        v_rvalue.set(&p_rvalue);
        obj.set(nullptr, v_rvalue, nullptr);

        CHECK(obj.end(nullptr, 0, nullptr));

        ByteMathData expected = {4, 7, 0, 0, name, BM_PLUS, 0, 0, 0, ENDIAN_BIG,
            0, IPS_OPTIONS_NO_VAR, IPS_OPTIONS_NO_VAR};

        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("with rvalue var")
    {
        ClearIpsOptionsVars();
        int8_t var_idx = AddVarNameToList("rvalue_test_var");
        SetVarValueByIndex(3, var_idx);

        Value v_rvalue("rvalue_test_var");
        Parameter p_rvalue = {"rvalue", Parameter::PT_STRING, nullptr, nullptr,
            "value to use mathematical operation against"};
        v_rvalue.set(&p_rvalue);
        obj.set(nullptr, v_rvalue, nullptr);

        CHECK(obj.end(nullptr, 0, nullptr));

        ByteMathData expected = {4, 0, 0, 0, name, BM_PLUS, 0, 0, 0, 
            ENDIAN_BIG, 0, var_idx, IPS_OPTIONS_NO_VAR};
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("with offset variable")
    {
        ClearIpsOptionsVars();
        int8_t var_idx = AddVarNameToList("offset_test_var");
        SetVarValueByIndex(3, var_idx);

        Value v_offvalue("offset_test_var");
        Parameter p_offvalue = { "offset", Parameter::PT_STRING, nullptr, nullptr,
            "number of bytes into the buffer to start processing"};
        v_offvalue.set(&p_offvalue);
        obj.set(nullptr, v_offvalue, nullptr);

        CHECK(obj.end(nullptr, 0, nullptr));

        ByteMathData expected = {4, 0, 0, 0, name, BM_PLUS, 0, 0,
            0, ENDIAN_BIG, 0, IPS_OPTIONS_NO_VAR, var_idx};
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("rvalue var doesn't exist")
    {
        ClearIpsOptionsVars();
        Value v_rvalue("rvalue_test_var");
        Parameter p_rvalue = {"rvalue", Parameter::PT_STRING, nullptr, nullptr,
            "value to use mathematical operation against"};
        v_rvalue.set(&p_rvalue);
        obj.set(nullptr, v_rvalue, nullptr);

        CHECK(!(obj.end(nullptr, 0, nullptr)));
    }
    SECTION("offset var doesn't exist")
    {
        ClearIpsOptionsVars();
        Value v_offvalue("offset_test_var");
        Parameter p_offvalue = { "offset", Parameter::PT_STRING, nullptr, nullptr,
            "number of bytes into the buffer to start processing"};
        v_offvalue.set(&p_offvalue);
        obj.set(nullptr, v_offvalue, nullptr);

        CHECK(!(obj.end(nullptr, 0, nullptr)));
    }
    delete name;
}

TEST_CASE("Test of byte_math_ctor", "[byte_math_tests]")
{
    ClearIpsOptionsVars();

    std::string name = "test";
    for (unsigned i = 0; i <= NUM_IPS_OPTIONS_VARS; ++i)
    {
        ByteMathModule obj;
        obj.begin(nullptr, 0, nullptr);
        Value v((name + std::to_string(i)).c_str());
        Parameter p = {"result", Parameter::PT_STRING, nullptr, nullptr,
            "name of the variable to store the result"};
        v.set(&p);
        obj.set(nullptr, v, nullptr);
        if (i < NUM_IPS_OPTIONS_VARS)
        {
            IpsOption* res = byte_math_ctor(&obj, nullptr);
            delete res;
        }
        else
        {
            IpsOption* res_null = byte_math_ctor(&obj, nullptr);
            CHECK(res_null == nullptr);
        }
    }
}

TEST_CASE("ByteMathModule::set valid", "[byte_math_tests]")
{
    ByteMathModule obj;
    obj.begin(nullptr, 0, nullptr);

    SECTION("set bytes")
    {
        Value v(4.0);
        Parameter p = {"bytes", Parameter::PT_INT, "1:10", nullptr,
            "number of bytes to pick up from the buffer"};
        v.set(&p);
        ByteMathData expected = {4, 0, 0, 0, 0, BM_PLUS, 0, 0, 0, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set offset")
    {
        Value v("3");
        Parameter p = {"offset", Parameter::PT_STRING, nullptr, nullptr,
            "number of bytes into the buffer to start processing"};
        v.set(&p);
        ByteMathData expected = {0, 0, 3, 0, 0, BM_PLUS, 0, 0, 0, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set option \"+\"")
    {
        Value v(0.0);
        Parameter p = {"oper", Parameter::PT_ENUM, "+|-|*|/|<<|>>", nullptr,
            "mathematical operation to perform"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_PLUS, 0, 0, 0, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set option \"-\"")
    {
        Value v(1.0);
        Parameter p = {"oper", Parameter::PT_ENUM, "+|-|*|/|<<|>>", nullptr,
            "mathematical operation to perform"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_MINUS, 0, 0, 0, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set option \"*\"")
    {
        Value v(2.0);
        Parameter p = {"oper", Parameter::PT_ENUM, "+|-|*|/|<<|>>", nullptr,
            "mathematical operation to perform"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_MULTIPLY, 0, 0, 0, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set option \"/\"")
    {
        Value v(3.0);
        Parameter p = {"oper", Parameter::PT_ENUM, "+|-|*|/|<<|>>", nullptr,
            "mathematical operation to perform"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_DIVIDE, 0, 0, 0, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set option \"<<\"")
    {
        Value v(4.0);
        Parameter p = {"oper", Parameter::PT_ENUM, "+|-|*|/|<<|>>", nullptr,
            "mathematical operation to perform"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_LEFT_SHIFT, 0, 0, 0, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set option \">>\"")
    {
        Value v(5.0);
        Parameter p = {"oper", Parameter::PT_ENUM, "+|-|*|/|<<|>>", nullptr,
            "mathematical operation to perform"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_RIGHT_SHIFT, 0, 0, 0, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set rvalue num")
    {
        Value v("21");
        Parameter p = {"rvalue", Parameter::PT_STRING, nullptr, nullptr,
            "value to use mathematical operation against"};
        v.set(&p);
        ByteMathData expected = {0, 21, 0, 0, 0, BM_PLUS, 0, 0, 0, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set result")
    {
        Value v("res_name");
        Parameter p = {"result", Parameter::PT_STRING, nullptr, nullptr,
            "name of the variable to store the result"};
        v.set(&p);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data.result_name, Catch::Matchers::Equals("res_name"));
    }
    SECTION("set relative")
    {
        Value v(true);
        Parameter p = {"relative", Parameter::PT_IMPLIED, nullptr, nullptr,
            "offset from cursor instead of start of buffer"};
        v.set(&p);
        obj.set(nullptr, v, nullptr);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_PLUS, 1, 0, 0, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set endianess \"big\"")
    {
        Value v(0.0);
        Parameter p = {"endian", Parameter::PT_ENUM, "big|little", nullptr,
            "specify big/little endian"};
        v.set(&p);
        obj.set(nullptr, v, nullptr);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_PLUS, 0,
            0, 0, ENDIAN_BIG, 0, 0, 0};
        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set endianess \"little\"")
    {
        Value v(1.0);
        Parameter p = {"endian", Parameter::PT_ENUM, "big|little", nullptr,
            "specify big/little endian"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_PLUS, 0, 0, 0, ENDIAN_LITTLE,
            0, 0, 0};
        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set dce")
    {
        Value v(true);
        Parameter p = {"dce", Parameter::PT_IMPLIED, nullptr, nullptr,
            "dcerpc2 determines endianess"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_PLUS, 0, 
            0, 0, ENDIAN_FUNC, 0, 0, 0};
        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set string, hex base")
    {
        Value v(0.0);
        Parameter p = {"string", Parameter::PT_ENUM, "hex|dec|oct", nullptr,
            "convert extracted string to dec/hex/oct"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_PLUS, 0, 1, 16, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set string, dec base")
    {
        Value v(1.0);
        Parameter p = {"string", Parameter::PT_ENUM, "hex|dec|oct", nullptr,
            "convert extracted string to dec/hex/oct"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_PLUS, 0, 1, 10, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set string, octa base")
    {
        Value v(2.0);
        Parameter p = {"string", Parameter::PT_ENUM, "hex|dec|oct", nullptr,
            "convert extracted string to dec/hex/oct"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_PLUS, 0, 1, 8, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("set bitmask")
    {
        Value v(1023.0);
        Parameter p = {"bitmask", Parameter::PT_INT, "0x1:0xFFFFFFFF", nullptr,
            "applies as bitwise AND to the extracted value before storage in 'name'"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 1023, 0, BM_PLUS, 0, 0, 0, 0, 0, 0, 0};

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("rvalue as variable")
    {
        Value v("r_test_var");
        Parameter p = {"rvalue", Parameter::PT_STRING, nullptr, nullptr,
            "value to use mathematical operation against"};
        v.set(&p);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK(strcmp(obj.rvalue_var.c_str(), "r_test_var") == 0);
    }
    SECTION("offset as variable")
    {
        Value v("off_test_var");
        Parameter p = {"offset", Parameter::PT_STRING, nullptr, nullptr,
            "number of bytes into the buffer to start processing"};
        v.set(&p);

        CHECK(obj.set(nullptr, v, nullptr));
        CHECK(strcmp(obj.off_var.c_str(), "off_test_var") == 0);
    }
}

TEST_CASE("ByteMathModule::set invalid", "[byte_math_tests]")
{
    ByteMathModule obj;
    obj.begin(nullptr, 0, nullptr);

    SECTION("invalid parameter")
    {
        Value v(1023.0);
        Parameter p = {"error", Parameter::PT_INT, "nan", nullptr,
            "not an option"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_PLUS, 0, 0, 0, 0, 0, 0, 0};

        CHECK(!obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
    SECTION("rvalue = 0")
    {
        Value v("0");
        Parameter p = {"rvalue", Parameter::PT_STRING, nullptr, nullptr,
            "value to use mathematical operation against"};
        v.set(&p);
        ByteMathData expected = {0, 0, 0, 0, 0, BM_PLUS, 0, 0, 0, 0, 0, 0, 0};

        CHECK(!obj.set(nullptr, v, nullptr));
        CHECK_THAT(obj.data, ByteMathDataEquals(expected));
    }
}
//-------------------------------------------------------------------------
// api tests
//-------------------------------------------------------------------------

TEST_CASE("ByteMathVerify valid", "[byte_math_tests]")
{
    ByteMathData obj;
    char* name = new char[5];
    strcpy(name, "test");

    SECTION("Minimum values, no string convertion")
    {
        obj = {1, 0, -65535, 0, name, BM_PLUS, 1, 0, 0, 0, 0, 0, 0};
        CHECK(ByteMathVerify(&obj));
    }
    SECTION("Maximum values, no string convertion")
    {
        obj = {MAX_BYTES_TO_GRAB, 2147483647, 65535, 0xFFFFFFFF, name, BM_PLUS, 1, 0,
            0, ENDIAN_FUNC, NUM_IPS_OPTIONS_VARS, NUM_IPS_OPTIONS_VARS, NUM_IPS_OPTIONS_VARS};
        CHECK(ByteMathVerify(&obj));
    }
    SECTION("Minimum values, with string convertion")
    {
        obj = {1, 0, -65535, 0, name, BM_PLUS, 1, 1, 8, 0, 0, 0, 0};
        CHECK(ByteMathVerify(&obj));
    }
    SECTION("Maximum values, with string convertion")
    {
        obj = {PARSELEN, 2147483647, 65535, 0xFFFFFFFF, name, BM_PLUS, 1, 1, 16, 
            ENDIAN_FUNC, NUM_IPS_OPTIONS_VARS, NUM_IPS_OPTIONS_VARS, NUM_IPS_OPTIONS_VARS};
        CHECK(ByteMathVerify(&obj));
    }
    delete name;
}

TEST_CASE("ByteMathVerify invalid", "[byte_math_tests]")
{
    char* name = new char[5];
    strcpy(name, "test");
    ByteMathData obj = {1, 9, 25, 1023, name, BM_PLUS, 1, 0, 0, 0, 0, 0, 0};

    SECTION("name existence check")
    {
        obj.result_name = nullptr;

        CHECK((!ByteMathVerify(&obj)));
    }
    SECTION("name not numeric check")
    {
        delete name;
        name = new char[5];
        strcpy(name, "9est");

        CHECK((!ByteMathVerify(&obj)));
    }
    SECTION("shift > 32 checks")
    {
        obj.rvalue = 33;

        obj.oper = BM_LEFT_SHIFT;
        CHECK((!ByteMathVerify(&obj)));

        obj.oper = BM_RIGHT_SHIFT;
        CHECK((!ByteMathVerify(&obj)));
    }
    SECTION("shift && bytes_to_extract > 4  checks")
    {
        obj.bytes_to_extract = MAX_BYTES_TO_GRAB + 1;

        obj.oper = BM_LEFT_SHIFT;
        CHECK((!ByteMathVerify(&obj)));

        obj.oper = BM_RIGHT_SHIFT;
        CHECK((!ByteMathVerify(&obj)));
    }
    SECTION("no string conversion && bytes_to_extract > 4  checks")
    {
        obj.bytes_to_extract = MAX_BYTES_TO_GRAB + 1;
        CHECK((!ByteMathVerify(&obj)));
    }
    SECTION("bitmask checks")
    {
        obj.bytes_to_extract = 2;
        obj.bitmask_val = 1048575;
        CHECK((!ByteMathVerify(&obj)));
    }
    delete name;
}

#endif