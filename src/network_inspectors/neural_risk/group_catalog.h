//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.
//--------------------------------------------------------------------------

#ifndef GROUP_CATALOG_H
#define GROUP_CATALOG_H

#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <set>
#include <cstdint>

namespace snort
{
struct SnortConfig;
}

namespace neural_risk
{

struct RuleFeatures
{
    uint32_t gid = 1;
    uint32_t sid = 0;
    uint32_t rev = 0;

    std::string classtype;
    std::vector<std::string> services;
    std::string primary_service;
    std::string surface;
    std::string dir; // "c2s", "s2c", "c2s+s2c"

    std::vector<std::pair<std::string, std::string>> refs; // (system, id)
    std::vector<std::string> flowbits_set;
    std::vector<std::string> flowbits_check;
    std::string file_type; // from flowbits_check "file.*" or "-"

    std::string fp_buffer;
    std::string fp_len_bucket; // short (<=8), med (<=16), long (<=32), vlong (>32)
    std::string port_bucket;   // web, any, other
    std::string cve_year;      // YYYY or nocve
    std::string detection_profile; // byte, pcre, len combinations or plain
    bool is_so = false;

    int comp_id = -1; // reference cluster component ID
};

struct GroupInfo
{
    uint32_t id = 0;
    std::string canonical_id;
    uint8_t tier = 0; // 1 (refclu), 2 (buf_class), 3 (class/context), 4 (tiny)
    std::string surface;
    std::string kind; // "refclu", "buf_class", "class", "context", "tiny"
    std::vector<const RuleFeatures*> members;
};

class GroupCatalog
{
public:
    GroupCatalog() = default;
    GroupCatalog(const GroupCatalog&) = delete;
    GroupCatalog& operator=(const GroupCatalog&) = delete;
    GroupCatalog(GroupCatalog&&) noexcept = default;
    GroupCatalog& operator=(GroupCatalog&&) noexcept = default;

    bool build(const snort::SnortConfig* sc,
               unsigned hub_limit = 50,
               unsigned min_size = 10,
               unsigned max_size = 500);

    bool build_from_rules(std::vector<RuleFeatures>&& rules_in,
                          unsigned hub_limit = 50,
                          unsigned min_size = 10,
                          unsigned max_size = 500);

    bool dump_tsv(const std::string& path) const;

    const GroupInfo* get_group(uint32_t gid, uint32_t sid) const;
    const GroupInfo* get_group_by_id(uint32_t id) const;
    const RuleFeatures* get_rule(uint32_t gid, uint32_t sid) const;
    const std::vector<GroupInfo>& get_groups() const { return groups; }
    size_t get_rule_count() const { return rules.size(); }

private:
    std::vector<RuleFeatures> rules;
    std::vector<GroupInfo> groups;
    std::unordered_map<uint64_t, const GroupInfo*> sid_to_group;
    std::unordered_map<uint64_t, const RuleFeatures*> sid_to_rule;

    static uint64_t make_key(uint32_t gid, uint32_t sid)
    {
        return (static_cast<uint64_t>(gid) << 32) | sid;
    }
};

} // namespace neural_risk

#endif // GROUP_CATALOG_H
