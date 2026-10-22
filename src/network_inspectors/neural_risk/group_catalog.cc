//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "group_catalog.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cctype>

#include "hash/ghash.h"
#include "main/snort_config.h"
#include "detection/signature.h"
#include "detection/treenodes.h"
#include "detection/fp_utils.h"
#include "detection/pattern_match_data.h"
#include "target_based/snort_protocols.h"
#include "ips_options/ips_flowbits.h"
#include "framework/ips_option.h"
#include "ports/port_object.h"

using namespace snort;
using namespace neural_risk;

namespace
{

std::string to_lower_str(const std::string& str)
{
    std::string s = str;
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string normalize_url(std::string id)
{
    if (id.rfind("http://", 0) == 0)
        id = id.substr(7);
    else if (id.rfind("https://", 0) == 0)
        id = id.substr(8);

    if (id.rfind("www.", 0) == 0)
        id = id.substr(4);

    while (!id.empty() && id.back() == '/')
        id.pop_back();

    return id;
}

static const std::set<std::string> FILE_BUFS = { "file_data", "js_data", "vba_data" };

struct UnionFind
{
    std::vector<int> parent;

    explicit UnionFind(size_t n) : parent(n)
    {
        for (size_t i = 0; i < n; ++i)
            parent[i] = static_cast<int>(i);
    }

    int find(int x)
    {
        int root = x;
        while (parent[root] != root)
            root = parent[root];
        int curr = x;
        while (parent[curr] != root)
        {
            int nxt = parent[curr];
            parent[curr] = root;
            curr = nxt;
        }
        return root;
    }

    void union_sets(int a, int b)
    {
        int ra = find(a);
        int rb = find(b);
        if (ra != rb)
            parent[ra] = rb;
    }
};

struct SplitterDef
{
    std::string name;
    std::string (*func)(const RuleFeatures&);
};

std::string splitter_ftype(const RuleFeatures& r) { return r.file_type; }
std::string splitter_dir(const RuleFeatures& r) { return (r.surface == "file") ? "any" : r.dir; }
std::string splitter_buf(const RuleFeatures& r) { return r.fp_buffer; }
std::string splitter_class(const RuleFeatures& r) { return r.classtype; }
std::string splitter_prof(const RuleFeatures& r) { return r.detection_profile; }
std::string splitter_port(const RuleFeatures& r) { return r.port_bucket; }
std::string splitter_fplen(const RuleFeatures& r) { return r.fp_len_bucket; }
std::string splitter_year(const RuleFeatures& r) { return r.cve_year; }

static const SplitterDef SPLITTERS[] =
{
    { "ftype", splitter_ftype },
    { "dir",   splitter_dir },
    { "buf",   splitter_buf },
    { "class", splitter_class },
    { "prof",  splitter_prof },
    { "port",  splitter_port },
    { "fplen", splitter_fplen },
    { "year",  splitter_year }
};

static constexpr size_t NUM_SPLITTERS = sizeof(SPLITTERS) / sizeof(SPLITTERS[0]);

struct SplitNode
{
    std::vector<std::string> key_tags; // e.g. "ftype=file.pdf"
    std::vector<const RuleFeatures*> members;
};

void recursive_split(
    const std::vector<std::string>& current_tags,
    const std::vector<const RuleFeatures*>& members,
    size_t level,
    unsigned min_size,
    unsigned max_size,
    std::vector<SplitNode>& output)
{
    if (members.size() <= max_size || level == NUM_SPLITTERS)
    {
        output.push_back({ current_tags, members });
        return;
    }

    const auto& sp = SPLITTERS[level];
    std::map<std::string, std::vector<const RuleFeatures*>> parts;
    for (const auto* r : members)
        parts[sp.func(*r)].push_back(r);

    if (parts.size() == 1)
    {
        recursive_split(current_tags, members, level + 1, min_size, max_size, output);
        return;
    }

    std::vector<const RuleFeatures*> rest;
    for (const auto& kv : parts)
    {
        const std::string& label = kv.first;
        const auto& part = kv.second;

        if (part.size() < min_size)
        {
            rest.insert(rest.end(), part.begin(), part.end());
        }
        else
        {
            std::vector<std::string> next_tags = current_tags;
            next_tags.push_back(sp.name + "=" + label);
            recursive_split(next_tags, part, level + 1, min_size, max_size, output);
        }
    }

    if (!rest.empty())
    {
        std::vector<std::string> next_tags = current_tags;
        next_tags.push_back(sp.name + "=*");
        recursive_split(next_tags, rest, level + 1, min_size, max_size, output);
    }
}

std::string get_anchor_for_members(const std::vector<const RuleFeatures*>& members)
{
    std::set<std::pair<std::string, std::string>> refs;
    for (const auto* r : members)
    {
        for (const auto& p : r->refs)
            refs.insert(p);
    }

    std::vector<std::string> cves;
    std::vector<std::string> bts;
    std::vector<std::string> urls;
    std::vector<std::string> others;

    for (const auto& p : refs)
    {
        if (p.first == "cve")
            cves.push_back(p.second);
        else if (p.first == "bugtraq")
            bts.push_back(p.second);
        else if (p.first == "url")
            urls.push_back("url:" + p.second);
        else
            others.push_back(p.first + ":" + p.second);
    }

    std::sort(cves.begin(), cves.end());
    if (!cves.empty())
        return "cve-" + cves[0];

    std::sort(bts.begin(), bts.end());
    if (!bts.empty())
        return "bugtraq-" + bts[0];

    std::sort(urls.begin(), urls.end());
    if (!urls.empty())
        return urls[0];

    std::sort(others.begin(), others.end());
    if (!others.empty())
        return others[0];

    return "unknown";
}

} // namespace

bool GroupCatalog::build(const SnortConfig* sc,
                         unsigned hub_limit,
                         unsigned min_size,
                         unsigned max_size)
{
    if (!sc || !sc->otn_map)
        return false;

    std::vector<RuleFeatures> extracted_rules;

    // 1. Walk sc->otn_map and extract RuleFeatures
    GHashNode* ghn = sc->otn_map->find_first();
    while (ghn)
    {
        OptTreeNode* otn = static_cast<OptTreeNode*>(ghn->data);
        if (!otn)
        {
            ghn = sc->otn_map->find_next();
            continue;
        }

        const SigInfo& si = otn->sigInfo;
        RuleFeatures rf;
        rf.gid = si.gid;
        rf.sid = si.sid;
        rf.rev = si.rev;
        rf.is_so = (otn->soid != nullptr);
        rf.classtype = (si.class_type && !si.class_type->name.empty()) ? si.class_type->name : "-";

        // References
        for (const auto* rn : si.refs)
        {
            if (!rn || !rn->system)
                continue;
            std::string sys = to_lower_str(rn->system->name);
            std::string id = to_lower_str(rn->id);
            if (id.find("attack.mitre.org") != std::string::npos)
                continue;
            if (sys == "url")
                id = normalize_url(id);
            rf.refs.emplace_back(sys, id);
        }

        // Flowbits
        OptFpList* ofl = otn->opt_func;
        while (ofl)
        {
            if (ofl->type == RULE_OPTION_TYPE_FLOWBIT && ofl->ips_opt)
            {
                bool set_bit = false;
                std::vector<std::string> bits;
                get_flowbits_dependencies(ofl->ips_opt, set_bit, bits);
                for (const auto& b : bits)
                {
                    if (set_bit)
                        rf.flowbits_set.push_back(b);
                    else
                        rf.flowbits_check.push_back(b);
                }
            }
            ofl = ofl->next;
        }
        std::sort(rf.flowbits_check.begin(), rf.flowbits_check.end());
        rf.file_type = "-";
        for (const auto& b : rf.flowbits_check)
        {
            if (b.rfind("file.", 0) == 0)
            {
                rf.file_type = b;
                break;
            }
        }

        // Services
        for (const auto& s : si.services)
        {
            if (!s.service.empty())
            {
                std::string svc_name = s.service;
                rf.services.push_back(svc_name);
                if (svc_name == "http")
                {
                    rf.services.push_back("http2");
                    rf.services.push_back("http3");
                }
                else if (svc_name == "netbios-ssn")
                {
                    rf.services.push_back("dcerpc");
                }
            }
        }

        const RuleTreeNode* rtn = nullptr;
        if (otn->proto_nodes)
        {
            for (int i = 0; i < otn->proto_node_num; ++i)
            {
                if (otn->proto_nodes[i])
                {
                    rtn = otn->proto_nodes[i];
                    break;
                }
            }
        }
        std::string proto = "";
        if (rtn && rtn->header && !rtn->header->proto.empty())
            proto = rtn->header->proto;
        else if (sc->proto_ref)
        {
            const char* p = sc->proto_ref->get_name(otn->snort_protocol_id);
            if (p)
                proto = p;
        }
        rf.primary_service = !rf.services.empty() ? rf.services[0] : proto;

        // Port bucket
        rf.port_bucket = "other";
        if (rtn)
        {
            if (rtn->any_dst_port())
                rf.port_bucket = "any";
            else if (rtn->dst_portobject &&
                     (PortObjectHasPort(rtn->dst_portobject, 80) || PortObjectHasPort(rtn->dst_portobject, 443)))
                rf.port_bucket = "web";
            else if (rtn->header)
            {
                const std::string& dp = rtn->header->dst_ports;
                if (dp == "80" || dp == "443" || dp == "$HTTP_PORTS")
                    rf.port_bucket = "web";
                else if (dp == "any" || dp.empty())
                    rf.port_bucket = "any";
            }
        }

        // Flow direction
        bool tc = otn->to_client();
        bool ts = otn->to_server();
        if (tc && !ts)
            rf.dir = "s2c";
        else if (ts && !tc)
            rf.dir = "c2s";
        else
            rf.dir = "c2s+s2c";

        // Fast pattern buffer & length
        OptFpList* node = nullptr;
        IpsOption* buf_opt = nullptr;
        bool exclude = false;
        bool srvc = !si.services.empty();
        PatternMatchVector pmv = get_fp_content(otn, node, buf_opt, srvc, false, exclude);

        if (rf.is_so)
        {
            rf.fp_buffer = "so";
            rf.fp_len_bucket = "short";
        }
        else if (pmv.empty())
        {
            rf.fp_buffer = "nfp";
            rf.fp_len_bucket = "short";
        }
        else
        {
            rf.fp_buffer = buf_opt ? buf_opt->get_name() : "pkt_data";
            unsigned pat_len = pmv.back()->pattern_size;
            if (pat_len <= 8) rf.fp_len_bucket = "short";
            else if (pat_len <= 16) rf.fp_len_bucket = "med";
            else if (pat_len <= 32) rf.fp_len_bucket = "long";
            else rf.fp_len_bucket = "vlong";
        }

        // Detection profile
        bool has_byte = false;
        bool has_pcre = false;
        bool has_len = false;
        for (OptFpList* p = otn->opt_func; p; p = p->next)
        {
            if (!p->ips_opt) continue;
            const char* opt_name = p->ips_opt->get_name();
            if (!opt_name) continue;
            std::string on(opt_name);
            if (on == "byte_test" || on == "byte_jump" || on == "byte_extract")
                has_byte = true;
            else if (on == "pcre")
                has_pcre = true;
            else if (on == "dsize" || on == "isdataat")
                has_len = true;
        }
        std::vector<std::string> prof_parts;
        if (has_byte) prof_parts.push_back("byte");
        if (has_pcre) prof_parts.push_back("pcre");
        if (has_len) prof_parts.push_back("len");
        if (prof_parts.empty())
            rf.detection_profile = "plain";
        else
        {
            rf.detection_profile = prof_parts[0];
            for (size_t i = 1; i < prof_parts.size(); ++i)
                rf.detection_profile += "+" + prof_parts[i];
        }

        // Surface
        if (FILE_BUFS.count(rf.fp_buffer))
        {
            rf.surface = "file";
        }
        else
        {
            std::string scope = rf.primary_service;
            if (scope == "http2" || scope == "http3")
                rf.surface = "http";
            else if (scope == "dcerpc")
                rf.surface = "netbios-ssn";
            else
                rf.surface = scope;
        }

        // CVE year
        rf.cve_year = "nocve";
        for (const auto& r : rf.refs)
        {
            if (r.first == "cve")
            {
                auto dash = r.second.find('-');
                if (dash != std::string::npos)
                {
                    std::string year = r.second.substr(0, dash);
                    if (rf.cve_year == "nocve" || year < rf.cve_year)
                        rf.cve_year = year;
                }
            }
        }

        extracted_rules.push_back(std::move(rf));
        ghn = sc->otn_map->find_next();
    }

    return build_from_rules(std::move(extracted_rules), hub_limit, min_size, max_size);
}

bool GroupCatalog::build_from_rules(std::vector<RuleFeatures>&& rules_in,
                                    unsigned hub_limit,
                                    unsigned min_size,
                                    unsigned max_size)
{
    rules = std::move(rules_in);
    groups.clear();
    sid_to_group.clear();
    sid_to_rule.clear();

    if (rules.empty())
        return true;

    // 2. Reference clustering via UnionFind
    // Collect all links and count fanout
    std::unordered_map<std::string, unsigned> link_fanout;
    for (const auto& r : rules)
    {
        std::set<std::string> rule_links;
        for (const auto& p : r.refs)
            rule_links.insert(p.first + ":" + p.second);
        for (const auto& l : rule_links)
            link_fanout[l]++;
    }

    // Deterministic sorting of link keys before indexing (prevents unordered_map iteration variance)
    std::vector<std::string> sorted_links;
    sorted_links.reserve(link_fanout.size());
    for (const auto& kv : link_fanout)
    {
        if (kv.second <= hub_limit)
            sorted_links.push_back(kv.first);
    }
    std::sort(sorted_links.begin(), sorted_links.end());

    std::unordered_map<std::string, int> link_to_idx;
    int link_counter = 0;
    for (const auto& l : sorted_links)
    {
        link_to_idx[l] = link_counter++;
    }

    size_t num_rules = rules.size();
    size_t total_nodes = num_rules + link_to_idx.size();
    UnionFind uf(total_nodes);

    for (size_t i = 0; i < num_rules; ++i)
    {
        std::set<std::string> rule_links;
        for (const auto& p : rules[i].refs)
            rule_links.insert(p.first + ":" + p.second);

        for (const auto& l : rule_links)
        {
            auto it = link_to_idx.find(l);
            if (it != link_to_idx.end())
            {
                uf.union_sets(static_cast<int>(i), static_cast<int>(num_rules + it->second));
            }
        }
    }

    std::unordered_map<int, int> comp_root_map;
    int next_comp_id = 0;
    for (size_t i = 0; i < num_rules; ++i)
    {
        int root = uf.find(static_cast<int>(i));
        auto it = comp_root_map.find(root);
        if (it == comp_root_map.end())
        {
            comp_root_map[root] = next_comp_id;
            rules[i].comp_id = next_comp_id++;
        }
        else
        {
            rules[i].comp_id = it->second;
        }
    }

    // 3. StructuralCut algorithm
    enum CutTier { TIER_REFCLU, TIER_BUF_CLASS, TIER_CLASS, TIER_CONTEXT, NUM_TIERS };

    std::vector<const RuleFeatures*> pending;
    pending.reserve(num_rules);
    for (const auto& r : rules)
        pending.push_back(&r);

    for (int tier_idx = 0; tier_idx < NUM_TIERS; ++tier_idx)
    {
        std::map<std::string, std::vector<const RuleFeatures*>> buckets;
        for (const auto* r : pending)
        {
            std::string key;
            if (tier_idx == TIER_REFCLU)
                key = r->surface + "#" + std::to_string(r->comp_id);
            else if (tier_idx == TIER_BUF_CLASS)
                key = r->surface + "#" + r->fp_buffer + "#" + r->classtype;
            else if (tier_idx == TIER_CLASS)
                key = r->surface + "#" + r->classtype;
            else // TIER_CONTEXT
                key = r->surface;

            buckets[key].push_back(r);
        }
        pending.clear();

        for (const auto& b_kv : buckets)
        {
            const auto& members = b_kv.second;
            std::vector<SplitNode> split_out;
            recursive_split({}, members, 0, min_size, max_size, split_out);

            for (const auto& sn : split_out)
            {
                if (sn.members.size() >= min_size)
                {
                    GroupInfo gi;
                    gi.members = sn.members;
                    gi.surface = sn.members[0]->surface;

                    std::string split_suffix;
                    for (const auto& tag : sn.key_tags)
                        split_suffix += "|" + tag;

                    if (tier_idx == TIER_REFCLU)
                    {
                        gi.tier = 1;
                        gi.kind = "refclu";
                        std::string anchor = get_anchor_for_members(sn.members);
                        gi.canonical_id = gi.surface + "|ref:" + anchor + split_suffix;
                    }
                    else if (tier_idx == TIER_BUF_CLASS)
                    {
                        gi.tier = 2;
                        gi.kind = "buf_class";
                        std::string buf = sn.members[0]->fp_buffer;
                        std::string cls = sn.members[0]->classtype;
                        gi.canonical_id = gi.surface + "|" + buf + "|" + cls + split_suffix;
                    }
                    else if (tier_idx == TIER_CLASS)
                    {
                        gi.tier = 3;
                        gi.kind = "class";
                        std::string cls = sn.members[0]->classtype;
                        gi.canonical_id = gi.surface + "|*|" + cls + split_suffix;
                    }
                    else // TIER_CONTEXT
                    {
                        gi.tier = 3;
                        gi.kind = "context";
                        gi.canonical_id = gi.surface + "|*" + split_suffix;
                    }

                    groups.push_back(std::move(gi));
                }
                else if (tier_idx == TIER_CONTEXT)
                {
                    GroupInfo gi;
                    gi.tier = 4;
                    gi.kind = "tiny";
                    gi.surface = sn.members[0]->surface;
                    gi.members = sn.members;

                    std::string split_suffix;
                    for (const auto& tag : sn.key_tags)
                        split_suffix += "|" + tag;
                    gi.canonical_id = gi.surface + "|tiny" + split_suffix;

                    groups.push_back(std::move(gi));
                }
                else
                {
                    // Undersized: falls through to next tier
                    pending.insert(pending.end(), sn.members.begin(), sn.members.end());
                }
            }
        }
    }

    // Assign integer IDs and populate sid_to_group and sid_to_rule maps
    for (const auto& r : rules)
    {
        sid_to_rule[make_key(r.gid, r.sid)] = &r;
    }

    for (size_t i = 0; i < groups.size(); ++i)
    {
        groups[i].id = static_cast<uint32_t>(i);
        for (const auto* r : groups[i].members)
        {
            sid_to_group[make_key(r->gid, r->sid)] = &groups[i];
        }
    }

    return true;
}

const GroupInfo* GroupCatalog::get_group(uint32_t gid, uint32_t sid) const
{
    auto it = sid_to_group.find(make_key(gid, sid));
    return (it != sid_to_group.end()) ? it->second : nullptr;
}

const RuleFeatures* GroupCatalog::get_rule(uint32_t gid, uint32_t sid) const
{
    auto it = sid_to_rule.find(make_key(gid, sid));
    return (it != sid_to_rule.end()) ? it->second : nullptr;
}

const GroupInfo* GroupCatalog::get_group_by_id(uint32_t id) const
{
    return (id < groups.size()) ? &groups[id] : nullptr;
}

bool GroupCatalog::dump_tsv(const std::string& path) const
{
    std::ofstream out(path);
    if (!out.is_open())
        return false;

    out << "gid\tsid\tgroup_id\ttier\tsurface\tfp_buffer\n";

    // Collect all rules sorted by gid, sid
    struct Row
    {
        uint32_t gid;
        uint32_t sid;
        std::string grp_id;
        int tier;
        std::string surface;
        std::string buf;
    };
    std::vector<Row> rows;
    rows.reserve(rules.size());

    for (const auto& r : rules)
    {
        const GroupInfo* gi = get_group(r.gid, r.sid);
        if (gi)
        {
            rows.push_back({ r.gid, r.sid, gi->canonical_id, gi->tier, r.surface, r.fp_buffer });
        }
    }

    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        if (a.gid != b.gid) return a.gid < b.gid;
        return a.sid < b.sid;
    });

    for (const auto& row : rows)
    {
        out << row.gid << "\t"
            << row.sid << "\t"
            << row.grp_id << "\t"
            << row.tier << "\t"
            << row.surface << "\t"
            << row.buf << "\n";
    }

    return true;
}
