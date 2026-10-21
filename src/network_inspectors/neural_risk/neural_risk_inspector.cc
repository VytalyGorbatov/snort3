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

#include "neural_risk_inspector.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

#include "detection/detection_engine.h"
#include "detection/detection_options.h"
#include "detection/ips_context.h"
#include "detection/pattern_match_data.h"
#include "detection/rule_option_types.h"
#include "detection/treenodes.h"
#include "framework/data_bus.h"
#include "framework/pig_pen.h"
#include "log/messages.h"
#include "main/thread.h"
#include "pub_sub/detection_events.h"
#include "utils/util.h"

#include "neural_risk_engine.h"
#include "risk_model.h"

using namespace snort;

namespace neural_risk
{
thread_local NeuralRiskStats neural_risk_stats;
}

using namespace neural_risk;

//--------------------------------------------------------------------------
// Parameters and Pegs
//--------------------------------------------------------------------------

static const Parameter neural_risk_params[] =
{
    { "log_file", Parameter::PT_STRING, nullptr, "neural_risk.jsonl",
      "JSONL output file path template (supports <tid> or stdout)" },
    { "log_teacher", Parameter::PT_BOOL, nullptr, "true",
      "log ALERT status lines for teacher alerts" },
    { "alert", Parameter::PT_BOOL, nullptr, "false",
      "queue Snort alert when score exceeds threshold" },
    { "trace", Parameter::PT_BOOL, nullptr, "false",
      "log human-readable trace lines" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap neural_risk_rules[] =
{
    { NEURAL_RISK_SID, "neural risk score exceeded threshold" },
    { 0, nullptr }
};

static const PegInfo neural_risk_pegs[] =
{
    { CountType::SUM, "near_miss", "total near-miss rule group actuations" },
    { CountType::SUM, "alerts_seen", "total alert (teacher) rule group actuations" },
    { CountType::SUM, "calls_A", "total calls to model A" },
    { CountType::SUM, "calls_B", "total calls to model B" },
    { CountType::SUM, "calls_C", "total calls to model C" },
    { CountType::SUM, "cache_hit", "root-to-group cache hits" },
    { CountType::SUM, "cache_miss", "root-to-group cache misses" },
    { CountType::SUM, "queue_dropped", "events dropped due to queue limits" },
    { CountType::END, nullptr, nullptr }
};

//--------------------------------------------------------------------------
// Root Cache and Helper Structures
//--------------------------------------------------------------------------

struct RootGroupInfo
{
    std::vector<const GroupInfo*> groups;
    std::unordered_map<const GroupInfo*, std::vector<std::pair<uint32_t, uint32_t>>> group_to_sids;
};

static thread_local std::unordered_map<const detection_option_tree_root_t*, RootGroupInfo> tl_root_cache;

static void collect_leaf_otns(const detection_option_tree_bud_t* bud, std::vector<const OptTreeNode*>& otns)
{
    if (!bud)
        return;

    if (bud->otn)
        otns.push_back(bud->otn);

    for (int i = 0; i < bud->num_children; ++i)
    {
        const auto* child = bud->children[i];
        if (!child)
            continue;
        if (child->option_type == RULE_OPTION_TYPE_LEAF_NODE && child->option_data)
        {
            otns.push_back(static_cast<const OptTreeNode*>(child->option_data));
        }
        else
        {
            collect_leaf_otns(child, otns);
        }
    }
}

// State tracked during current packet processing
struct PacketDetectionState
{
    uint64_t last_packet_number = 0;
    std::set<std::pair<uint32_t, uint32_t>> logged_sids;
    std::map<const GroupInfo*, std::vector<std::pair<uint32_t, uint32_t>>> alerted_groups;

    void update_packet(uint64_t pkt_num)
    {
        if (pkt_num != last_packet_number)
        {
            last_packet_number = pkt_num;
            logged_sids.clear();
            alerted_groups.clear();
        }
    }

    void clear()
    {
        logged_sids.clear();
        alerted_groups.clear();
    }
};

static thread_local PacketDetectionState tl_packet_state;

static void write_jsonl_log(const std::string& path_tmpl, const std::string& line)
{
    if (path_tmpl.empty())
        return;

    if (path_tmpl == "stdout")
    {
        std::cout << line << std::endl;
        return;
    }

    std::string path = path_tmpl;
    auto tid_pos = path.find("<tid>");
    if (tid_pos != std::string::npos)
    {
        path.replace(tid_pos, 5, std::to_string(get_instance_id()));
    }

    static thread_local std::ofstream tl_ofs;
    static thread_local std::string tl_cur_path;

    if (!tl_ofs.is_open() || tl_cur_path != path)
    {
        if (tl_ofs.is_open())
            tl_ofs.close();
        tl_cur_path = path;
        tl_ofs.open(path, std::ios::out | std::ios::app);
    }

    if (tl_ofs.is_open())
    {
        tl_ofs << line << "\n";
        tl_ofs.flush();
    }
}

//--------------------------------------------------------------------------
// Handlers
//--------------------------------------------------------------------------

class IpsLoggingHandler : public DataHandler
{
public:
    explicit IpsLoggingHandler(NeuralRiskInspector& in)
        : DataHandler(NEURAL_RISK_NAME), inspector(in) {}

    void handle(DataEvent& de, Flow*) override
    {
        uint64_t pkt_num = PigPen::get_packet_number();
        tl_packet_state.update_packet(pkt_num);

        auto* ire = static_cast<IpsRuleEvent*>(&de);
        uint32_t gid = ire->get_gid();
        uint32_t sid = ire->get_sid();

        tl_packet_state.logged_sids.insert({ gid, sid });

        const GroupCatalog* cat = NeuralRiskEngine::get_catalog();
        if (cat)
        {
            const GroupInfo* grp = cat->get_group(gid, sid);
            if (grp)
            {
                tl_packet_state.alerted_groups[grp].push_back({ gid, sid });
            }
        }
    }

private:
    NeuralRiskInspector& inspector;
};

class RuleGroupEvalHandler : public DataHandler
{
public:
    explicit RuleGroupEvalHandler(NeuralRiskInspector& in)
        : DataHandler(NEURAL_RISK_NAME), inspector(in) {}

    void handle(DataEvent& de, Flow*) override
    {
        auto* rge = static_cast<RuleGroupEvalEvent*>(&de);
        Packet* p = rge->packet;
        if (!p)
            return;

        uint64_t pkt_num = p->context ? p->context->packet_number : PigPen::get_packet_number();
        tl_packet_state.update_packet(pkt_num);

        const GroupCatalog* cat = NeuralRiskEngine::get_catalog();
        if (!cat)
            return;

        const auto& conf = inspector.get_config();

        enum class GroupStatus { NONE, ALERT, NEAR_MISS };

        struct GroupActuation
        {
            GroupStatus status = GroupStatus::NONE;
            const PatternMatchData* pmd = nullptr;
            std::vector<std::pair<uint32_t, uint32_t>> sids;
        };

        std::map<const GroupInfo*, GroupActuation> actuated;

        std::map<const GroupInfo*, std::vector<std::pair<uint32_t, uint32_t>>> packet_alerted_groups;
        for (const auto& kv : tl_packet_state.alerted_groups)
            packet_alerted_groups[kv.first] = kv.second;
        for (const auto& ms : rge->matched_sids)
        {
            const GroupInfo* grp = cat->get_group(ms.first, ms.second);
            if (grp)
            {
                auto& svec = packet_alerted_groups[grp];
                if (std::find(svec.begin(), svec.end(), ms) == svec.end())
                    svec.push_back(ms);
            }
        }

        // 1. Process all evaluation records from this packet
        for (const auto& rec : rge->records)
        {
            if (!rec.root)
                continue;

            // Lookup or populate root cache
            auto it = tl_root_cache.find(rec.root);
            if (it == tl_root_cache.end())
            {
                neural_risk_stats.cache_miss++;
                RootGroupInfo rgi;
                std::vector<const OptTreeNode*> otns;
                collect_leaf_otns(rec.root, otns);

                for (const auto* otn : otns)
                {
                    if (!otn)
                        continue;
                    uint32_t gid = otn->sigInfo.gid;
                    uint32_t sid = otn->sigInfo.sid;
                    const GroupInfo* grp = cat->get_group(gid, sid);
                    if (grp)
                    {
                        rgi.group_to_sids[grp].push_back({ gid, sid });
                    }
                }

                for (const auto& kv : rgi.group_to_sids)
                    rgi.groups.push_back(kv.first);

                it = tl_root_cache.emplace(rec.root, std::move(rgi)).first;
            }
            else
            {
                neural_risk_stats.cache_hit++;
            }

            const RootGroupInfo& rgi = it->second;

            for (const auto* grp : rgi.groups)
            {
                auto& act = actuated[grp];

                // If any rule of this group alerted on this packet, status is ALERT
                if (packet_alerted_groups.find(grp) != packet_alerted_groups.end())
                {
                    act.status = GroupStatus::ALERT;
                    act.sids = packet_alerted_groups[grp];
                }
                else if (act.status != GroupStatus::ALERT)
                {
                    act.status = GroupStatus::NEAR_MISS;
                    if (!act.pmd)
                        act.pmd = rec.pmd;

                    auto s_it = rgi.group_to_sids.find(grp);
                    if (s_it != rgi.group_to_sids.end())
                    {
                        for (const auto& sp : s_it->second)
                        {
                            if (std::find(act.sids.begin(), act.sids.end(), sp) == act.sids.end())
                                act.sids.push_back(sp);
                        }
                    }
                }
            }
        }

        // 2. Also ensure any groups with alerts not caught in records are marked ALERT
        for (const auto& kv : packet_alerted_groups)
        {
            auto& act = actuated[kv.first];
            act.status = GroupStatus::ALERT;
            act.sids = kv.second;
        }

        // 3. Dispatch actuated groups to bound models
        for (const auto& kv : actuated)
        {
            const GroupInfo* grp = kv.first;
            const GroupActuation& act = kv.second;

            const BoundModel* bm = NeuralRiskEngine::get_binding(grp->id);
            if (!bm || !bm->model)
                continue;

            RiskModel* model = bm->model;
            const std::string& model_name = model->get_name();

            if (act.status == GroupStatus::ALERT)
            {
                neural_risk_stats.alerts_seen++;

                if (conf.log_teacher)
                {
                    // Build alert SIDs list
                    auto sorted_sids = act.sids;
                    std::sort(sorted_sids.begin(), sorted_sids.end());
                    std::stringstream ss_sids;
                    ss_sids << "[";
                    for (size_t i = 0; i < sorted_sids.size(); ++i)
                    {
                        if (i > 0)
                            ss_sids << ",";
                        ss_sids << "\"" << sorted_sids[i].first << ":" << sorted_sids[i].second << "\"";
                    }
                    ss_sids << "]";

                    std::stringstream jline;
                    jline << "{\"pkt\":" << pkt_num
                          << ",\"model\":\"" << model_name << "\""
                          << ",\"status\":\"ALERT\""
                          << ",\"group\":\"" << grp->canonical_id << "\""
                          << ",\"tier\":" << (unsigned)grp->tier
                          << ",\"alert_sids\":" << ss_sids.str() << "}";

                    write_jsonl_log(conf.log_file, jline.str());

                    if (conf.trace)
                    {
                        std::string first_sid = !act.sids.empty()
                            ? (std::to_string(act.sids[0].first) + ":" + std::to_string(act.sids[0].second))
                            : "-";
                        LogMessage("neural_risk[%s] ALERT     group=%s tier=%u sid=%s (teacher)\n",
                                   model_name.c_str(), grp->canonical_id.c_str(), grp->tier, first_sid.c_str());
                    }
                }
            }
            else if (act.status == GroupStatus::NEAR_MISS)
            {
                neural_risk_stats.near_miss++;

                if (model_name == "A")
                    neural_risk_stats.calls_A++;
                else if (model_name == "B")
                    neural_risk_stats.calls_B++;
                else if (model_name == "C")
                    neural_risk_stats.calls_C++;

                // Resolve buffer: primary actuated rule's fp_buffer, group member fallback, or pkt_data
                std::string buf_name;
                const RuleFeatures* rf = !act.sids.empty()
                    ? cat->get_rule(act.sids[0].first, act.sids[0].second)
                    : nullptr;

                if (rf && !rf->fp_buffer.empty() && rf->fp_buffer != "nfp")
                    buf_name = rf->fp_buffer;
                else if (!grp->members.empty() && !grp->members[0]->fp_buffer.empty())
                    buf_name = grp->members[0]->fp_buffer;
                else if (act.pmd && act.pmd->sticky_buf && act.pmd->sticky_buf[0])
                    buf_name = act.pmd->sticky_buf;
                else
                    buf_name = "pkt_data";

                const uint8_t* buf_data = nullptr;
                size_t buf_len = 0;

                if (buf_name == "pkt_data" || buf_name == "raw_data")
                {
                    buf_data = p->data;
                    buf_len = p->dsize;
                }
                else if (p->flow && p->flow->gadget)
                {
                    InspectionBuffer ibuf;
                    if (p->flow->gadget->get_buf(buf_name.c_str(), p, ibuf) && ibuf.data && ibuf.len > 0)
                    {
                        buf_data = ibuf.data;
                        buf_len = ibuf.len;
                    }
                }

                if (!buf_data && p->data && p->dsize > 0)
                {
                    buf_data = p->data;
                    buf_len = p->dsize;
                }

                std::string dir = p->is_from_client() ? "c2s" : "s2c";

                ScoreRequest req;
                req.group = grp;
                if (!act.sids.empty())
                {
                    req.gid = act.sids[0].first;
                    req.sid = act.sids[0].second;
                }
                req.buffer_name = buf_name;
                req.buffer_data = buf_data;
                req.buffer_len = buf_len;
                req.dir = dir;

                RiskResult res = model->score(req);

                auto sorted_sids = act.sids;
                std::sort(sorted_sids.begin(), sorted_sids.end());
                std::stringstream ss_sids;
                ss_sids << "[";
                for (size_t i = 0; i < sorted_sids.size(); ++i)
                {
                    if (i > 0)
                        ss_sids << ",";
                    ss_sids << "\"" << sorted_sids[i].first << ":" << sorted_sids[i].second << "\"";
                }
                ss_sids << "]";

                std::stringstream jline;
                jline << std::fixed << std::setprecision(2);
                jline << "{\"pkt\":" << pkt_num
                      << ",\"model\":\"" << model_name << "\""
                      << ",\"status\":\"NEAR_MISS\""
                      << ",\"group\":\"" << grp->canonical_id << "\""
                      << ",\"tier\":" << (unsigned)grp->tier
                      << ",\"fp_sids\":" << ss_sids.str()
                      << ",\"buffer\":\"" << buf_name << "\""
                      << ",\"len\":" << buf_len
                      << ",\"dir\":\"" << dir << "\""
                      << ",\"score\":" << res.score << "}";

                write_jsonl_log(conf.log_file, jline.str());

                if (conf.trace)
                {
                    std::string first_sid = !act.sids.empty()
                        ? (std::to_string(act.sids[0].first) + ":" + std::to_string(act.sids[0].second))
                        : "-";
                    LogMessage("neural_risk[%s] NEAR_MISS group=%s tier=%u fp=%s buf=%s len=%zu %s score=%.2f\n",
                               model_name.c_str(), grp->canonical_id.c_str(), grp->tier, first_sid.c_str(),
                               buf_name.c_str(), buf_len, dir.c_str(), res.score);
                }

                if (conf.alert && res.score >= 0.5f)
                {
                    DetectionEngine::queue_event(NEURAL_RISK_GID, NEURAL_RISK_SID);
                }
            }
        }

        tl_packet_state.clear();
    }

private:
    NeuralRiskInspector& inspector;
};

//--------------------------------------------------------------------------
// Module implementation
//--------------------------------------------------------------------------

NeuralRiskModule::NeuralRiskModule()
    : Module(NEURAL_RISK_NAME, NEURAL_RISK_HELP, neural_risk_params)
{
}

bool NeuralRiskModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("log_file"))
        conf.log_file = v.get_string();
    else if (v.is("log_teacher"))
        conf.log_teacher = v.get_bool();
    else if (v.is("alert"))
        conf.alert = v.get_bool();
    else if (v.is("trace"))
        conf.trace = v.get_bool();

    return true;
}

const snort::RuleMap* NeuralRiskModule::get_rules() const
{
    return neural_risk_rules;
}

const PegInfo* NeuralRiskModule::get_pegs() const
{
    return neural_risk_pegs;
}

PegCount* NeuralRiskModule::get_counts() const
{
    return reinterpret_cast<PegCount*>(&neural_risk_stats);
}

//--------------------------------------------------------------------------
// Inspector implementation
//--------------------------------------------------------------------------

NeuralRiskInspector::NeuralRiskInspector(const NeuralRiskConfig& c)
    : config(c)
{
}

bool NeuralRiskInspector::configure(SnortConfig* sc)
{
    if (!config.log_file.empty() && config.log_file != "stdout")
    {
        std::string path = config.log_file;
        auto tid_pos = path.find("<tid>");
        if (tid_pos == std::string::npos)
        {
            std::ofstream ofs(path, std::ios::trunc);
        }
    }

    DataBus::subscribe_global(de_pub_key, DetectionEventIds::IPS_LOGGING,
                              new IpsLoggingHandler(*this), *sc);
    DataBus::subscribe_global(de_pub_key, DetectionEventIds::RULE_GROUP_EVAL,
                              new RuleGroupEvalHandler(*this), *sc);

    return true;
}

void NeuralRiskInspector::show(const SnortConfig*) const
{
    LogMessage("neural_risk configured (log_file=%s, log_teacher=%s, alert=%s)\n",
               config.log_file.c_str(),
               config.log_teacher ? "true" : "false",
               config.alert ? "true" : "false");
}

//--------------------------------------------------------------------------
// API Registration
//--------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new NeuralRiskModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Inspector* neural_risk_ctor(Module* m)
{
    auto* mod = static_cast<NeuralRiskModule*>(m);
    return new NeuralRiskInspector(mod->get_conf());
}

static void neural_risk_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi neural_risk_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        NEURAL_RISK_NAME,
        NEURAL_RISK_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__ANY_IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    neural_risk_ctor,
    neural_risk_dtor,
    nullptr, // ssn
    nullptr  // reset
};

const BaseApi* nin_neural_risk[] =
{
    &neural_risk_api.base,
    nullptr
};
