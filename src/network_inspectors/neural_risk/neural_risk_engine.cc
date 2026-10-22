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

#include "neural_risk_engine.h"

#include <iostream>
#include <iomanip>
#include <cassert>

#include "framework/decode_data.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "parser/parse_conf.h"
#include "pub_sub/detection_events.h"
#include <atomic>

using namespace snort;
using namespace neural_risk;

static std::atomic<NeuralRiskEngine*> s_engine{nullptr};

//--------------------------------------------------------------------------
// Parameters
//--------------------------------------------------------------------------

static const Parameter model_params[] =
{
    { "name", Parameter::PT_STRING, nullptr, nullptr, "model name (e.g. A, B, C)" },
    { "type", Parameter::PT_STRING, nullptr, "mock", "model type (mock, libml, onnx)" },
    { "score", Parameter::PT_REAL, "0:1", "0.5", "mock fixed score" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter when_params[] =
{
    { "cve", Parameter::PT_STRING, nullptr, nullptr, "CVE identifier without CVE- prefix" },
    { "group", Parameter::PT_STRING, nullptr, nullptr, "exact canonical group ID" },
    { "surface", Parameter::PT_STRING, nullptr, nullptr, "surface (e.g. http, file, dns)" },
    { "buffer", Parameter::PT_STRING, nullptr, nullptr, "fast-pattern buffer name" },
    { "classtype", Parameter::PT_STRING, nullptr, nullptr, "classification type" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter use_params[] =
{
    { "model", Parameter::PT_STRING, nullptr, nullptr, "target model name" },
    { "fpr_budget", Parameter::PT_INT, "1:100", "5", "FPR budget percentage (e.g. 1, 5, 10)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter binding_params[] =
{
    { "when", Parameter::PT_TABLE, when_params, nullptr, "match condition" },
    { "use", Parameter::PT_TABLE, use_params, nullptr, "target model invocation" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter neural_risk_engine_params[] =
{
    { "enabled", Parameter::PT_BOOL, nullptr, "true", "enable neural risk scoring" },
    { "hub_limit", Parameter::PT_INT, "1:1000", "50", "maximum link fanout for reference clustering" },
    { "min_group", Parameter::PT_INT, "1:1000", "10", "minimum group size" },
    { "max_group", Parameter::PT_INT, "1:10000", "500", "maximum group size" },
    { "dump_groups", Parameter::PT_STRING, nullptr, nullptr, "output path to dump groups TSV" },
    { "models", Parameter::PT_LIST, model_params, nullptr, "model definitions" },
    { "bindings", Parameter::PT_LIST, binding_params, nullptr, "rule group to model bindings" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//--------------------------------------------------------------------------
// Module implementation
//--------------------------------------------------------------------------

NeuralRiskEngineModule::NeuralRiskEngineModule()
    : Module(NEURAL_RISK_ENGINE_NAME, NEURAL_RISK_ENGINE_HELP, neural_risk_engine_params)
{
}

bool NeuralRiskEngineModule::begin(const char* fqn, int idx, SnortConfig* sc)
{
    if (sc)
        sc->output_flags |= OUTPUT_FLAG__ALERT_REFS;

    if (!strcmp(fqn, "neural_risk_engine.models") && idx)
    {
        current_model = ModelSpec();
    }
    else if (!strcmp(fqn, "neural_risk_engine.bindings") && idx)
    {
        current_binding = BindingSpec();
    }
    return true;
}

bool NeuralRiskEngineModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    if (sc)
        sc->output_flags |= OUTPUT_FLAG__ALERT_REFS;

    if (v.is("enabled"))
        conf.enabled = v.get_bool();
    else if (v.is("hub_limit"))
        conf.hub_limit = v.get_uint32();
    else if (v.is("min_group"))
        conf.min_group = v.get_uint32();
    else if (v.is("max_group"))
        conf.max_group = v.get_uint32();
    else if (v.is("dump_groups"))
        conf.dump_groups = v.get_string();

    // models
    else if (!strcmp(fqn, "neural_risk_engine.models.name"))
        current_model.name = v.get_string();
    else if (!strcmp(fqn, "neural_risk_engine.models.type"))
        current_model.type = v.get_string();
    else if (!strcmp(fqn, "neural_risk_engine.models.score"))
        current_model.score = static_cast<float>(v.get_real());

    // bindings.when
    else if (!strcmp(fqn, "neural_risk_engine.bindings.when.cve"))
        current_binding.when.cve = v.get_string();
    else if (!strcmp(fqn, "neural_risk_engine.bindings.when.group"))
        current_binding.when.group = v.get_string();
    else if (!strcmp(fqn, "neural_risk_engine.bindings.when.surface"))
        current_binding.when.surface = v.get_string();
    else if (!strcmp(fqn, "neural_risk_engine.bindings.when.buffer"))
        current_binding.when.buffer = v.get_string();
    else if (!strcmp(fqn, "neural_risk_engine.bindings.when.classtype"))
        current_binding.when.classtype = v.get_string();

    // bindings.use
    else if (!strcmp(fqn, "neural_risk_engine.bindings.use.model"))
        current_binding.use.model = v.get_string();
    else if (!strcmp(fqn, "neural_risk_engine.bindings.use.fpr_budget"))
        current_binding.use.fpr_budget = v.get_int32();

    return true;
}

bool NeuralRiskEngineModule::end(const char* fqn, int idx, SnortConfig*)
{
    if (!strcmp(fqn, "neural_risk_engine.models") && idx)
    {
        if (current_model.name.empty())
        {
            ParseError("neural_risk_engine: model name cannot be empty");
            return false;
        }
        conf.models.push_back(current_model);
    }
    else if (!strcmp(fqn, "neural_risk_engine.bindings") && idx)
    {
        if (current_binding.use.model.empty())
        {
            ParseError("neural_risk_engine: binding use.model cannot be empty");
            return false;
        }
        conf.bindings.push_back(current_binding);
    }
    return true;
}

//--------------------------------------------------------------------------
// Engine implementation
//--------------------------------------------------------------------------

NeuralRiskEngine::NeuralRiskEngine(const NeuralRiskEngineConfig& conf)
    : config(conf)
{
    s_engine.store(this);
}

const GroupCatalog* NeuralRiskEngine::get_catalog()
{
    NeuralRiskEngine* eng = s_engine.load();
    return eng ? &eng->catalog : nullptr;
}

const BoundModel* NeuralRiskEngine::get_binding(uint32_t group_id)
{
    NeuralRiskEngine* eng = s_engine.load();
    if (!eng || group_id >= eng->group_bindings.size())
        return nullptr;
    return &eng->group_bindings[group_id];
}

bool NeuralRiskEngine::is_eval_enabled()
{
    return rule_group_eval_enabled;
}

void NeuralRiskEngine::compile_models()
{
    instantiated_models.clear();
    model_map.clear();

    for (const auto& ms : config.models)
    {
        auto model = std::make_unique<MockRiskModel>(ms.name, ms.score);
        model_map[ms.name] = model.get();
        instantiated_models.push_back(std::move(model));
    }
}

static bool group_matches_binding(const GroupInfo& grp, const WhenClause& when)
{
    // Match exact group ID
    if (!when.group.empty())
    {
        if (grp.canonical_id != when.group)
            return false;
    }

    // Match CVE
    if (!when.cve.empty())
    {
        std::string target_cve = "cve-" + when.cve;
        std::string cve_token = "ref:" + target_cve;
        if (grp.canonical_id.find(cve_token) == std::string::npos)
        {
            // Also check if any member rule has this CVE
            bool found_in_members = false;
            for (const auto* r : grp.members)
            {
                for (const auto& p : r->refs)
                {
                    if (p.first == "cve" && p.second == when.cve)
                    {
                        found_in_members = true;
                        break;
                    }
                }
                if (found_in_members)
                    break;
            }
            if (!found_in_members)
                return false;
        }
    }

    // Match surface
    if (!when.surface.empty())
    {
        if (grp.surface != when.surface)
            return false;
    }

    // Per integration plan: tier-1 groups span several buffers and classtypes,
    // so they match only via cve, group, or a surface-only binding.
    if (grp.tier == 1 && when.cve.empty() && when.group.empty() && (!when.buffer.empty() || !when.classtype.empty()))
    {
        return false;
    }

    // Match buffer
    if (!when.buffer.empty())
    {
        if (grp.tier == 2)
        {
            // For Tier 2: surface|buffer|classtype
            std::string buf_token = "|" + when.buffer + "|";
            if (grp.canonical_id.find(buf_token) == std::string::npos)
                return false;
        }
        else
        {
            // Tier 1 groups span multiple buffers; by design, buffer constraint only matches
            // if all members use this buffer or if group is structural Tier 2
            bool has_buf = false;
            for (const auto* r : grp.members)
            {
                if (r->fp_buffer == when.buffer)
                {
                    has_buf = true;
                    break;
                }
            }
            if (!has_buf)
                return false;
        }
    }

    // Match classtype
    if (!when.classtype.empty())
    {
        bool has_class = false;
        for (const auto* r : grp.members)
        {
            if (r->classtype == when.classtype)
            {
                has_class = true;
                break;
            }
        }
        if (!has_class)
            return false;
    }

    return true;
}

void NeuralRiskEngine::compile_bindings()
{
    const auto& groups = catalog.get_groups();
    group_bindings.assign(groups.size(), { nullptr, 0 });

    if (config.bindings.empty())
        return;

    for (const auto& grp : groups)
    {
        for (const auto& b : config.bindings)
        {
            if (group_matches_binding(grp, b.when))
            {
                auto it = model_map.find(b.use.model);
                if (it != model_map.end())
                {
                    group_bindings[grp.id] = { it->second, b.use.fpr_budget };
                }
                else
                {
                    ParseWarning(WARN_CONF, "neural_risk_engine: unknown model '%s' in binding",
                                 b.use.model.c_str());
                }
                break; // first match wins
            }
        }
    }
}

bool NeuralRiskEngine::configure(SnortConfig* sc)
{
    if (!config.enabled)
    {
        rule_group_eval_enabled = false;
        return true;
    }

    rule_group_eval_enabled = true;

    // Build the catalog from parsed rules in sc->otn_map
    if (!catalog.build(sc, config.hub_limit, config.min_group, config.max_group))
    {
        ErrorMessage("neural_risk_engine: failed to build rule group catalog\n");
        return false;
    }

    compile_models();
    compile_bindings();

    if (!config.dump_groups.empty())
    {
        if (!catalog.dump_tsv(config.dump_groups))
        {
            ParseWarning(WARN_CONF, "neural_risk_engine: failed to write %s",
                         config.dump_groups.c_str());
        }
    }

    show(sc);

    return true;
}

void NeuralRiskEngine::show(const SnortConfig*) const
{
    if (!config.enabled)
        return;

    const auto& groups = catalog.get_groups();
    size_t total_rules = catalog.get_rule_count();
    size_t in_window = 0;

    for (const auto& g : groups)
    {
        if (g.members.size() >= config.min_group && g.members.size() <= config.max_group)
            in_window += g.members.size();
    }

    double cov_pct = total_rules > 0 ? (100.0 * in_window / total_rules) : 0.0;

    LogMessage("neural_risk_engine: %zu rules -> %zu groups, %.1f%% of rules in [%u,%u]\n",
               total_rules, groups.size(), cov_pct, config.min_group, config.max_group);

    // Print resolved binding summary
    std::unordered_map<std::string, std::pair<size_t, size_t>> model_stats; // model_name -> (group_count, rule_count)
    for (size_t i = 0; i < groups.size(); ++i)
    {
        if (group_bindings[i].model)
        {
            const std::string& mname = group_bindings[i].model->get_name();
            model_stats[mname].first++;
            model_stats[mname].second += groups[i].members.size();
        }
    }

    std::stringstream ss;
    bool first = true;
    for (const auto& kv : model_stats)
    {
        if (!first)
            ss << " | ";
        ss << kv.first << " <- " << kv.second.first << " groups (" << kv.second.second << " rules)";
        first = false;
    }
    if (!model_stats.empty())
    {
        LogMessage("neural_risk_engine: bindings resolved: %s\n", ss.str().c_str());
    }
}

//--------------------------------------------------------------------------
// API Registration
//--------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new NeuralRiskEngineModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Inspector* engine_ctor(Module* m)
{
    auto* mod = static_cast<NeuralRiskEngineModule*>(m);
    return new NeuralRiskEngine(mod->get_config());
}

static void engine_dtor(Inspector* p)
{
    if (s_engine.load() == static_cast<NeuralRiskEngine*>(p))
        s_engine.store(nullptr);
    delete p;
}

static void engine_tinit()
{
    // Seam for per-thread model runtime initialization (Phase 6/7)
}

static void engine_tterm()
{
    // Seam for per-thread model runtime cleanup (Phase 6/7)
}

static const InspectApi neural_risk_engine_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        NEURAL_RISK_ENGINE_NAME,
        NEURAL_RISK_ENGINE_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__NONE,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    engine_tinit,
    engine_tterm,
    engine_ctor,
    engine_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_neural_risk_engine[] =
#endif
{
    &neural_risk_engine_api.base,
    nullptr
};
