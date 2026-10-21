//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.
//--------------------------------------------------------------------------

#ifndef NEURAL_RISK_ENGINE_H
#define NEURAL_RISK_ENGINE_H

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

#include "framework/module.h"
#include "framework/inspector.h"
#include "group_catalog.h"
#include "risk_model.h"

#define NEURAL_RISK_ENGINE_NAME "neural_risk_engine"
#define NEURAL_RISK_ENGINE_HELP "configure rule-group conditioned neural risk engine"

namespace neural_risk
{

struct ModelSpec
{
    std::string name;
    std::string type = "mock";
    float score = 0.5f;
};

struct WhenClause
{
    std::string cve;
    std::string group;
    std::string surface;
    std::string buffer;
    std::string classtype;
};

struct UseClause
{
    std::string model;
    int fpr_budget = 5;
};

struct BindingSpec
{
    WhenClause when;
    UseClause use;
};

struct NeuralRiskEngineConfig
{
    bool enabled = true;
    unsigned hub_limit = 50;
    unsigned min_group = 10;
    unsigned max_group = 500;
    std::string dump_groups;

    std::vector<ModelSpec> models;
    std::vector<BindingSpec> bindings;
};

class NeuralRiskEngineModule : public snort::Module
{
public:
    NeuralRiskEngineModule();

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    Usage get_usage() const override { return GLOBAL; }

    const NeuralRiskEngineConfig& get_config() const { return conf; }

private:
    NeuralRiskEngineConfig conf;
    ModelSpec current_model;
    BindingSpec current_binding;
};

struct BoundModel
{
    RiskModel* model = nullptr;
    int fpr_budget = 0;
};

class NeuralRiskEngine : public snort::Inspector
{
public:
    explicit NeuralRiskEngine(const NeuralRiskEngineConfig&);
    ~NeuralRiskEngine() override = default;

    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet*) override {}

    static const GroupCatalog* get_catalog();
    static const BoundModel* get_binding(uint32_t group_id);
    static bool is_eval_enabled();

private:
    void compile_models();
    void compile_bindings();

    NeuralRiskEngineConfig config;
    GroupCatalog catalog;
    std::vector<std::unique_ptr<RiskModel>> instantiated_models;
    std::unordered_map<std::string, RiskModel*> model_map;
    std::vector<BoundModel> group_bindings; // indexed by group_id
};

} // namespace neural_risk

#endif // NEURAL_RISK_ENGINE_H
