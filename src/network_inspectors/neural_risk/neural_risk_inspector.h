//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.
//--------------------------------------------------------------------------

#ifndef NEURAL_RISK_INSPECTOR_H
#define NEURAL_RISK_INSPECTOR_H

#include <string>

#include "framework/counts.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "main/thread.h"
#include "profiler/profiler.h"

#define NEURAL_RISK_NAME "neural_risk"
#define NEURAL_RISK_HELP "rule-group conditioned neural risk scoring inspector"

#define NEURAL_RISK_GID 412
#define NEURAL_RISK_SID 1

namespace neural_risk
{

struct NeuralRiskConfig
{
    std::string log_file = "neural_risk.jsonl";
    bool log_teacher = true;
    bool alert = false;
    bool trace = false;
};

struct NeuralRiskStats
{
    PegCount near_miss = 0;
    PegCount alerts_seen = 0;
    PegCount calls_A = 0;
    PegCount calls_B = 0;
    PegCount calls_C = 0;
    PegCount cache_hit = 0;
    PegCount cache_miss = 0;
    PegCount queue_dropped = 0;
};

extern thread_local NeuralRiskStats neural_risk_stats;

class NeuralRiskModule : public snort::Module
{
public:
    NeuralRiskModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Usage get_usage() const override { return GLOBAL; }

    const NeuralRiskConfig& get_conf() const { return conf; }

private:
    NeuralRiskConfig conf;
};

class NeuralRiskEngine;

class NeuralRiskInspector : public snort::Inspector
{
public:
    explicit NeuralRiskInspector(const NeuralRiskConfig& c);
    ~NeuralRiskInspector() override = default;

    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet*) override {}

    const NeuralRiskConfig& get_config() const { return config; }
    NeuralRiskEngine* get_engine() const { return engine; }

private:
    NeuralRiskConfig config;
    NeuralRiskEngine* engine = nullptr;
};

} // namespace neural_risk

#endif // NEURAL_RISK_INSPECTOR_H
