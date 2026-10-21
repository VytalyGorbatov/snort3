//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.
//--------------------------------------------------------------------------

#ifndef RISK_MODEL_H
#define RISK_MODEL_H

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace neural_risk
{

struct GroupInfo;

struct ScoreRequest
{
    const GroupInfo* group = nullptr;
    uint32_t gid = 0;
    uint32_t sid = 0;
    std::string buffer_name;
    const uint8_t* buffer_data = nullptr;
    size_t buffer_len = 0;
    std::string dir;
};

struct RiskResult
{
    float score = 0.0f;
    bool alert = false;
};

class RiskModel
{
public:
    virtual ~RiskModel() = default;
    virtual const std::string& get_name() const = 0;
    virtual const std::string& get_type() const = 0;
    virtual RiskResult score(const ScoreRequest& req) = 0;
};

class MockRiskModel : public RiskModel
{
public:
    MockRiskModel(const std::string& name, float fixed_score)
        : name(name), model_type("mock"), fixed_score(fixed_score) {}

    const std::string& get_name() const override { return name; }
    const std::string& get_type() const override { return model_type; }

    RiskResult score(const ScoreRequest&) override
    {
        return { fixed_score, false };
    }

private:
    std::string name;
    std::string model_type;
    float fixed_score;
};

} // namespace neural_risk

#endif // RISK_MODEL_H
