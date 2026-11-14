-- =============================================================================
-- Snort 3 Performance Benchmark: Variant 2 (Active Engine, No I/O / Dry-Run)
-- Description: Measures pure in-memory algorithmic & pub/sub overhead:
--              - rule_group_scratch vector recording in fp_detect.cc
--              - post-callback registration in fp_complete
--              - RULE_GROUP_EVAL DataBus event publishing
--              - thread-local root cache lookups and group resolution
--              - MockRiskModel scoring
--              - log_file is empty (''), so write_jsonl_log returns immediately
--                with zero disk I/O and zero JSON formatting overhead.
-- =============================================================================

alerts = { log_references = true }

neural_risk_engine =
{
    enabled = true,
    hub_limit = 50,
    min_group = 10,
    max_group = 500,

    models =
    {
        { name = 'A', type = 'mock', score = 0.91 },
        { name = 'B', type = 'mock', score = 0.42 },
        { name = 'C', type = 'mock', score = 0.10 },
    },

    bindings =
    {
        { when = { cve = '2021-44228' },
          use  = { model = 'A', fpr_budget = 1 } },
        { when = { surface = 'http', buffer = 'http_client_body',
                   classtype = 'web-application-attack' },
          use  = { model = 'B', fpr_budget = 5 } },
        { when = { surface = 'http', buffer = 'http_uri',
                   classtype = 'web-application-activity' },
          use  = { model = 'C', fpr_budget = 10 } },
    },
}

neural_risk =
{
    log_file = '',
    log_teacher = false,
    trace = false,
    alert = false,
}
