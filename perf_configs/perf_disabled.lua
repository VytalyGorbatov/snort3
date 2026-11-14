-- =============================================================================
-- Snort 3 Performance Benchmark: Variant 1 (Modules Loaded but Inactive)
-- Description: Tests configuration and registration overhead when neural risk
--              is loaded into the runtime but explicitly marked enabled = false.
--              rule_group_eval_enabled remains false.
-- =============================================================================

alerts = { log_references = true }

neural_risk_engine =
{
    enabled = false,
}

neural_risk =
{
    log_file = '',
    log_teacher = false,
    trace = false,
    alert = false,
}
