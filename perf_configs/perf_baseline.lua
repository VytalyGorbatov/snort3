-- =============================================================================
-- Snort 3 Performance Benchmark: Variant 0 (Stock Baseline)
-- Description: Baseline measurement with no neural risk modules loaded.
--              Core detection hooks are compiled in, but rule_group_eval_enabled
--              remains false. Serves as ground truth for throughput and latency.
-- =============================================================================

alerts = { log_references = true }

-- Note: neural_risk_engine and neural_risk are intentionally not loaded.
