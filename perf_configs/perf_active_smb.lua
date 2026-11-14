-- =============================================================================
-- Snort 3 Performance Benchmark: Variant 4 (SMB / NetBIOS Rule-Group Evaluation)
-- Description: Targeted configuration for testing SMB traffic datasets
--              (e.g. ntlm-lab/shared/pcaps/), evaluating the MS09-001 rule group:
--              - Model A: netbios-ssn|ref:cve-2008-4834 (SMB NT Transact underflow)
--              - Model B: netbios-ssn|pkt_data|protocol-command-decode (Structural)
--              - Model C: netbios-ssn|dce_iface|attempted-admin (DCERPC over SMB)
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
        { when = { cve = '2008-4834' },
          use  = { model = 'A', fpr_budget = 1 } },
        { when = { surface = 'netbios-ssn', buffer = 'pkt_data',
                   classtype = 'protocol-command-decode' },
          use  = { model = 'B', fpr_budget = 5 } },
        { when = { surface = 'netbios-ssn', buffer = 'dce_iface',
                   classtype = 'attempted-admin' },
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
