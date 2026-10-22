-- Test configuration for neural_risk: swapped binding (A <-> B)
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
          use  = { model = 'B', fpr_budget = 5 } },
        { when = { surface = 'http', buffer = 'http_client_body',
                   classtype = 'web-application-attack' },
          use  = { model = 'A', fpr_budget = 1 } },
        { when = { surface = 'http', buffer = 'http_uri',
                   classtype = 'web-application-activity' },
          use  = { model = 'C', fpr_budget = 10 } },
    },
}

neural_risk =
{
    log_file = '/tmp/nr_test.jsonl',
    log_teacher = true,
    trace = false,
    alert = false,
}
