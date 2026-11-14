-- =============================================================================
-- Snort 3 Performance Benchmark: Variant 5 (Large Enterprise Scenario)
-- Description: Stress-tests Snort 3 Neural Risk in a realistic large enterprise
--              environment with:
--              - 30 specialized risk models (threat-actor, CVE, structural, fallbacks)
--              - 62 declarative bindings across 959 canonical groups
--              - ~92% rule coverage across the 52k universe
--              - Zero I/O overhead by default (dry-run); supports <tid>.jsonl
-- =============================================================================

alerts = { log_references = true }

neural_risk_engine =
{
    enabled = true,
    hub_limit = 50,
    min_group = 10,
    max_group = 500,

    -- -------------------------------------------------------------------------
    -- 30 Specialized Neural Risk Models
    -- -------------------------------------------------------------------------
    models =
    {
        -- Category 1: Critical Threat & Zero-Day CVE Models (FPR budget <= 1%)
        { name = 'log4shell',            type = 'mock', score = 0.95 },
        { name = 'eternalblue',          type = 'mock', score = 0.95 },
        { name = 'proxylogon',           type = 'mock', score = 0.92 },
        { name = 'ms09_001_underflow',   type = 'mock', score = 0.91 },
        { name = 'samba_overflow',       type = 'mock', score = 0.88 },
        { name = 'disttrack_wiper',      type = 'mock', score = 0.96 },
        { name = 'cve_high_priority',    type = 'mock', score = 0.85 },

        -- Category 2: Web Application & HTTP Models (FPR budget <= 5%)
        { name = 'http_body_sqli_rce',   type = 'mock', score = 0.82 },
        { name = 'http_body_webattack',  type = 'mock', score = 0.78 },
        { name = 'http_uri_traversal',   type = 'mock', score = 0.68 },
        { name = 'http_uri_activity',    type = 'mock', score = 0.55 },
        { name = 'http_header_evasion',  type = 'mock', score = 0.72 },
        { name = 'http_trojan_activity', type = 'mock', score = 0.85 },

        -- Category 3: SMB / NetBIOS & DCERPC Models (FPR budget <= 5% - 10%)
        { name = 'smb_transact_expert',  type = 'mock', score = 0.84 },
        { name = 'smb_dcerpc_privesc',   type = 'mock', score = 0.89 },
        { name = 'smb_cmd_decode',       type = 'mock', score = 0.45 },
        { name = 'smb_attempted_user',   type = 'mock', score = 0.60 },

        -- Category 4: File & Attachment Payload Models (FPR budget <= 5%)
        { name = 'file_pe_executable',   type = 'mock', score = 0.90 },
        { name = 'file_doc_exploit',     type = 'mock', score = 0.85 },
        { name = 'file_pdf_malware',     type = 'mock', score = 0.82 },
        { name = 'file_trojan_payload',  type = 'mock', score = 0.88 },

        -- Category 5: Network Core & Infrastructure Models (FPR budget <= 5% - 10%)
        { name = 'dns_tunneling',        type = 'mock', score = 0.75 },
        { name = 'ssl_malicious_sni',    type = 'mock', score = 0.65 },
        { name = 'email_attachment',     type = 'mock', score = 0.70 },
        { name = 'tcp_recon_scanner',    type = 'mock', score = 0.40 },

        -- Category 6: Surface Catch-All Fallback Models (FPR budget <= 10%)
        { name = 'surface_http_fallback',type = 'mock', score = 0.30 },
        { name = 'surface_smb_fallback', type = 'mock', score = 0.30 },
        { name = 'surface_file_fallback',type = 'mock', score = 0.35 },
        { name = 'surface_dns_fallback', type = 'mock', score = 0.25 },
        { name = 'surface_ssl_fallback', type = 'mock', score = 0.25 },
    },

    -- -------------------------------------------------------------------------
    -- 62 Declarative Bindings (Hierarchical: Tier 1 -> Tier 2 -> Tier 3)
    -- -------------------------------------------------------------------------
    bindings =
    {
        -- Tier 1: High-Priority Exploit & Zero-Day Refclus
        { when = { cve = '2021-44228' }, use = { model = 'log4shell',           fpr_budget = 1 } },
        { when = { cve = '2017-0143' },  use = { model = 'eternalblue',         fpr_budget = 1 } },
        { when = { cve = '2021-26855' }, use = { model = 'proxylogon',          fpr_budget = 1 } },
        { when = { cve = '2008-4834' },  use = { model = 'ms09_001_underflow',  fpr_budget = 1 } },
        { when = { cve = '2007-2446' },  use = { model = 'samba_overflow',      fpr_budget = 1 } },
        { when = { cve = '2004-1154' },  use = { model = 'samba_overflow',      fpr_budget = 1 } },
        { when = { cve = '2012-1182' },  use = { model = 'samba_overflow',      fpr_budget = 1 } },
        { when = { cve = '2006-0003' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2015-2411' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2009-1095' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2014-4143' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2005-1211' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2003-0906' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2011-0559' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2012-1525' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2016-3267' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2013-0015' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2016-0010' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2008-0015' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2016-0102' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2010-0822' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2012-0751' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2010-3243' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '1999-0005' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2010-0842' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2011-1272' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2016-0099' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2016-1063' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { cve = '2014-0574' },  use = { model = 'cve_high_priority',   fpr_budget = 1 } },
        { when = { group = 'netbios-ssn|ref:url:blog.talosintel.com/2012/08/new-threat-disttrack.html' },
          use  = { model = 'disttrack_wiper',    fpr_budget = 1 } },

        -- Tier 2: Structural HTTP Web Application Cuts
        { when = { surface = 'http', buffer = 'http_client_body', classtype = 'web-application-attack' },
          use  = { model = 'http_body_sqli_rce',  fpr_budget = 5 } },
        { when = { surface = 'http', buffer = 'http_client_body', classtype = 'attempted-admin' },
          use  = { model = 'http_body_webattack', fpr_budget = 5 } },
        { when = { surface = 'http', buffer = 'http_client_body', classtype = 'trojan-activity' },
          use  = { model = 'http_trojan_activity',fpr_budget = 5 } },
        { when = { surface = 'http', buffer = 'http_uri', classtype = 'web-application-attack' },
          use  = { model = 'http_uri_traversal',  fpr_budget = 5 } },
        { when = { surface = 'http', buffer = 'http_uri', classtype = 'web-application-activity' },
          use  = { model = 'http_uri_activity',   fpr_budget = 10 } },
        { when = { surface = 'http', buffer = 'http_uri', classtype = 'attempted-user' },
          use  = { model = 'http_uri_activity',   fpr_budget = 10 } },
        { when = { surface = 'http', buffer = 'http_uri', classtype = 'trojan-activity' },
          use  = { model = 'http_trojan_activity',fpr_budget = 5 } },
        { when = { surface = 'http', buffer = 'http_header', classtype = 'web-application-attack' },
          use  = { model = 'http_header_evasion', fpr_budget = 5 } },
        { when = { surface = 'http', buffer = 'http_header', classtype = 'attempted-recon' },
          use  = { model = 'http_header_evasion', fpr_budget = 10 } },
        { when = { surface = 'http', buffer = 'http_header', classtype = 'trojan-activity' },
          use  = { model = 'http_trojan_activity',fpr_budget = 5 } },

        -- Tier 2: Structural SMB / NetBIOS Cuts
        { when = { surface = 'netbios-ssn', buffer = 'dce_iface', classtype = 'attempted-admin' },
          use  = { model = 'smb_dcerpc_privesc',  fpr_budget = 5 } },
        { when = { surface = 'netbios-ssn', buffer = 'dce_iface', classtype = 'protocol-command-decode' },
          use  = { model = 'smb_cmd_decode',      fpr_budget = 10 } },
        { when = { surface = 'netbios-ssn', buffer = 'dce_iface', classtype = 'attempted-user' },
          use  = { model = 'smb_attempted_user',  fpr_budget = 5 } },
        { when = { surface = 'netbios-ssn', buffer = 'pkt_data', classtype = 'attempted-admin' },
          use  = { model = 'smb_transact_expert', fpr_budget = 5 } },
        { when = { surface = 'netbios-ssn', buffer = 'pkt_data', classtype = 'protocol-command-decode' },
          use  = { model = 'smb_cmd_decode',      fpr_budget = 10 } },
        { when = { surface = 'netbios-ssn', buffer = 'pkt_data', classtype = 'attempted-user' },
          use  = { model = 'smb_attempted_user',  fpr_budget = 5 } },
        { when = { surface = 'netbios-ssn', buffer = 'pkt_data', classtype = 'trojan-activity' },
          use  = { model = 'smb_transact_expert', fpr_budget = 5 } },
        { when = { surface = 'netbios-ssn', buffer = 'pkt_data', classtype = 'attempted-recon' },
          use  = { model = 'smb_cmd_decode',      fpr_budget = 10 } },

        -- Tier 2: Structural File Payload Cuts
        { when = { surface = 'file', buffer = 'file_data', classtype = 'trojan-activity' },
          use  = { model = 'file_trojan_payload', fpr_budget = 5 } },
        { when = { surface = 'file', buffer = 'file_data', classtype = 'attempted-user' },
          use  = { model = 'file_doc_exploit',    fpr_budget = 5 } },
        { when = { surface = 'file', buffer = 'file_data', classtype = 'attempted-admin' },
          use  = { model = 'file_pe_executable',  fpr_budget = 5 } },
        { when = { surface = 'file', buffer = 'file_data', classtype = 'policy-violation' },
          use  = { model = 'file_pdf_malware',    fpr_budget = 5 } },

        -- Tier 2: Infrastructure & Core Protocols
        { when = { surface = 'dns', buffer = 'pkt_data' },
          use  = { model = 'dns_tunneling',       fpr_budget = 5 } },
        { when = { surface = 'ssl', buffer = 'pkt_data' },
          use  = { model = 'ssl_malicious_sni',   fpr_budget = 5 } },
        { when = { surface = 'smtp' },
          use  = { model = 'email_attachment',    fpr_budget = 5 } },
        { when = { surface = 'imap' },
          use  = { model = 'email_attachment',    fpr_budget = 5 } },
        { when = { surface = 'tcp', buffer = 'pkt_data', classtype = 'attempted-recon' },
          use  = { model = 'tcp_recon_scanner',   fpr_budget = 10 } },

        -- Tier 3: Surface-Wide Context Fallbacks (Catch-Alls)
        { when = { surface = 'http' },        use = { model = 'surface_http_fallback', fpr_budget = 10 } },
        { when = { surface = 'netbios-ssn' }, use = { model = 'surface_smb_fallback',  fpr_budget = 10 } },
        { when = { surface = 'file' },        use = { model = 'surface_file_fallback', fpr_budget = 10 } },
        { when = { surface = 'dns' },         use = { model = 'surface_dns_fallback',  fpr_budget = 10 } },
        { when = { surface = 'ssl' },         use = { model = 'surface_ssl_fallback',  fpr_budget = 10 } },
    },
}

neural_risk =
{
    log_file = '', -- Empty for dry-run / pure engine perf; set to '/tmp/nr_enterprise_<tid>.jsonl' for logged test
    log_teacher = false,
    trace = false,
    alert = false,
}
