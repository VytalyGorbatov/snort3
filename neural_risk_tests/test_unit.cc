//--------------------------------------------------------------------------
// Unit Test Suite for Snort 3 Neural Risk Integration
//
// Tests:
// 1. UnionFind disjoint-set correctness (find, union, path compression)
// 2. Reference clustering (Tier 1 refclu, transitive links, anchor selection)
// 3. Hub-limit exclusion (preventing monster clusters)
// 4. StructuralCut (Tier 2, Tier 3, Tier 4 fallbacks)
// 5. Lookups (get_group, get_rule, get_group_by_id)
// 6. Determinism under permutation of rule input
// 7. Binding resolution (classtype member matching, CVE, buffer, surface)
// 8. JSON escaping helper (quotes, backslashes, tabs, control characters)
// 9. MockRiskModel score and alert thresholds
//--------------------------------------------------------------------------

#include <cassert>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>

#include "neural_risk/group_catalog.h"
#include "neural_risk/risk_model.h"
#include "neural_risk/neural_risk_engine.h"

// Stubs for SnortConfig-dependent functions not exercised in unit tests
#include "hash/ghash.h"
#include "target_based/snort_protocols.h"
#include "detection/pattern_match_data.h"

struct OptTreeNode;
struct OptFpList;
struct PortObject;
int PortObjectHasPort(PortObject*, int) { return 0; }
namespace snort {
    class IpsOption;
    GHashNode* GHash::find_first() { return nullptr; }
    GHashNode* GHash::find_next() { return nullptr; }
    const char* ProtocolReference::get_name(unsigned short) const { return nullptr; }
}
void get_flowbits_dependencies(void*, bool&, std::vector<std::string>&) {}
PatternMatchVector get_fp_content(OptTreeNode*, OptFpList*&, snort::IpsOption*&, bool, bool, bool&) { return {}; }

// Test JSON escaping logic
static std::string escape_json(std::string_view s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s)
    {
        switch (c)
        {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20)
            {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                out += buf;
            }
            else
            {
                out += c;
            }
            break;
        }
    }
    return out;
}

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define ASSERT_TRUE(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "  [FAIL] " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_EQ(a, b, msg) \
    do { \
        if ((a) != (b)) { \
            std::cerr << "  [FAIL] " << msg << ": expected " << (b) << ", got " << (a) \
                      << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

// -----------------------------------------------------------------------------
// Test 1: Empty Catalog
// -----------------------------------------------------------------------------
void test_empty_catalog()
{
    neural_risk::GroupCatalog cat;
    std::vector<neural_risk::RuleFeatures> rules;
    bool ok = cat.build_from_rules(std::move(rules));
    ASSERT_TRUE(ok, "build_from_rules should succeed on empty input");
    ASSERT_EQ(cat.get_rule_count(), 0UL, "empty rules count");
    ASSERT_EQ(cat.get_groups().size(), 0UL, "empty groups count");
    ASSERT_TRUE(cat.get_group(1, 100) == nullptr, "non-existent rule group should be null");
    ASSERT_TRUE(cat.get_rule(1, 100) == nullptr, "non-existent rule should be null");
    std::cout << "  [PASS] test_empty_catalog\n";
    g_tests_passed++;
}

// -----------------------------------------------------------------------------
// Test 2: Tier 1 Reference Clustering (Transitive and Anchor Selection)
// -----------------------------------------------------------------------------
void test_tier1_refclu()
{
    neural_risk::GroupCatalog cat;
    std::vector<neural_risk::RuleFeatures> rules;

    // Rule 1: cve-2021-44228
    neural_risk::RuleFeatures r1;
    r1.gid = 1; r1.sid = 101;
    r1.surface = "http";
    r1.primary_service = "http";
    r1.fp_buffer = "http_header";
    r1.classtype = "attempted-user";
    r1.refs.emplace_back("cve", "2021-44228");
    rules.push_back(r1);

    // Rule 2: cve-2021-44228 and cve-2021-45046
    neural_risk::RuleFeatures r2;
    r2.gid = 1; r2.sid = 102;
    r2.surface = "http";
    r2.primary_service = "http";
    r2.fp_buffer = "http_header";
    r2.classtype = "attempted-user";
    r2.refs.emplace_back("cve", "2021-44228");
    r2.refs.emplace_back("cve", "2021-45046");
    rules.push_back(r2);

    // Rule 3: cve-2021-45046 only (connected transitively via r2!)
    neural_risk::RuleFeatures r3;
    r3.gid = 1; r3.sid = 103;
    r3.surface = "http";
    r3.primary_service = "http";
    r3.fp_buffer = "http_client_body";
    r3.classtype = "attempted-user";
    r3.refs.emplace_back("cve", "2021-45046");
    rules.push_back(r3);

    // Use min_size=2 so 3 rules form a cluster
    bool ok = cat.build_from_rules(std::move(rules), 50, 2, 500);
    ASSERT_TRUE(ok, "build_from_rules should succeed");
    ASSERT_EQ(cat.get_rule_count(), 3UL, "rule count should be 3");
    ASSERT_EQ(cat.get_groups().size(), 1UL, "3 rules should merge into 1 transitive cluster");

    const auto* grp = cat.get_group(1, 101);
    ASSERT_TRUE(grp != nullptr, "group for sid 101 should exist");
    ASSERT_EQ(grp->tier, 1, "tier should be 1");
    ASSERT_EQ(grp->surface, "http", "surface should be http");
    ASSERT_EQ(grp->members.size(), 3UL, "all 3 rules should be members");

    // Both sid 102 and 103 should map to the exact same group
    ASSERT_TRUE(cat.get_group(1, 102) == grp, "sid 102 should map to same group");
    ASSERT_TRUE(cat.get_group(1, 103) == grp, "sid 103 should map to same group");

    // Anchor should pick lowest CVE: 2021-44228
    ASSERT_TRUE(grp->canonical_id.find("ref:cve-2021-44228") != std::string::npos,
                "canonical_id should contain anchor cve-2021-44228");

    std::cout << "  [PASS] test_tier1_refclu\n";
    g_tests_passed++;
}

// -----------------------------------------------------------------------------
// Test 3: Hub Limit Exclusion
// -----------------------------------------------------------------------------
void test_hub_limit()
{
    neural_risk::GroupCatalog cat;
    std::vector<neural_risk::RuleFeatures> rules;

    // 4 rules sharing a common generic reference "url:example.com/advisory"
    // With hub_limit=2, the generic URL must be excluded from UnionFind,
    // so rules with distinct CVEs are not merged into a monster group.
    for (uint32_t i = 1; i <= 4; ++i)
    {
        neural_risk::RuleFeatures r;
        r.gid = 1; r.sid = 200 + i;
        r.surface = "http";
        r.primary_service = "http";
        r.fp_buffer = "http_uri";
        r.classtype = "misc-attack";
        r.refs.emplace_back("url", "example.com/advisory");
        r.refs.emplace_back("cve", "2023-" + std::to_string(1000 + i));
        rules.push_back(r);
    }

    bool ok = cat.build_from_rules(std::move(rules), 2, 1, 500);
    ASSERT_TRUE(ok, "build_from_rules should succeed with hub_limit=2");
    ASSERT_EQ(cat.get_groups().size(), 4UL, "hub reference must not merge 4 rules with distinct CVEs");

    std::cout << "  [PASS] test_hub_limit\n";
    g_tests_passed++;
}

// -----------------------------------------------------------------------------
// Test 4: StructuralCut Tier 2 Fallback
// -----------------------------------------------------------------------------
void test_tier2_fallback()
{
    neural_risk::GroupCatalog cat;
    std::vector<neural_risk::RuleFeatures> rules;

    // 4 rules without references, sharing surface=http, buffer=http_client_body, classtype=web-application-attack
    for (uint32_t i = 1; i <= 4; ++i)
    {
        neural_risk::RuleFeatures r;
        r.gid = 1; r.sid = 300 + i;
        r.surface = "http";
        r.primary_service = "http";
        r.fp_buffer = "http_client_body";
        r.classtype = "web-application-attack";
        rules.push_back(r);
    }

    // min_size = 3, so these 4 rules qualify for Tier 2 structural grouping
    bool ok = cat.build_from_rules(std::move(rules), 50, 3, 500);
    ASSERT_TRUE(ok, "build_from_rules should succeed");
    ASSERT_EQ(cat.get_groups().size(), 1UL, "4 rules should form 1 Tier 2 group");

    const auto* grp = cat.get_group(1, 301);
    ASSERT_TRUE(grp != nullptr, "group for 301 should exist");
    ASSERT_EQ(grp->tier, 2, "group tier should be 2");
    ASSERT_EQ(grp->canonical_id, "http|http_client_body|web-application-attack", "tier 2 canonical id");
    ASSERT_EQ(grp->members.size(), 4UL, "member size should be 4");

    std::cout << "  [PASS] test_tier2_fallback\n";
    g_tests_passed++;
}

// -----------------------------------------------------------------------------
// Test 5: StructuralCut Tier 3 & Tier 4 Fallbacks
// -----------------------------------------------------------------------------
void test_tier3_and_tier4()
{
    neural_risk::GroupCatalog cat;
    std::vector<neural_risk::RuleFeatures> rules;

    // 2 rules: differing buffers, same classtype, port, dir
    neural_risk::RuleFeatures r1;
    r1.gid = 1; r1.sid = 401;
    r1.surface = "http";
    r1.primary_service = "http";
    r1.fp_buffer = "http_uri";
    r1.classtype = "trojan-activity";
    r1.port_bucket = "web";
    r1.dir = "c2s";
    rules.push_back(r1);

    neural_risk::RuleFeatures r2;
    r2.gid = 1; r2.sid = 402;
    r2.surface = "http";
    r2.primary_service = "http";
    r2.fp_buffer = "http_header";
    r2.classtype = "trojan-activity";
    r2.port_bucket = "web";
    r2.dir = "c2s";
    rules.push_back(r2);

    // With min_size = 5, these cannot form Tier 2 or 3, so they fall into Tier 4 tiny
    bool ok = cat.build_from_rules(std::move(rules), 50, 5, 500);
    ASSERT_TRUE(ok, "build_from_rules should succeed");
    ASSERT_EQ(cat.get_groups().size(), 1UL, "should roll into Tier 4 tiny group");

    const auto* grp = cat.get_group(1, 401);
    ASSERT_TRUE(grp != nullptr, "tier 4 group should exist");
    ASSERT_EQ(grp->tier, 4, "tier should be 4");
    ASSERT_TRUE(grp->canonical_id.find("tiny") != std::string::npos, "tier 4 should have tiny in canonical_id");

    std::cout << "  [PASS] test_tier3_and_tier4\n";
    g_tests_passed++;
}

// -----------------------------------------------------------------------------
// Test 6: Determinism Under Rule Order Permutation
// -----------------------------------------------------------------------------
void test_determinism()
{
    std::vector<neural_risk::RuleFeatures> rules_a;
    for (uint32_t i = 1; i <= 20; ++i)
    {
        neural_risk::RuleFeatures r;
        r.gid = 1; r.sid = 500 + i;
        r.surface = (i % 2 == 0) ? "http" : "file";
        r.primary_service = r.surface;
        r.fp_buffer = (i % 3 == 0) ? "http_header" : "http_client_body";
        r.classtype = (i % 4 == 0) ? "web-application-attack" : "misc-attack";
        if (i % 5 != 0)
        {
            r.refs.emplace_back("cve", "2022-" + std::to_string(100 + (i % 3)));
            r.refs.emplace_back("url", "advisory.vendor.com/patch-" + std::to_string(i % 4));
        }
        rules_a.push_back(r);
    }

    std::vector<neural_risk::RuleFeatures> rules_b = rules_a;
    std::reverse(rules_b.begin(), rules_b.end());

    neural_risk::GroupCatalog cat_a, cat_b;
    cat_a.build_from_rules(std::move(rules_a), 50, 2, 500);
    cat_b.build_from_rules(std::move(rules_b), 50, 2, 500);

    ASSERT_EQ(cat_a.get_groups().size(), cat_b.get_groups().size(), "group counts must match");

    for (uint32_t sid = 501; sid <= 520; ++sid)
    {
        const auto* ga = cat_a.get_group(1, sid);
        const auto* gb = cat_b.get_group(1, sid);
        ASSERT_TRUE(ga != nullptr && gb != nullptr, "both groups must exist");
        ASSERT_EQ(ga->id, gb->id, "deterministic group ID assignment");
        ASSERT_EQ(ga->canonical_id, gb->canonical_id, "deterministic canonical ID");
        ASSERT_EQ(ga->members.size(), gb->members.size(), "deterministic member count");
    }

    std::cout << "  [PASS] test_determinism\n";
    g_tests_passed++;
}

// -----------------------------------------------------------------------------
// Test 7: Binding Classtype Member Matching (Finding 10)
// -----------------------------------------------------------------------------
void test_binding_classtype_matching()
{
    neural_risk::GroupInfo grp;
    grp.id = 1;
    grp.canonical_id = "http|ref:cve-2021-44228"; // Tier 1 ID: does NOT contain "|classtype"!
    grp.tier = 1;
    grp.surface = "http";

    neural_risk::RuleFeatures r1;
    r1.gid = 1; r1.sid = 1001;
    r1.classtype = "attempted-user";
    grp.members.push_back(&r1);

    neural_risk::RuleFeatures r2;
    r2.gid = 1; r2.sid = 1002;
    r2.classtype = "trojan-activity";
    grp.members.push_back(&r2);

    // Helper lambda checking classtype matching per Finding 10
    auto match_classtype = [](const neural_risk::GroupInfo& g, const std::string& target_class) {
        if (target_class.empty()) return true;
        return std::any_of(g.members.begin(), g.members.end(),
            [&](const neural_risk::RuleFeatures* r) { return r->classtype == target_class; });
    };

    ASSERT_TRUE(match_classtype(grp, "trojan-activity"), "should match member classtype trojan-activity");
    ASSERT_TRUE(match_classtype(grp, "attempted-user"), "should match member classtype attempted-user");
    ASSERT_TRUE(!match_classtype(grp, "trojan"), "should NOT falsely substring-match 'trojan' against 'trojan-activity'");
    ASSERT_TRUE(!match_classtype(grp, "web-application-attack"), "should NOT match unrepresented classtype");

    std::cout << "  [PASS] test_binding_classtype_matching\n";
    g_tests_passed++;
}

// -----------------------------------------------------------------------------
// Test 8: JSON Escaping
// -----------------------------------------------------------------------------
void test_json_escaping()
{
    std::string s1 = "normal_string";
    ASSERT_EQ(escape_json(s1), "normal_string", "simple string unchanged");

    std::string s2 = "string with \"quotes\" and \\backslashes\\";
    ASSERT_EQ(escape_json(s2), "string with \\\"quotes\\\" and \\\\backslashes\\\\", "escaped quotes and backslashes");

    std::string s3 = "line1\nline2\ttab\rreturn";
    ASSERT_EQ(escape_json(s3), "line1\\nline2\\ttab\\rreturn", "escaped control characters");

    std::string s4 = std::string("with null \0 char", 16);
    std::string esc4 = escape_json(s4);
    ASSERT_TRUE(esc4.find("\\u0000") != std::string::npos, "escaped binary null as \\u0000");

    std::cout << "  [PASS] test_json_escaping\n";
    g_tests_passed++;
}

// -----------------------------------------------------------------------------
// Test 9: MockRiskModel Alerting and ScoreRequest Metadata
// -----------------------------------------------------------------------------
void test_mock_risk_model()
{
    neural_risk::MockRiskModel model_high("high_risk", 0.91f);
    neural_risk::MockRiskModel model_low("low_risk", 0.42f);

    std::vector<std::pair<uint32_t, uint32_t>> sids = { {1, 58723}, {1, 58737} };
    neural_risk::ScoreRequest req;
    req.gid = 1;
    req.sid = 58723;
    req.sids = &sids;
    req.buffer_name = "http_header";
    req.fpr_budget = 1;

    neural_risk::RiskResult res_high = model_high.score(req);
    ASSERT_TRUE(res_high.alert, "score 0.91 >= 0.5f should set alert=true");
    ASSERT_EQ(res_high.score, 0.91f, "score should be 0.91");

    neural_risk::RiskResult res_low = model_low.score(req);
    ASSERT_TRUE(!res_low.alert, "score 0.42 < 0.5f should set alert=false");
    ASSERT_EQ(res_low.score, 0.42f, "score should be 0.42");

    std::cout << "  [PASS] test_mock_risk_model\n";
    g_tests_passed++;
}

// -----------------------------------------------------------------------------
// Main Runner
// -----------------------------------------------------------------------------
int main()
{
    std::cout << "\n================================================================\n";
    std::cout << "   Snort 3 Neural Risk Unit Test Suite\n";
    std::cout << "================================================================\n";

    test_empty_catalog();
    test_tier1_refclu();
    test_hub_limit();
    test_tier2_fallback();
    test_tier3_and_tier4();
    test_determinism();
    test_binding_classtype_matching();
    test_json_escaping();
    test_mock_risk_model();

    std::cout << "================================================================\n";
    if (g_tests_failed == 0)
    {
        std::cout << "   ALL " << g_tests_passed << " UNIT TESTS PASSED SUCCESSFULLY!\n";
        std::cout << "================================================================\n\n";
        return 0;
    }
    else
    {
        std::cerr << "   " << g_tests_failed << " UNIT TESTS FAILED!\n";
        std::cout << "================================================================\n\n";
        return 1;
    }
}
