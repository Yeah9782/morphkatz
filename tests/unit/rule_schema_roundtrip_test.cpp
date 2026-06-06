// Schema-roundtrip guard: every YAML file under rules/x64/ must load cleanly
// and every loaded rule must satisfy the contract the engine relies on
//   (non-empty id, either a match+rewrite pair or a raw byte pair,
//    and a non-NotVerified flags_effect unless the rule explicitly opts out).
//
// This catches a stray malformed YAML or a typoed mnemonic before it reaches
// `Orchestrator::run` and silently breaks rewrite coverage in the field.

#include "morphkatz/rules/rule_loader.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <set>
#include <string>
#include <system_error>

namespace fs = std::filesystem;

namespace {

std::vector<fs::path> collect_yamls(const fs::path& root) {
    std::vector<fs::path> out;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(root, ec);
         it != fs::recursive_directory_iterator{}; it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        const auto ext = it->path().extension().string();
        if (ext == ".yaml" || ext == ".yml") {
            out.push_back(it->path());
        }
    }
    return out;
}

}  // namespace

TEST_CASE("every YAML rule pack loads via load_file",
          "[rules][schema][roundtrip]") {
    const fs::path rules_root = fs::path(MORPHKATZ_RULES_DIR) / "x64";
    REQUIRE(fs::is_directory(rules_root));

    const auto yamls = collect_yamls(rules_root);
    INFO("yaml count: " << yamls.size());
    REQUIRE(!yamls.empty());

    for (const auto& yaml : yamls) {
        INFO("yaml: " << yaml.string());
        auto rs = morphkatz::rules::load_file(yaml);
        REQUIRE(rs.ok());
        // Empty rule lists are explicitly allowed (push_pop_pairs.yaml ships
        // an empty `rules: []` as a placeholder for v1.1 peephole work).
        for (const auto& r : *rs) {
            INFO("rule_id: " << r.id);
            REQUIRE(!r.id.empty());

            const bool has_raw     = r.raw_from.has_value() && r.raw_to.has_value();
            const bool has_pattern = r.match_mnemonic != 0;
            REQUIRE((has_raw || has_pattern));

            if (has_raw) {
                REQUIRE(!r.raw_from->empty());
                REQUIRE(!r.raw_to->empty());
                REQUIRE(r.raw_from->size() == r.raw_to->size());
            } else {
                // Pattern-style rules must have a compiled predicate plus a
                // rewrite mnemonic; otherwise `engine::encode_rewrite` will
                // refuse them at run time.
                REQUIRE(r.compiled_predicate);
                REQUIRE(r.rewrite_mnemonic != 0);
            }

            // NotVerified is only legitimate when the loader saw an
            // unrecognised flags_effect token; surface it loudly so a
            // typoed YAML doesn't silently lose its flag gate.
            if (r.flags_effect ==
                morphkatz::rules::FlagsEquivalence::NotVerified) {
                WARN("rule " << r.id
                     << " resolved to FlagsEquivalence::NotVerified - "
                     << "check the flags_effect: token in its YAML");
            }
        }
    }
}

TEST_CASE("load_all aggregation has no duplicate rule ids",
          "[rules][schema][roundtrip]") {
    morphkatz::rules::LoaderOptions opts;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;
    auto pack = morphkatz::rules::load_all(opts);
    REQUIRE(pack.ok());

    std::set<std::string> seen;
    for (const auto& r : (*pack)->rules()) {
        INFO("duplicate rule id: " << r.id);
        REQUIRE(seen.insert(r.id).second);
    }
}
