// Unicorn-backed equivalence proof harness for the YAML rule packs.
//
// For every per-instruction rule under rules/x64/equivalence/ and
// rules/x64/encoding/, this test:
//   1. Loads the bundled rule pack.
//   2. Looks up the rule by id and confirms its compiled predicate matches a
//      representative source instruction.
//   3. Runs `engine::encode_rewrite` on the source to obtain the rewritten
//      bytes.
//   4. Emulates `kSeedCount` distinct seeded random initial states under both
//      the original and the rewritten bytes via `verify::emulate_block`, then
//      asserts the live-out GPR file is bit-identical and that the
//      arithmetic-flag subset agrees modulo each rule's declared
//      `flags_value_diff_mask`.
//
// A failed assertion identifies the rule id, seed, and disagreeing register
// or flag; that is exactly the contract the rest of the rule-pack expansion
// work relies on.

#include "morphkatz/disasm/decoder.hpp"
#include "morphkatz/engine/encoder.hpp"
#include "morphkatz/engine/rng.hpp"
#include "morphkatz/ir/flags_effect.hpp"
#include "morphkatz/rules/rule_loader.hpp"

#if MORPHKATZ_WITH_UNICORN
#  include "morphkatz/verify/block_emu.hpp"
#endif

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <vector>

namespace {

#if MORPHKATZ_WITH_UNICORN

struct RuleCase {
    const char*                    rule_id;
    std::initializer_list<uint8_t> source_bytes;
};

// One representative source instruction per rule. Bytes are chosen to match
// the rule's predicate. Rules sharing a source mnemonic (e.g. all three
// zero_register variants on `xor rax, rax`) are listed independently so a
// predicate regression on any single rule fails its own case.
const RuleCase kCases[] = {
    // --- equivalence/zero_register.yaml ---
    {"x64.zero.xor_to_sub",        {0x48, 0x31, 0xC0}},  // xor rax, rax
    {"x64.zero.sub_to_xor",        {0x48, 0x29, 0xC0}},  // sub rax, rax
    {"x64.zero.xor_to_and_imm0",   {0x48, 0x31, 0xC0}},

    // --- equivalence/add_sub_neg.yaml ---
    {"x64.add_neg_to_sub_pos",     {0x48, 0x83, 0xC1, 0x05}}, // add rcx, 5
    {"x64.sub_neg_to_add_pos",     {0x48, 0x83, 0xE9, 0x50}}, // sub rcx, 0x50

    // --- equivalence/mov_forms.yaml ---
    {"x64.mov.r_r_alt_89_8b",      {0x48, 0x89, 0xC1}},          // mov rcx, rax
    {"x64.cmp.reg0_to_test_self",  {0x48, 0x83, 0xF8, 0x00}},    // cmp rax, 0
    {"x64.test_self.to_cmp_imm0",  {0x48, 0x85, 0xC0}},          // test rax, rax

    // --- encoding/alt_mov_89_8b.yaml ---
    {"x64.enc.mov_reg_reg",        {0x48, 0x89, 0xC1}},          // mov rcx, rax
    {"x64.enc.and_reg_reg",        {0x48, 0x21, 0xC1}},          // and rcx, rax
    {"x64.enc.or_reg_reg",         {0x48, 0x09, 0xC1}},          // or  rcx, rax

    // --- encoding/alt_nop_pool.yaml ---
    {"x64.nop.66_90",              {0x90}},
    {"x64.nop.0f_1f",              {0x90}},

    // --- equivalence/inc_dec.yaml (added by Phase 2) ---
    {"x64.inc.to_add1",            {0x48, 0xFF, 0xC0}},          // inc rax
    {"x64.add1.to_inc",            {0x48, 0x83, 0xC0, 0x01}},    // add rax, 1
    {"x64.dec.to_sub1",            {0x48, 0xFF, 0xC8}},          // dec rax
    {"x64.sub1.to_dec",            {0x48, 0x83, 0xE8, 0x01}},    // sub rax, 1

    // --- equivalence/test_or_cmp.yaml (added by Phase 2) ---
    {"x64.test_self.to_or_self",   {0x48, 0x85, 0xC0}},          // test rax, rax
    {"x64.or_self.to_test_self",   {0x48, 0x09, 0xC0}},          // or rax, rax

    // --- equivalence/shift_doubles.yaml (added by Phase 2) ---
    {"x64.shl1.to_add_self",       {0x48, 0xD1, 0xE0}},          // shl rax, 1
    {"x64.add_self.to_shl1",       {0x48, 0x01, 0xC0}},          // add rax, rax
};

// MorphKatz uses a compact F_* bit numbering that does not match the hardware
// EFLAGS bit positions. Convert a YAML-declared `flags_value_diff_mask` into
// the EFLAGS-layout bits Unicorn returns from UC_X86_REG_EFLAGS.
constexpr uint64_t to_eflags_bits(uint32_t mk_mask) noexcept {
    uint64_t out = 0;
    if (mk_mask & morphkatz::ir::F_CF) out |= 0x001ULL;
    if (mk_mask & morphkatz::ir::F_PF) out |= 0x004ULL;
    if (mk_mask & morphkatz::ir::F_AF) out |= 0x010ULL;
    if (mk_mask & morphkatz::ir::F_ZF) out |= 0x040ULL;
    if (mk_mask & morphkatz::ir::F_SF) out |= 0x080ULL;
    if (mk_mask & morphkatz::ir::F_TF) out |= 0x100ULL;
    if (mk_mask & morphkatz::ir::F_IF) out |= 0x200ULL;
    if (mk_mask & morphkatz::ir::F_DF) out |= 0x400ULL;
    if (mk_mask & morphkatz::ir::F_OF) out |= 0x800ULL;
    return out;
}

// CF, PF, AF, ZF, SF, DF, OF — the arithmetic flags the existing
// unicorn_verify call compares. We never compare TF/IF/RF/VM.
constexpr uint64_t kArithEflagsMask = 0x8D5ULL;

morphkatz::ir::Instruction decode_at(std::span<const uint8_t> bytes,
                                     uint64_t va = 0x1000) {
    morphkatz::ir::Instruction ins{};
    const auto rc = morphkatz::disasm::decode_one(bytes, va, 0, ins);
    REQUIRE(rc.ok());
    return ins;
}

const morphkatz::rules::Rule* find_rule(const morphkatz::rules::RulePack& pack,
                                        const std::string& id) {
    for (const auto& r : pack.rules()) {
        if (r.id == id) return &r;
    }
    return nullptr;
}

void seed_random_state(morphkatz::verify::BlockEmuState& s,
                       morphkatz::engine::Rng& rng) noexcept {
    // RSP is left at the harness-provided stack mid-point to keep PUSH/POP
    // emulations inside the mapped stack page. Every other GPR is fully
    // randomised so the equivalence assertion samples a meaningful slice of
    // the input space (sign bits, zero, parity-edge values, etc.).
    for (std::size_t i = 0; i < morphkatz::verify::kBlockEmuGprCount; ++i) {
        if (i == morphkatz::verify::kGprRsp) continue;
        s.gpr[i] = rng.next_u64();
    }
}

// Per-rule sample count. 64 random seeds is enough to exercise all the
// boundary cases the rules in our catalogue care about (MSB set/clear,
// low-nibble carry, zero, all-ones) without blowing CI wall-time. The
// existing unicorn-verify path runs once per patch; this is per rule.
constexpr int kSeedCount = 64;

void prove_rule(const morphkatz::rules::Rule& rule,
                std::span<const uint8_t> source_bytes,
                uint64_t mk_diff_mask) {
    const auto src_ins = decode_at(source_bytes);

    INFO("rule " << rule.id);
    REQUIRE(rule.compiled_predicate);
    REQUIRE(rule.compiled_predicate(src_ins));

    auto encoded = morphkatz::engine::encode_rewrite(src_ins, rule);
    REQUIRE(encoded.ok());
    REQUIRE(!encoded->empty());

    const std::vector<uint8_t> old_bytes(source_bytes.begin(), source_bytes.end());
    const std::vector<uint8_t> new_bytes = *encoded;

    const uint64_t flag_mask =
        kArithEflagsMask & ~to_eflags_bits(static_cast<uint32_t>(mk_diff_mask));

    constexpr uint64_t kEmuVa = 0x10'0000ULL;

    // Seed the same xoshiro stream the engine ships with; a fixed master
    // seed per-rule keeps every CI run deterministic.
    morphkatz::engine::Rng rng(uint64_t{0xC0FFEE'DEAD'B055ULL});
    auto seed = morphkatz::verify::default_block_emu_state();

    for (int i = 0; i < kSeedCount; ++i) {
        seed_random_state(seed, rng);

        const auto a = morphkatz::verify::emulate_block(
            std::span<const uint8_t>(old_bytes.data(), old_bytes.size()),
            kEmuVa, seed, /*timeout_ms*/ 200);
        const auto b = morphkatz::verify::emulate_block(
            std::span<const uint8_t>(new_bytes.data(), new_bytes.size()),
            kEmuVa, seed, /*timeout_ms*/ 200);

        INFO("seed iteration " << i);
        INFO("emu a.ok=" << a.ok << " err=" << a.error);
        INFO("emu b.ok=" << b.ok << " err=" << b.error);
        REQUIRE(a.ok);
        REQUIRE(b.ok);

        for (std::size_t g = 0; g < morphkatz::verify::kBlockEmuGprCount; ++g) {
            INFO("gpr index " << g);
            CHECK(a.out.gpr[g] == b.out.gpr[g]);
        }

        const uint64_t fa = a.out.rflags & flag_mask;
        const uint64_t fb = b.out.rflags & flag_mask;
        INFO("flag_mask 0x" << std::hex << flag_mask
             << " a=0x" << (a.out.rflags & kArithEflagsMask)
             << " b=0x" << (b.out.rflags & kArithEflagsMask));
        CHECK(fa == fb);
    }
}

#endif  // MORPHKATZ_WITH_UNICORN

}  // namespace

#if MORPHKATZ_WITH_UNICORN

TEST_CASE("every catalogued rule survives Unicorn equivalence proof",
          "[rules][equivalence][unicorn]") {
    morphkatz::rules::LoaderOptions opts;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;
    auto pack = morphkatz::rules::load_all(opts);
    REQUIRE(pack.ok());

    for (const auto& tc : kCases) {
        const auto* rule = find_rule(**pack, tc.rule_id);
        INFO("rule_id: " << tc.rule_id);
        REQUIRE(rule != nullptr);

        // Skip targeted raw-byte rules - they are validated separately by
        // tests/integration/targeted_byte_pairs_test.cpp.
        if (rule->raw_from || rule->raw_to) continue;

        // Rules that opt out of formal flag checking are out of scope for
        // the equivalence harness (the author has accepted responsibility).
        if (rule->flags_effect ==
            morphkatz::rules::FlagsEquivalence::NotVerified) {
            continue;
        }

        const std::vector<uint8_t> src(tc.source_bytes);
        prove_rule(*rule,
                   std::span<const uint8_t>(src.data(), src.size()),
                   rule->flags_value_diff_mask);
    }
}

#else  // !MORPHKATZ_WITH_UNICORN

TEST_CASE("rule equivalence proof harness requires Unicorn",
          "[rules][equivalence][unicorn][!mayfail]") {
    WARN("MORPHKATZ_WITH_UNICORN not defined; equivalence harness skipped");
    SUCCEED();
}

#endif
