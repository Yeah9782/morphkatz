#include "morphkatz/verify/unicorn_verify.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/format/pe_image.hpp"
#include "morphkatz/verify/block_emu.hpp"

namespace morphkatz::verify {

#if MORPHKATZ_WITH_UNICORN

Result<void> unicorn_verify(const format::PeImage& image,
                            const std::vector<engine::AppliedPatch>& applied,
                            const UnicornOptions& opts) {
    (void)image;  // reserved for future cross-block memory seeding
    std::size_t agree = 0, disagree = 0;

    const auto seed = default_block_emu_state();

    for (const auto& p : applied) {
        if (p.old_bytes.empty() || p.new_bytes.empty()) continue;

        const auto a = emulate_block(p.old_bytes, p.va, seed, opts.timeout_ms);
        const auto b = emulate_block(p.new_bytes, p.va, seed, opts.timeout_ms);
        if (!a.ok || !b.ok) continue;

        // Arithmetic flag-subset comparison (ignore TF/IF/RF/VM which Unicorn
        // may set differently depending on mode).
        constexpr uint64_t mask = 0x8D5;  // CF PF AF ZF SF DF OF (EFLAGS bits)
        if (a.out.gpr == b.out.gpr &&
            (a.out.rflags & mask) == (b.out.rflags & mask)) {
            ++agree;
        } else {
            ++disagree;
            if (opts.log_first_disagreement && disagree == 1) {
                MK_WARN("unicorn disagreement at 0x{:x} rule={}", p.va, p.rule_id);
            }
        }
    }

    MK_INFO("Unicorn verify: {} agree, {} disagree", agree, disagree);
    if (disagree > 0) {
        return Error::make(ErrorKind::Verify,
            fmt::format("unicorn self-verify: {} patches disagree", disagree));
    }
    return {};
}

#else   // !MORPHKATZ_WITH_UNICORN

Result<void> unicorn_verify(const format::PeImage& /*image*/,
                            const std::vector<engine::AppliedPatch>& /*applied*/,
                            const UnicornOptions& /*opts*/) {
    return Error::make(ErrorKind::NotSupported,
        "build was compiled without MORPHKATZ_WITH_UNICORN");
}

#endif

}
