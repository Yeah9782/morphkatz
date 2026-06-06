#include "morphkatz/verify/block_emu.hpp"

#if MORPHKATZ_WITH_UNICORN
#  include <unicorn/unicorn.h>
#endif

namespace morphkatz::verify {

#if MORPHKATZ_WITH_UNICORN

namespace {

constexpr uint64_t kStackVa  = 0x7fff'0000ULL;
constexpr uint64_t kStackSz  = 0x10000ULL;
constexpr uint64_t kPageSize = 0x4000ULL;

constexpr std::array<int, kBlockEmuGprCount> kGprIds{
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
    UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
    UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
};

struct UcGuard {
    uc_engine* h = nullptr;
    ~UcGuard() { if (h) uc_close(h); }
};

} // namespace

BlockEmuState default_block_emu_state() noexcept {
    BlockEmuState s{};
    s.gpr[kGprRax] = 0x1111'1111'1111'1111ULL;
    s.gpr[kGprRcx] = 0x2222'2222'2222'2222ULL;
    s.gpr[kGprRdx] = 0x3333'3333'3333'3333ULL;
    s.gpr[kGprRbx] = 0x4444'4444'4444'4444ULL;
    s.gpr[kGprRsp] = kStackVa + kStackSz / 2;
    s.gpr[kGprRbp] = 0x6666'6666'6666'6666ULL;
    s.gpr[kGprRsi] = 0x7777'7777'7777'7777ULL;
    s.gpr[kGprRdi] = 0x8888'8888'8888'8888ULL;
    s.gpr[kGprR8]  = 0x99a0ULL;
    s.gpr[kGprR9]  = 0x9991ULL;
    s.gpr[kGprR10] = 0x9992ULL;
    s.gpr[kGprR11] = 0x9993ULL;
    s.gpr[kGprR12] = 0x9994ULL;
    s.gpr[kGprR13] = 0x9995ULL;
    s.gpr[kGprR14] = 0x9996ULL;
    s.gpr[kGprR15] = 0x9997ULL;
    s.rflags       = 0;
    return s;
}

BlockEmuResult emulate_block(std::span<const uint8_t> code,
                             uint64_t va,
                             const BlockEmuState& in,
                             int timeout_ms) noexcept {
    BlockEmuResult r;
    UcGuard uc;

    if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc.h) != UC_ERR_OK) {
        r.error = "uc_open failed";
        return r;
    }

    const uint64_t page = va & ~(kPageSize - 1);
    if (uc_mem_map(uc.h, page, kPageSize, UC_PROT_ALL) != UC_ERR_OK) {
        r.error = "uc_mem_map code failed";
        return r;
    }
    if (uc_mem_write(uc.h, va, code.data(), code.size()) != UC_ERR_OK) {
        r.error = "uc_mem_write code failed";
        return r;
    }
    if (uc_mem_map(uc.h, kStackVa, kStackSz,
                   UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK) {
        r.error = "uc_mem_map stack failed";
        return r;
    }

    for (std::size_t i = 0; i < kBlockEmuGprCount; ++i) {
        uc_reg_write(uc.h, kGprIds[i], &in.gpr[i]);
    }
    if (in.rflags != 0) {
        // Caller-supplied EFLAGS preset; otherwise leave Unicorn's default.
        uc_reg_write(uc.h, UC_X86_REG_EFLAGS, &in.rflags);
    }

    const auto err = uc_emu_start(uc.h, va, va + code.size(),
                                  static_cast<uint64_t>(timeout_ms) * 1000ULL, 0);
    if (err != UC_ERR_OK && err != UC_ERR_FETCH_UNMAPPED) {
        r.error = std::string("uc_emu_start: ") + uc_strerror(err);
        return r;
    }

    for (std::size_t i = 0; i < kBlockEmuGprCount; ++i) {
        uc_reg_read(uc.h, kGprIds[i], &r.out.gpr[i]);
    }
    uc_reg_read(uc.h, UC_X86_REG_EFLAGS, &r.out.rflags);
    r.ok = true;
    return r;
}

#else  // !MORPHKATZ_WITH_UNICORN

BlockEmuState default_block_emu_state() noexcept { return {}; }

BlockEmuResult emulate_block(std::span<const uint8_t> /*code*/,
                             uint64_t /*va*/,
                             const BlockEmuState& /*in*/,
                             int /*timeout_ms*/) noexcept {
    BlockEmuResult r;
    r.error = "build was compiled without MORPHKATZ_WITH_UNICORN";
    return r;
}

#endif

} // namespace morphkatz::verify
