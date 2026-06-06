#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>

namespace morphkatz::verify {

// Unicorn-backed straight-line basic-block emulator, extracted from
// `unicorn_verify` so unit tests can prove rule-pack semantic equivalence
// under caller-supplied initial register state.
//
// The harness maps two pages per call:
//   - one 16 KiB RWX code page covering [va & ~0x3FFF, ...] with `code` at va
//   - one 64 KiB RW stack page at 0x7FFF_0000
//
// All MORPHKATZ_WITH_UNICORN gating lives in the .cpp; the header is buildable
// either way. When Unicorn is not linked, `emulate_block` returns ok=false.

inline constexpr std::size_t kBlockEmuGprCount = 16;

enum BlockEmuGpr : std::size_t {
    kGprRax = 0, kGprRcx, kGprRdx, kGprRbx,
    kGprRsp,     kGprRbp, kGprRsi, kGprRdi,
    kGprR8,      kGprR9,  kGprR10, kGprR11,
    kGprR12,     kGprR13, kGprR14, kGprR15,
};

struct BlockEmuState {
    std::array<uint64_t, kBlockEmuGprCount> gpr{};
    uint64_t rflags = 0;
};

struct BlockEmuResult {
    bool          ok = false;
    BlockEmuState out{};
    std::string   error;
};

// Deterministic non-trivial seed with RSP pointing inside the harness stack.
[[nodiscard]] BlockEmuState default_block_emu_state() noexcept;

// Run `code` at `va` from initial state `in`; return GPR + EFLAGS live-out.
[[nodiscard]] BlockEmuResult emulate_block(std::span<const uint8_t> code,
                                           uint64_t va,
                                           const BlockEmuState& in,
                                           int timeout_ms = 200) noexcept;

} // namespace morphkatz::verify
