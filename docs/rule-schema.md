# MorphKatz rule schema (YAML, v1.0)

MorphKatz rule packs live under `rules/x64/` as YAML documents. A pack is
a single file containing a top-level `rules:` list. Every list entry is
one rule that the loader (`src/rules/rule_loader.cpp`) compiles into a
predicate plus a rewrite template.

Two rule flavours coexist:

1. **Per-instruction rewrites** — the matcher walks the decoded CFG and
   applies a rule when `match:` matches a single instruction. The rule
   supplies a typed rewrite template under `rewrite:`; the encoder
   (`src/engine/encoder.cpp`) produces the replacement bytes.
2. **Raw-byte rules** — bypasses the per-instruction matcher. The
   orchestrator feeds `(raw_from, raw_to)` pairs into `Patcher::queue_raw`,
   which runs them through an Aho-Corasick automaton over executable
   sections.

This document mirrors the loader as of v1.0. Anything not listed here is
either silently ignored (unknown keys) or **not implemented yet** — see
the [Not yet supported](#not-yet-supported) section at the bottom.

---

## Schema reference

```yaml
id: <string>            # required. Globally unique rule id, e.g. "x64.zero.xor_to_sub".
description: <string>   # optional. Human-readable summary.
weight: <double>        # optional. Selection weight (default 1.0).
flags_effect: <enum>    # optional. One of: equivalent | equivalent_if_dead.
                        # Defaults to equivalent. Anything starting with
                        # `equivalent_if` (e.g. `equivalent_if_dead` or
                        # `equivalent_if { CF, OF dead }`) is treated as
                        # equivalent_if_dead; anything else parses as
                        # not_verified.
flags_value_differs_in: # optional. List form OR `|`-separated string of
  - CF                  # flag tokens whose *value* differs between source
  - OF                  # and rewrite (the modified set may be identical
                        # but the carry/overflow/aux-carry value bits
                        # diverge). Only consulted when flags_effect is
                        # equivalent_if_dead. Tokens: CF PF AF ZF SF TF
                        # IF DF OF (case-insensitive).
size_delta: <int>       # optional. Author-declared byte-length delta;
                        # the matcher recomputes the actual delta from
                        # encoded output. Default 0.

# --- Per-instruction match (mutually exclusive with `raw:` block) ---
match:
  mnemonic: <string>          # required for per-instruction rules.
                              # Intel mnemonic, e.g. XOR, MOV, ADD, CMP, TEST.
  operand_count: <int>        # optional. Default: any (-1).
  constraints:                # optional list. Three shapes are accepted.
    # Shape A: same-register pair (relationship across two operands)
    - same_register: [0, 1]

    # Shape B: register blacklist (rejects rule if any operand reads/writes
    # one of these registers, including sub-register aliases like
    # ESP/SP/SPL for RSP).
    - register_blacklist: [RSP, RBP]

    # Shape C: per-operand constraint. Every key is optional; missing
    # keys behave as "any".
    - op: <int>                # operand index (default 0)
      kind: register | immediate | memory | relative
      class: gpr | gpr8 | gpr16 | gpr32 | gpr64 | xmm | ymm | zmm
      size_bits: <int>         # 8, 16, 32 or 64
      imm: <int>               # exact-value match for immediates

rewrite:
  mnemonic: <string>        # Intel mnemonic of the replacement.
  operands:                 # optional list. Three shapes are accepted.
    # Shape A: copy an operand verbatim from the matched source.
    - copy_from: <int>
      transform: negate     # optional. Flips the sign of a copied
                            # immediate (required for ADD<->SUB swaps).

    # Shape B: emit a literal immediate.
    - kind: immediate
      value: <int>          # default 0
      size_bits: <int>      # default 32

    # Shape C: emit a fixed register.
    - kind: register
      name: <Zydis name>    # required for this shape
      size_bits: <int>      # default 64

# --- Raw-byte match (mutually exclusive with `match:`) ---
raw:
  from: "48 31 C0"          # hex string. Whitespace, commas, colons and
  to:   "48 29 C0"          # tabs are stripped before parsing into bytes.
                            # `from` and `to` must be the same length.
```

### `flags_effect` semantics

| value                | meaning                                                                                             |
|----------------------|-----------------------------------------------------------------------------------------------------|
| `equivalent`         | Rewrite's flag effect is byte-identical to the source after canonicalisation (see `decoder.cpp`).  |
| `equivalent_if_dead` | Rewrite changes some flag bits; only applied when every differing bit is dead at this instruction. |

`equivalent_if_dead` rules typically also set `flags_value_differs_in`
to declare which flag *values* diverge. The matcher requires
`(decoder_diffs | flags_value_diff_mask) & live_out == 0` before firing.

Flag-liveness dataflow (`src/analysis/flag_liveness.cpp`) drives the
`equivalent_if_dead` gate at `src/rules/rule_matcher.cpp`.

### Rewrite operand sources

- `copy_from: <int>` — take the operand from the source instruction at
  the given index. Used for register, immediate, and memory operands
  that the matcher already validated. Add `transform: negate` to flip
  the sign of a copied immediate (required by the ADD <-> SUB swap
  rules so `sub a, X` becomes `add a, -X`, not the wrong-direction
  `add a, X`).
- `kind: immediate` — emit a literal immediate (`value:` default 0,
  `size_bits:` default 32).
- `kind: register` — emit a specific register (`name: RAX`,
  `size_bits:` default 64).

### Raw rules — caveats

Raw rules **must** have identical `from`/`to` byte lengths (the
patcher enforces this and skips mismatched pairs with a warning). They
match anywhere in scanned PE sections, so they are appropriate only
for multi-byte signatures that are statistically unique inside real
PEs (e.g. Mimikatz's `48 8B 02 48 89 41 40` prologue). One- or
two-byte `from:` patterns will create collateral damage.

Raw rules ignore `match:`, `rewrite:`, and `flags_effect:` at run
time — only `id`, `description`, `raw`, `size_delta` and `weight` are
consulted by the matcher / orchestrator.

---

## Loader behaviour

- Files are parsed recursively from `LoaderOptions.default_rules_dir`
  (defaulting to the `share/morphkatz/rules` install dir) plus every
  `LoaderOptions.extra_paths` entry. Both `.yaml` and `.yml` extensions
  are picked up.
- Parse errors are fatal: a single malformed YAML aborts the entire
  rule-pack load and surfaces as `ErrorKind::RuleLoad`.
- File-level keys like `version:` and top-level `description:` are
  permitted but ignored.
- Unknown keys on rule entries are silently ignored. Use the schema
  reference above as the authoritative key list.

---

## Writing a new rule

1. Pick the right directory:
   - `rules/x64/equivalence/` — semantically equivalent rewrites.
   - `rules/x64/encoding/` — alternate encoding forms of the same
     semantics (MOV 89/8B swap, AND/OR bit-fiddling).
   - `rules/x64/targeted/` — raw-byte patterns against a specific
     attacker toolchain (Mimikatz, CobaltStrike, Donut, Adaptix).
2. Keep `flags_effect: equivalent` where possible. When the rewrite
   touches different *value* bits (e.g. ADD <-> SUB swaps), declare
   them in `flags_value_differs_in:` and switch to
   `equivalent_if_dead`. The flag-liveness pass will keep you honest.
3. Add a guard test:
   - per-instruction rules are exercised automatically by
     [`tests/unit/rule_equivalence_proof_test.cpp`](../tests/unit/rule_equivalence_proof_test.cpp).
     Append your `(rule_id, source_bytes)` pair to the `kCases` table
     so the Unicorn-backed harness runs 64 seeded random initial
     states through both your source and your rewrite and asserts
     GPR / flag equivalence.
   - raw-byte rules belong in
     [`tests/integration/targeted_byte_pairs_test.cpp`](../tests/integration/targeted_byte_pairs_test.cpp).
4. Every YAML file is also auto-verified by
   [`tests/unit/rule_schema_roundtrip_test.cpp`](../tests/unit/rule_schema_roundtrip_test.cpp)
   for: non-empty `id`, either `match`+`rewrite` or `raw`, no duplicate
   ids across the whole pack, and (warning) for any rule that the
   loader downgraded to `NotVerified` because the `flags_effect:` token
   was unrecognised.

---

## Not yet supported

The loader **silently ignores** anything it does not recognise. The
constructs below are common ones that the documentation has historically
implied or that contributors have asked for, and they are not yet
implemented. Track them in `docs/roadmap.md` if you need any of them.

- `imm_in_range` / `imm_min` / `imm_max` — only exact `imm:` equality
  works today. Required for the `imm_sign_extend` encoding rule that
  forces `81 /0 id` over `83 /0 ib` for `imm in [-128, 127]`.
- Memory operand sub-fields under `constraints:` (base, index, scale,
  displacement bounds). Memory operands can only be matched by `kind:
  memory` and `size_bits:`; finer constraints are not parsed.
- Multi-instruction / peephole match windows. `push_pop_pairs.yaml`
  ships with `rules: []` because the two-instruction matcher is on
  the v1.1 roadmap.
- Conditional rules (`when: os_version > 10.0.22000`, profile tags
  that actually filter). `LoaderOptions.profile` exists but is not
  consulted by the loader today.
- ModR/M direction / opcode-form forcing in `rewrite:`. The encoder
  picks the canonical encoding; alternative encodings are landed as
  separate rules in `rules/x64/encoding/`.
- `copy_from` operand size override (e.g. take operand 1 but force a
  wider encoding). Today a copied operand inherits its source width.

---

Last updated: v1.0.
