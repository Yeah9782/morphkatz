/*
 * MorphKatz - Mimikatz target hint pack
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) MorphKatz contributors
 *
 * Purpose
 * -------
 * Hints for the MorphKatz rule matcher when the input binary is
 * a known Mimikatz build. The two rules below feed the
 * `PriorityMap::boost_for` lookup so candidate rewrites that touch
 * Mimikatz-shaped byte patterns are pushed up the polymorphic
 * selector's priority list and survive budget pruning.
 *
 * These rules are NOT a Mimikatz detector. They contain only
 * fragments that any reverse-engineering write-up of Mimikatz
 * already documents in public (the module identifiers map directly
 * to the canonical command surface in mimikatz_help / mimikatz.exe
 * banner output) plus byte sequences that match the existing
 * targeted YAML rule pack at rules/x64/targeted/mimikatz.yaml.
 *
 * Authoring guideline: add ONLY public, low-confidence atoms here.
 * High-confidence YARA detection rules live in third-party packs
 * (e.g. yara-rules/rules) and are loaded explicitly via --target.
 */

rule MorphKatz_Mimikatz_Strings
{
    meta:
        author      = "MorphKatz"
        license     = "AGPL-3.0-or-later"
        description = "Public banner / module identifiers shipped in mimikatz x86/x64 builds"
        target      = "HackTool:Win32/Mimikatz"
        confidence  = "low-priority hint, not a detection rule"

    strings:
        // banner tokens - present in the help screen and version stamp
        $b1 = "gentilkiwi" ascii wide nocase
        $b2 = "Benjamin DELPY" ascii wide nocase
        $b3 = "mimikatz" ascii wide nocase

        // canonical command surface (module::action)
        $m_kerb1   = "kerberos::list" ascii
        $m_sekur1  = "sekurlsa::msv" ascii
        $m_sekur2  = "sekurlsa::logonpasswords" ascii
        $m_sekur3  = "sekurlsa::tspkg" ascii
        $m_sekur4  = "sekurlsa::wdigest" ascii
        $m_sekur5  = "sekurlsa::kerberos" ascii
        $m_sekur6  = "sekurlsa::ekeys" ascii
        $m_lsad1   = "lsadump::sam" ascii
        $m_lsad2   = "lsadump::lsa" ascii
        $m_lsad3   = "lsadump::dcsync" ascii
        $m_lsad4   = "lsadump::secrets" ascii
        $m_crypto  = "crypto::capi" ascii
        $m_token   = "token::elevate" ascii
        $m_priv    = "privilege::debug" ascii
        $m_misc    = "misc::skeleton" ascii

        // structure / table identifiers used internally
        $s1 = "WDIGEST_GENERIC" ascii
        $s2 = "TSPKG_CREDENTIAL" ascii
        $s3 = "KIWI_DPAPI_CACHE" ascii
        $s4 = "KERB_QUERY_TKT_CACHE_INFO" ascii

    condition:
        4 of them
}

rule MorphKatz_Mimikatz_CodeAtoms
{
    meta:
        author      = "MorphKatz"
        license     = "AGPL-3.0-or-later"
        description = "Code-byte atoms aligned with rules/x64/targeted/mimikatz.yaml"
        target      = "HackTool:Win32/Mimikatz"
        confidence  = "code-byte hint, used to boost equivalent rewrites"

    strings:
        // 48 85 C9 / 48 09 C9 (test rcx,rcx <-> or rcx,rcx)
        $a_test_or = { 48 85 C9 }
        // 24 02 0F 84 00 00 (and al,2; je rel16) high byte bump pattern
        $a_je16    = { 24 02 0F 84 00 00 }
        // 5-byte LEA prefix scramble
        $a_lea5    = { 05 02 0F 0D 09 }
        // rip-relative indirect call prefix
        $a_indir   = { 24 43 72 64 41 48 FF 15 }
        // F3 0F 6F (movdqu) <-> C5 FA 6F (vmovdqu) with disp pattern
        $a_movdqu  = { F3 0F 6F 6C 24 30 }
        // 48 8B CA F3 (mov rcx,rdx; rep) <-> 48 89 D1 F3
        $a_mov_alt = { 48 8B CA F3 }

    condition:
        any of them
}
