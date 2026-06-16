#!/usr/bin/env python3
"""Offline FT_VOCAB seeding for protocol-parser fuzzers.

Background
----------

When a kernel parser emits a "reject" printk because trinity handed it
bytes that did not match its grammar, the printk is a precise,
attributable signal that *this* syscall (or subsystem) is bottlenecked
on a token-level shape the existing generators are not producing.  The
fix is to learn the literal grammar tokens once, offline, and seed them
into the vocabulary pools that struct_catalog FT_VOCAB / childop
payload builders already draw from.

Scope of this tool:
  - Offline.  Reads a dmesg.log and a kernel source tree; writes a C header.
  - Static tokens only.  No retain/mutate/replay.
  - Single-syscall payload BYTES.  No cross-syscall splice, no
    program-sequence synthesis, no unbounded growth.
  - SEEDS the existing generators; never replaces them.

Inputs
------
  --dmesg PATH      A run's dmesg.log.  Optional: when absent, the
                    kernel header is the sole token source and the
                    reject count is reported as zero.
  --kernel PATH     Root of a Linux source tree (e.g. /path/to/linux).
                    The recipe table below names the per-parser header
                    that defines the canonical key/value vocabulary.
  --out PATH        Output header path.  Atomically replaced only when the
                    generated content differs (cmp-then-rename), so that
                    re-running the tool with no input changes does not
                    invalidate ccache on a downstream rebuild.

Output
------
A C header (default include/generated/parser_vocab.h) containing, per
recipe, two NUL-terminated string arrays plus their counts:

    static const char * const <name>_key_vocab[];
    #define NR_<NAME>_KEY_VOCAB N
    static const char * const <name>_value_vocab[];
    #define NR_<NAME>_VALUE_VOCAB M

Plus a per-recipe leading comment recording the dmesg reject count, so
downstream consumers (childops, struct_catalog FT_VOCAB slots) can be
prioritised by which parsers are currently bottlenecked.

Recipes
-------
The iscsi text-key recipe is the only one today.  Adding a new recipe
is a table entry plus a header path -- no script logic change.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Recipe:
    """One parser surface to mine.

    name:               C symbol prefix (lowercase).  Drives the generated
                        array names: <name>_key_vocab / <name>_value_vocab.
    description:        Human-readable, dumped into the header comment.
    reject_patterns:    Regexes matched line-by-line against dmesg.log.
                        Hit count goes into the header comment as a
                        prioritisation hint for downstream consumers.
    key_header:         Path relative to --kernel root.  This header is
                        scanned for key_regex; capture group 1 is the
                        token added to <name>_key_vocab.
    key_regex:          Token-extracting regex against key_header.
    value_regex:        Optional second regex against key_header; capture
                        group 1 is added to <name>_value_vocab.  Used for
                        the INITIAL_* default-value mineable defines.
    value_macro_regex:  Regex matching "#define INITIAL_FOO BAREWORD"
                        lines; capture group 1 is the BAREWORD.  Those
                        barewords are macro names that themselves expand
                        to a string literal elsewhere in the header
                        (e.g. INITIAL_AUTHMETHOD = CHAP, where CHAP is
                        `#define CHAP "CHAP"`).  Used to (a) collect the
                        value string by chasing the indirection, and
                        (b) deny those macros from the *key* set, since
                        the same regex shape matches them as the real
                        key macros.
    value_only_macros:  Macro names that look like keys (key_regex
                        matches them) but are actually values used by
                        the parser as enumeration members rather than
                        keynames -- e.g. iscsi NONE / CRC32C / KRB5 /
                        SPKM1 / SPKM2 / SRP / DISCOVERY / NORMAL /
                        IRRELEVANT / NOTUNDERSTOOD which are never on
                        an INITIAL_* RHS but still must not enter the
                        key vocab (a real iscsi target rejects unknown
                        keys, so polluting the key set with values
                        would generate a *different* parser reject and
                        miss the win).
    """

    name: str
    description: str
    reject_patterns: tuple[str, ...]
    key_header: str
    key_regex: str
    value_regex: Optional[str]
    value_macro_regex: Optional[str]
    value_only_macros: tuple[str, ...]


# The recipe table.  iscsi key=value negotiation is the only surface today.
RECIPES: tuple[Recipe, ...] = (
    Recipe(
        name="iscsi_login",
        description=(
            "iSCSI Login text-key parser (drivers/target/iscsi/"
            "iscsi_target_parameters.c).  Reject signal is the '=' "
            "separator gate."
        ),
        reject_patterns=(
            # The exact printk from iscsi_target_parameters.c
            # iscsi_get_key_value() at the '=' lookup.
            r'Unable to locate "=" separator for key, ignoring request\.',
            # Two adjacent same-parser rejects worth counting alongside,
            # since hitting either still means the text-key parser saw
            # our bytes -- valuable signal that the framing got us past
            # the BHS gate.
            r'Login parameters failed',
            r'Unable to extract key.*from line',
        ),
        key_header="drivers/target/iscsi/iscsi_target_parameters.h",
        # Matches:  #define INITIATORNAME      "InitiatorName"
        # but NOT:  #define INITIAL_INITIATORNAME "LIO.Initiator"
        # (the leading-underscore-free CAPS macro is always the key name;
        # INITIAL_* is the seed default value, handled by value_regex.)
        key_regex=(
            r'^#define\s+(?!INITIAL_)'
            r'([A-Z][A-Z0-9_]*)\s+"([A-Za-z][A-Za-z0-9_]*)"'
        ),
        # Matches:  #define INITIAL_FOO        "value"
        # Only the quoted form -- the unquoted-macro form (YES / NO /
        # CHAP / NORMAL / ALL) is handled by extra_values so we do not
        # have to follow a second indirection through the header.
        value_regex=r'^#define\s+INITIAL_[A-Z][A-Z0-9_]*\s+"([^"]+)"',
        # Matches:  #define INITIAL_FOO   BAREWORD
        # The bareword resolves via key_regex to a string literal (e.g.
        # `#define CHAP "CHAP"`), which feeds the *value* vocab and is
        # excluded from the key vocab.
        value_macro_regex=r'^#define\s+INITIAL_[A-Z][A-Z0-9_]*\s+([A-Z][A-Z0-9_]*)\s*$',
        # Parser-enumeration members that are never on an INITIAL_* RHS
        # but must still be excluded from the key vocab.
        value_only_macros=(
            "NONE",                            # digest / auth no-op
            "IRRELEVANT", "NOTUNDERSTOOD",     # parser reject responses
            "KRB5", "SPKM1", "SPKM2", "SRP",   # AuthMethod alternates
            "CRC32C",                          # Digest alternate
            "DISCOVERY",                       # SessionType alternate
        ),
    ),
)


@dataclass
class MinedRecipe:
    """A recipe after mining: tokens collected, rejects counted."""
    recipe: Recipe
    keys: list[str] = field(default_factory=list)
    values: list[str] = field(default_factory=list)
    reject_count: int = 0


def count_rejects(dmesg_path: Optional[str], patterns: tuple[str, ...]) -> int:
    """Count lines in dmesg_path matching ANY of the given regexes.

    Missing file is not an error: runs without a dmesg.log must still
    produce a usable header.  Returns 0 in that case.
    """
    if dmesg_path is None or not os.path.exists(dmesg_path):
        return 0
    compiled = [re.compile(p) for p in patterns]
    count = 0
    # Line-by-line: dmesg.log can be 100s of MB on a long run, mmap'ing
    # is overkill and a regex sweep over each line is plenty fast.
    with open(dmesg_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if any(c.search(line) for c in compiled):
                count += 1
    return count


def mine_header(kernel_root: str, header_rel: str,
                key_regex: str, value_regex: Optional[str],
                value_macro_regex: Optional[str],
                value_only_macros: tuple[str, ...]
                ) -> tuple[list[str], list[str]]:
    """Extract (keys, values) from a kernel source header.

    Two-pass discipline:
      1. value_macro_regex builds a set of macro NAMES that are values,
         not keys (e.g. CHAP, YES, NO).  Identified by appearing on the
         right-hand side of `#define INITIAL_FOO BAREWORD`.
      2. key_regex matches lines of shape `#define MACRO "string"`.
         A match goes into:
           - the VALUE list if MACRO is in the value-macro set
             (capture group 2, the string literal, is the value);
           - the KEY list otherwise (capture group 2 is the key name).
      3. value_regex matches lines of shape
         `#define INITIAL_FOO "string"` and contributes group 1 to the
         value list directly (the quoted-default arm).

    All three lists are deduplicated, first-seen order preserved.
    """
    path = os.path.join(kernel_root, header_rel)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"recipe header {header_rel!r} not found under {kernel_root!r}; "
            f"pass --kernel pointing to a Linux source tree containing it"
        )

    with open(path, encoding="utf-8") as f:
        lines = f.readlines()

    # Pass 1: build the value-macro denylist.  Two sources:
    #   - value_macro_regex (BAREWORD on INITIAL_* RHS) -- learned
    #   - value_only_macros from the recipe -- hardcoded for tokens
    #     the kernel parser enumerates but never lists as a default.
    value_macros: set[str] = set(value_only_macros)
    if value_macro_regex is not None:
        vm_re = re.compile(value_macro_regex)
        for line in lines:
            m = vm_re.match(line)
            if m:
                value_macros.add(m.group(1))

    # Pass 2: split key_regex matches into keys / values by the
    # value-macro denylist.  Capture group 2 is always the string token
    # the parser sees on the wire ("InitiatorName", "Yes", etc.).
    key_re = re.compile(key_regex)
    keys: list[str] = []
    values: list[str] = []
    key_seen: dict[str, None] = {}
    val_seen: dict[str, None] = {}
    for line in lines:
        m = key_re.match(line)
        if not m or m.lastindex is None or m.lastindex < 2:
            continue
        macro_name = m.group(1)
        token = m.group(2)
        target = val_seen if macro_name in value_macros else key_seen
        target_list = values if macro_name in value_macros else keys
        if token not in target:
            target[token] = None
            target_list.append(token)

    # Pass 3: value_regex (the quoted-form default values).
    if value_regex is not None:
        val_re = re.compile(value_regex)
        for line in lines:
            m = val_re.match(line)
            if m and m.group(1) not in val_seen:
                val_seen[m.group(1)] = None
                values.append(m.group(1))

    return keys, values


def mine_recipe(recipe: Recipe, dmesg_path: Optional[str],
                kernel_root: str) -> MinedRecipe:
    """Run one recipe end-to-end."""
    keys, values = mine_header(kernel_root, recipe.key_header,
                               recipe.key_regex, recipe.value_regex,
                               recipe.value_macro_regex,
                               recipe.value_only_macros)
    reject_count = count_rejects(dmesg_path, recipe.reject_patterns)
    return MinedRecipe(recipe=recipe, keys=keys, values=values,
                       reject_count=reject_count)


def c_string_literal(s: str) -> str:
    """Render s as a C string literal, escaping the small set of bytes
    that can appear in a kernel-ABI vocabulary token.  Tokens are ASCII
    by construction (parser keynames, INITIAL_* defaults) so the escape
    set is intentionally narrow."""
    out = ['"']
    for ch in s:
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '\n':
            out.append('\\n')
        elif 0x20 <= ord(ch) <= 0x7e:
            out.append(ch)
        else:
            out.append(f'\\{ord(ch):03o}')
    out.append('"')
    return ''.join(out)


def render_header(mined: list[MinedRecipe], dmesg_path: Optional[str]) -> str:
    """Compose the generated C header from the mined recipes."""
    lines: list[str] = []
    lines.append("/*")
    lines.append(
        " * AUTO-GENERATED by scripts/seed-vocab-from-dmesg.py -- do not edit."
    )
    lines.append(" *")
    lines.append(
        " * Static vocab pools mined from kernel sources to seed protocol-"
    )
    lines.append(
        " * parser fuzzers with valid grammar tokens.  Each recipe emits a"
    )
    lines.append(
        " * NUL-terminated string array pair (keys + values) plus their"
    )
    lines.append(
        " * counts, consumed by per-surface childop / struct_catalog payload"
    )
    lines.append(
        " * builders so emitted text payloads carry tokens the kernel parser"
    )
    lines.append(" * actually recognises.")
    lines.append(" *")
    lines.append(" * Source signal:")
    if dmesg_path is None:
        lines.append(" *   dmesg.log: none provided")
    else:
        lines.append(f" *   dmesg.log: {dmesg_path}")
    lines.append(" */")
    lines.append("")
    lines.append("#pragma once")
    lines.append("")

    for m in mined:
        r = m.recipe
        upper = r.name.upper()

        lines.append(f"/* === {r.name} ===")
        lines.append(f" * {r.description}")
        lines.append(f" * Key source:  {r.key_header}")
        lines.append(f" * Rejects in run: {m.reject_count}")
        lines.append(f" * Keys mined:   {len(m.keys)}")
        lines.append(f" * Values mined: {len(m.values)}")
        lines.append(" */")
        lines.append("")

        lines.append(f"static const char * const {r.name}_key_vocab[] = {{")
        for k in m.keys:
            lines.append(f"\t{c_string_literal(k)},")
        lines.append("};")
        lines.append(f"#define NR_{upper}_KEY_VOCAB "
                     f"(sizeof({r.name}_key_vocab) / "
                     f"sizeof({r.name}_key_vocab[0]))")
        lines.append("")

        lines.append(f"static const char * const {r.name}_value_vocab[] = {{")
        for v in m.values:
            lines.append(f"\t{c_string_literal(v)},")
        lines.append("};")
        lines.append(f"#define NR_{upper}_VALUE_VOCAB "
                     f"(sizeof({r.name}_value_vocab) / "
                     f"sizeof({r.name}_value_vocab[0]))")
        lines.append("")

        # Per-recipe reject counter as a u32: lets a consumer that wants
        # to weight effort by parser hotness do so without parsing the
        # comment.  Static const so a TU can ifdef on it == 0.
        lines.append(f"#define {upper}_REJECT_COUNT {m.reject_count}u")
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def atomic_write(path: str, content: str) -> bool:
    """Replace path with content only if content differs.

    Returns True if the file was rewritten, False if it was unchanged.
    Mirrors the scripts/gen-versionh.sh discipline so re-runs do not
    invalidate ccache on a downstream build.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            old = f.read()
        if old == content:
            return False

    # Write to a tempfile in the same directory so the rename is atomic
    # within the filesystem (cross-fs rename would fall back to copy).
    fd, tmp = tempfile.mkstemp(prefix=".vocab.", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, path)
    except Exception:
        os.unlink(tmp)
        raise
    return True


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dmesg", help="path to a run's dmesg.log (optional)")
    p.add_argument("--kernel", required=True,
                   help="root of a Linux source tree (e.g. /path/to/linux)")
    p.add_argument("--out", default="include/generated/parser_vocab.h",
                   help="output header path "
                        "(default: include/generated/parser_vocab.h)")
    p.add_argument("--print-only", action="store_true",
                   help="render to stdout, do not write --out")
    args = p.parse_args(argv)

    mined: list[MinedRecipe] = []
    for r in RECIPES:
        m = mine_recipe(r, args.dmesg, args.kernel)
        mined.append(m)
        print(
            f"[{r.name}] keys={len(m.keys)} values={len(m.values)} "
            f"rejects={m.reject_count}",
            file=sys.stderr,
        )

    content = render_header(mined, args.dmesg)

    if args.print_only:
        sys.stdout.write(content)
        return 0

    changed = atomic_write(args.out, content)
    print(f"[out] {args.out} {'rewritten' if changed else 'unchanged'}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
