#!/bin/bash
#
# params-value-lists: the values the tree advertises for a mode option must be
# the values its parser accepts.
#
# A mode option is parsed by strcmp(arg, "value") arms under
# strcmp("option", name) in main/params/*.c.  What an operator reads is prose:
# the --help row, the option's section in a document, an inline
# "--option=a|b|c".  A value listed but not parsed is rejected at startup, and
# one parsed but not listed cannot be found.  The accepted values are read out
# of the parser source and diffed in both directions against each advertised
# list:
#
#   help.c          every such option needs an option_descs[] row listing
#                   exactly its values as "a/b/c", "a / b" or "a or b"; a row
#                   that lists "off" for an option with no arms is an error,
#                   since that parser is one this gate cannot read
#   *.md            the `value` bullets under an option's "## --option"
#                   heading; a heading with none is an error
#   .c .h .md .txt .1 README
#                   every inline "--option=a|b|c"
#
# Only tracked files are read, so an untracked scratch note cannot fail the
# gate; a tree without .git is an export and is walked instead.  Not read:
# prose preambles, bullets written "* x" or "- **x**", single-value
# "--option=x" examples, help strings that mix "/" and "|", and the parser's
# own error strings.
#
# Sources are only read; the one process started is git, to list the tracked
# files.

set -u

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

NAME="params-value-lists"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
PARAMS="$ROOT/main/params"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$PARAMS/help.c" ] || fail "cannot read ${PARAMS#"$ROOT"/}/help.c"
command -v python3 >/dev/null 2>&1 || fail "python3 not found in PATH"

# A commented-out arm is not an accepted value, so the parser is read with
# its comments removed.
stripped="$(mktemp -d)" || fail "mktemp failed"
trap 'rm -rf "$stripped"' EXIT
for f in "$PARAMS"/*.c; do
	[ -r "$f" ] || fail "cannot read ${f#"$ROOT"/}"
	strip_c_comments "$f" > "$stripped/$(basename "$f")"
done

python3 - "$stripped" "$NAME" "$ROOT" <<'PYEOF'
import io
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

stripped_dir, name, root = sys.argv[1:4]

VALUE = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"

# strcmp("option", name) is how a parse_*_options() helper claims a long
# option and strcmp(arg, "value") is one accepted value.  The != form is a
# guard that returns when the name is not the option's, so the option owns
# the rest of the function.
OPTION_RE = re.compile(
    r'strcmp\s*\(\s*"(' + VALUE + r')"\s*,\s*name\s*\)\s*(==|!=)\s*0')
ARM_RE = re.compile(r'strcmp\s*\(\s*arg\s*,\s*"([^"\\\n]*)"\s*\)\s*==\s*0')

# { "option", 'c' or 0, "description" or NULL }, the description possibly
# several adjacent literals.
ROW_RE = re.compile(
    r'\{\s*"([^"\\]+)"\s*,\s*(?:\'[^\'\\]\'|0)\s*,\s*'
    r'(NULL|(?:"(?:[^"\\]|\\.)*"\s*)+)\s*\}')
END_RE = re.compile(r'\{\s*NULL\s*,\s*0\s*,\s*NULL\s*\}')
STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

# A value list as help text spells it: a/b/c, "a (default) / b" or "a or b".
# The lookbehind keeps the match out of paths and identifiers.
ITEM = VALUE + r"(?:\s*\(default\))?"
SEP = r"(?:\s*/\s*|\s+or\s+)"
GROUP_RE = re.compile(
    r"(?<![\w$./<>-])" + ITEM + "(?:" + SEP + ITEM + r")+(?![\w-])")
SEP_RE = re.compile(SEP)

HEADING_RE = re.compile(r"^#{1,6}\s")
SECTION_RE = re.compile(r"^#{1,6}\s+--(" + VALUE + r")\s*$")
BULLET_RE = re.compile(r"^- (`[^`\n]+`(?:\s*/\s*`[^`\n]+`)*)")
INLINE_RE = re.compile(
    r"--(" + VALUE + r")=(" + VALUE + r"(?:\|" + VALUE + r")+)")

TEXT_SUFFIXES = (".c", ".h", ".md", ".txt", ".1")

# The checkout is found from its path, not from whatever repository the caller
# is inside of, so a hook or rebase exporting GIT_DIR cannot redirect it.
GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


class GateFailure(Exception):
    pass


def matching_brace(src, start):
    # Braces inside string and char literals do not count.
    depth = 0
    i = start
    while i < len(src):
        c = src[i]
        if c in "\"'":
            i += 1
            while i < len(src) and src[i] != c:
                i += 2 if src[i] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise GateFailure("unbalanced braces after an option test in the parser")


def parse_options(files):
    # {option: set of accepted values}, for each option whose block holds
    # strcmp(arg, "value") arms.  An option with none is a flag or is parsed
    # by a helper, and is not a list this gate can check.
    options = {}
    for src in files:
        for m in OPTION_RE.finditer(src):
            if m.group(2) == "==":
                head = re.match(r"\s*\)\s*\{", src[m.end():])
                if not head:
                    continue
                start = m.end() + head.end() - 1
                block = src[start:matching_brace(src, start)]
            else:
                end = src.find("\n}\n", m.end())
                block = src[m.end():end if end >= 0 else len(src)]
            values = set(ARM_RE.findall(block))
            if values:
                options.setdefault(m.group(1), set()).update(values)
    return options


def parse_help(src):
    # {option: [(description or None, line)]} from option_descs[].
    table = re.search(r"option_descs\s*\[\s*\]\s*=\s*\{(.*?)\n\};", src,
                      re.DOTALL)
    if not table:
        raise GateFailure("could not locate option_descs[] in "
                          "main/params/help.c")
    body = table.group(1)
    first = src.count("\n", 0, table.start(1)) + 1
    rows = {}
    for m in ROW_RE.finditer(body):
        desc = None if m.group(2) == "NULL" else "".join(
            STRING_RE.findall(m.group(2)))
        line = first + body.count("\n", 0, m.start())
        rows.setdefault(m.group(1), []).append((desc, line))
    # Text left over once the rows are removed is a row the extractor did
    # not read; ignoring it would pass on a partial table.
    leftover = END_RE.sub("", ROW_RE.sub("", body)).strip(" \t\n,")
    if leftover:
        raise GateFailure("option_descs[] holds text the extractor cannot "
                          f"read: {leftover[:60]!r}")
    return rows


def help_lists(desc):
    # Every value list in desc, as a list of values.
    return [[re.sub(r"\s*\(default\)$", "", item)
             for item in SEP_RE.split(m.group(0))]
            for m in GROUP_RE.finditer(desc)]


def diff(accepted, advertised, subject, where):
    # A finding is (file, line, text), with line 0 when it has none.
    # advertised maps each value to the (file, line) it is listed at, and
    # where is the (file, line) of the list itself.
    problems = []
    for value in sorted(set(advertised) - accepted):
        problems.append((*advertised[value],
                         f"{subject} advertises '{value}', which the parser "
                         f"rejects (it accepts "
                         f"{', '.join(sorted(accepted))})"))
    for value in sorted(accepted - set(advertised)):
        problems.append((*where, f"{subject} omits '{value}', which the "
                                 f"parser accepts"))
    return problems


def check_help(options, rows, rel):
    problems = []
    for option, accepted in sorted(options.items()):
        if option not in rows:
            problems.append((rel, 0, f"--{option} has no option_descs[] row; "
                                     f"the parser accepts "
                                     f"{', '.join(sorted(accepted))}"))
        for desc, line in rows.get(option, []):
            where = (rel, line)
            listed = {}
            for values in help_lists(desc or ""):
                # A list holding none of the accepted values is something
                # else, like "producer/consumer".
                if accepted & set(values):
                    listed.update({v: where for v in values})
            problems += diff(accepted, listed, f"--{option} help text", where)
    for option, entries in sorted(rows.items()):
        if option in options:
            continue
        for desc, line in entries:
            if any("off" in values for values in help_lists(desc or "")):
                problems.append((
                    rel, line,
                    f"--{option} lists off/... but the parser has no "
                    f"strcmp(arg, ...) arms for it, which is a shape this "
                    f"gate cannot read"))
    return problems


def check_sections(options, text, rel):
    # The `value` bullets under a "## --option" heading are its value list.
    # A bullet naming something else, like a constant, is not one.
    problems = []
    found = 0
    section = None

    def close():
        if section is None:
            return
        option, line, listed = section
        subject = f"--{option} section"
        if listed:
            problems.extend(diff(options[option], listed, subject,
                                 (rel, line)))
        else:
            accepted = ', '.join(sorted(options[option]))
            problems.append((rel, line, f"{subject} has no `value` "
                                        f"bullets; the parser accepts "
                                        f"{accepted}"))

    for line, text_line in enumerate(text.split("\n"), 1):
        if HEADING_RE.match(text_line):
            close()
            m = SECTION_RE.match(text_line)
            section = ((m.group(1), line, {})
                       if m and m.group(1) in options else None)
            if section is not None:
                found += 1
        elif section is not None:
            m = BULLET_RE.match(text_line)
            words = re.findall(r"`([^`\n]+)`", m.group(1)) if m else []
            if words and all(re.fullmatch(VALUE, w) for w in words):
                for w in words:
                    section[2].setdefault(w, (rel, line))
    close()
    return problems, found


def check_inline(options, text, rel):
    problems = []
    found = 0
    for line, text_line in enumerate(text.split("\n"), 1):
        for m in INLINE_RE.finditer(text_line):
            if m.group(1) not in options:
                continue
            found += 1
            where = (rel, line)
            listed = {v: where for v in m.group(2).split("|")}
            problems += diff(options[m.group(1)], listed,
                             f"inline --{m.group(1)} list", where)
    return problems, found


def report(problems, out):
    print(f"FAIL: {name}: advertised value lists differ from the parser",
          file=out)
    for rel, line, text in sorted(set(problems)):
        print(f"  {rel}:{line}: {text}" if line else f"  {rel}: {text}",
              file=out)
    print("  The parser is the strcmp(arg, ...) arms in main/params/*.c: "
          "change the text to", file=out)
    print("  match them, or change the arms and the text together.",
          file=out)


def source_files(base):
    # The files whose text is checked, relative to base.  An untracked
    # scratch note quoting an old list would fail the battery for text that
    # never ships, so a git checkout is read from its index.  A tree without
    # .git is an export, which has nothing untracked, and is walked.
    if os.path.exists(os.path.join(base, ".git")):
        try:
            listing = subprocess.run(
                ["git", "-C", base, "ls-files", "-z"], env=GIT_ENV,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True).stdout
        except OSError as e:
            raise GateFailure(f"cannot run git to list the tracked files: "
                              f"{e.strerror or e}")
        except subprocess.CalledProcessError as e:
            lines = e.stderr.decode(errors="replace").strip().splitlines()
            raise GateFailure("git ls-files failed: " +
                              (lines[0] if lines else f"exit {e.returncode}"))
        names = os.fsdecode(listing).split("\0")
    else:
        names = []
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            names += [os.path.relpath(os.path.join(dirpath, f), base)
                      for f in filenames]
    return sorted(n for n in names if n.endswith(TEXT_SUFFIXES) or
                  os.path.basename(n) == "README")


def read_source(base, rel):
    # The text of a tracked file, or None if it is gone from the work tree.
    # A file that exists but cannot be read, such as a dangling symlink,
    # fails the gate instead of passing unchecked.
    path = os.path.join(base, rel)
    if not os.path.lexists(path):
        return None
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise GateFailure(f"cannot read {rel}: {e.strerror or e}")


def selftest():
    # Synthetic sources put every detector through both outcomes whatever
    # the real tree holds: one that stopped finding drift, or found it
    # everywhere, would pass or fail the tree for the wrong reason.  The
    # fixtures include the shapes the real parser has -- the != guard form
    # that owns the rest of its function, a description in two literals --
    # an unbalanced brace in a string and in a char literal, and near-misses
    # a looser extractor would take for a value list.
    parser = r'''
bool parse_a(int opt, const char *name, char *arg)
{
    if (strcmp("alpha", name) == 0) {
        if (strcmp(arg, "off") == 0) {
            outputerr("a } in a string\n");
            alpha = 0;
        } else if (strcmp(arg, "shadow-only") == 0) {
            alpha = 1;
        } else {
            outputerr("--alpha: unknown '%s'\n", arg);
            exit(EXIT_FAILURE);
        }
        return true;
    }

    if (strcmp("beta", name) == 0) {
        if (strcmp(arg, "off") == 0) {
            beta = '}';
        } else if (strcmp(arg, "auto") == 0) {
            beta = 1;
        } else if (strcmp(arg, "on") == 0) {
            beta = 2;
        }
        return true;
    }

    if (strcmp("flag", name) == 0) {
        flag = true;
        return true;
    }

    return false;
}

bool parse_b(int opt, const char *name, char *arg)
{
    if (strcmp("delta", name) != 0)
        return false;

    if (arg == NULL || strcmp(arg, "pools") == 0) {
        delta = 1;
    } else if (strcmp(arg, "all") == 0) {
        delta = 2;
    } else if (strcmp(arg, "off") == 0) {
        delta = 0;
    }
    return true;
}

bool parse_c(int opt, const char *name, char *arg)
{
    if (strcmp("gamma", name) == 0) {
        if (strcmp(arg, "x") == 0)
            gamma = 1;
        else if (strcmp(arg, "y") == 0)
            gamma = 2;
        return true;
    }
    return false;
}
'''
    expected = {"alpha": {"off", "shadow-only"},
                "beta": {"off", "auto", "on"},
                "delta": {"off", "pools", "all"},
                "gamma": {"x", "y"}}
    options = parse_options([parser])
    if options != expected:
        raise GateFailure(f"self-test: parser extraction: expected "
                          f"{expected}, got {options}")
    try:
        parse_options(['if (strcmp("alpha", name) == 0) { if (a) {'])
    except GateFailure:
        pass
    else:
        raise GateFailure("self-test: unbalanced braces were accepted")

    help_src = r'''
static const struct option_help option_descs[] = {
    { "alpha",     0,  "alpha thing: off/shadow-only (default off)" },
    { "beta",    'b', "beta thing: auto (default) or off/on" },
    { "delta",     0,  "delta regions: off/pools/all" },
    { "gamma",     0,  "gamma"
                 " thing: x (default) / y" },
    { "flag",     0,  "set the flag; tuning/knobs live elsewhere" },
    { "nodesc",     0,  NULL },
    { NULL,         0,  NULL },
};
'''

    # Each case swaps one piece of a clean fixture for another and says how
    # many problems that must produce.  An edit that matches nothing would
    # leave the case testing the clean fixture, so it is an error.
    help_cases = [
        ("clean help, with a slash pair on a flag row", 0,
         "alpha thing", "alpha thing"),
        ("help lists a value the parser rejects", 1,
         "off/shadow-only (", "off/shadow-only/combined ("),
        ("help drops a value the parser accepts", 1,
         "auto (default) or off/on", "auto (default) or off"),
        ("help has no row for an option with arms", 2,
         '{ "alpha",', '{ "alphax",'),
        ("help row with no description", 3,
         '"delta regions: off/pools/all"', "NULL"),
        ("off list for an option with no arms", 1,
         "set the flag;", "set the flag: off/on;"),
        ("unrelated slash pair beside the real list", 0,
         "beta thing: auto", "beta producer/consumer: auto"),
    ]
    for label, count, old, new in help_cases:
        text = help_src.replace(old, new)
        if (text == help_src) != (old == new):
            raise GateFailure(f"self-test: {label}: stale fixture edit")
        problems = check_help(options, parse_help(text), "help.c")
        if len(problems) != count:
            raise GateFailure(f"self-test: {label}: expected {count} "
                              f"problem(s), got {problems}")
    try:
        parse_help(help_src.replace('"alpha",     0,', '"alpha",     flags,'))
    except GateFailure:
        pass
    else:
        raise GateFailure("self-test: an unreadable option_descs[] row was "
                          "accepted")

    doc = ("## --alpha\n\n- `off`: a\n- `shadow-only` (default): b\n\n"
           "## --beta\n\n- `auto` / `on` (default): a\n- `off`: b\n"
           "- `BETA_MAX`: not a value\n\n## --flag\n\n- `anything`: c\n")
    doc_cases = [
        ("clean doc", 0, "## --flag", "## --flag"),
        ("section lists a value the parser rejects", 1,
         "- `off`: a\n", "- `off`: a\n- `combined`: z\n"),
        ("section drops a value the parser accepts", 1,
         "- `shadow-only` (default): b\n", ""),
        ("section with prose and no bullets", 1,
         "- `off`: a\n- `shadow-only` (default): b\n", "prose\n"),
        ("heading with trailing words is not a section", 0,
         "## --alpha\n", "## --alpha design\n"),
        ("bullets under the next heading are not the section's", 0,
         "## --beta\n", "## Other\n\n- `combined`: z\n\n## --beta\n"),
    ]
    for label, count, old, new in doc_cases:
        text = doc.replace(old, new)
        if (text == doc) != (old == new):
            raise GateFailure(f"self-test: {label}: stale fixture edit")
        problems, _ = check_sections(options, text, "d.md")
        if len(problems) != count:
            raise GateFailure(f"self-test: {label}: expected {count} "
                              f"problem(s), got {problems}")

    inline = [
        ("clean inline list", 0, "use `--alpha=off|shadow-only` here"),
        ("inline list with a rejected value", 1,
         "use `--alpha=off|shadow-only|combined` here"),
        ("inline list missing a value", 1, "use `--beta=off|on`"),
        ("inline list for an unknown option", 0, "`--nosuch=a|b`"),
        ("single inline value is not a list", 0, "`--alpha=combined`"),
    ]
    for label, count, text in inline:
        problems, _ = check_inline(options, text, "i.c")
        if len(problems) != count:
            raise GateFailure(f"self-test: {label}: expected {count} "
                              f"problem(s), got {problems}")

    # Findings sort by file and numeric line, so line 95 comes before 107.
    shown = io.StringIO()
    report([("b.c", 107, "x"), ("b.c", 95, "y"), ("a.md", 3, "z"),
            ("b.c", 0, "w")], shown)
    got = shown.getvalue().splitlines()[1:5]
    if got != ["  a.md:3: z", "  b.c: w", "  b.c:95: y", "  b.c:107: x"]:
        raise GateFailure(f"self-test: findings are not ordered by file and "
                          f"line: {got}")

    # A tree without .git is walked; in a git checkout only the tracked
    # files count, so an untracked note beside them cannot matter.
    with tempfile.TemporaryDirectory() as tmp:
        for rel in ("a.md", "b.md", "c.c", "d.txt", "e.o", "sub/README"):
            os.makedirs(os.path.dirname(os.path.join(tmp, rel)),
                        exist_ok=True)
            Path(tmp, rel).write_text("x\n")
        if source_files(tmp) != ["a.md", "b.md", "c.c", "d.txt",
                                 "sub/README"]:
            raise GateFailure(f"self-test: a tree without .git was not "
                              f"walked: {source_files(tmp)}")
        if os.path.exists(os.path.join(root, ".git")):
            try:
                for args in (["init", "-q"],
                             ["add", "a.md", "c.c", "sub/README"]):
                    subprocess.run(["git", "-C", tmp] + args, env=GIT_ENV,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, check=True)
            except (OSError, subprocess.CalledProcessError) as e:
                raise GateFailure(f"self-test: cannot set up a scratch "
                                  f"git tree: {e}")
            if source_files(tmp) != ["a.md", "c.c", "sub/README"]:
                raise GateFailure(f"self-test: untracked files were listed: "
                                  f"{source_files(tmp)}")

        # An unreadable file is a failure, a file that is gone is skipped.
        os.symlink(os.path.join(tmp, "nowhere"),
                   os.path.join(tmp, "dangling.md"))
        got = (read_source(tmp, "a.md"), read_source(tmp, "gone.md"))
        if got != ("x\n", None):
            raise GateFailure(f"self-test: a readable file was not read or "
                              f"a removed one was not skipped: {got}")
        try:
            read_source(tmp, "dangling.md")
        except GateFailure as e:
            if "cannot read dangling.md" not in str(e):
                raise GateFailure(f"self-test: unexpected message: {e}")
        else:
            raise GateFailure("self-test: a dangling symlink was read")


def main():
    selftest()

    sources = {p.name: p.read_text(encoding="utf-8", errors="replace")
               for p in sorted(Path(stripped_dir).glob("*.c"))}
    options = parse_options(sources.values())
    if not options:
        raise GateFailure("found no strcmp(arg, ...) arms under "
                          "strcmp(\"option\", name) in main/params/*.c")
    problems = check_help(options, parse_help(sources["help.c"]),
                          "main/params/help.c")

    sections = inline = 0
    for rel in source_files(root):
        text = read_source(root, rel)
        if text is None:
            continue
        if rel.endswith(".md"):
            found, count = check_sections(options, text, rel)
            problems += found
            sections += count
        found, count = check_inline(options, text, rel)
        problems += found
        inline += count

    # An extractor that stops finding the doc sections must fail, not pass
    # on an empty set.
    if not sections:
        raise GateFailure("found no \"## --option\" section for any mode "
                          "option in the .md files")

    if problems:
        report(problems, sys.stderr)
        sys.exit(1)

    print(f"PASS: {name}: parser, help text, {sections} doc sections and "
          f"{inline} inline lists agree on {len(options)} mode options")


try:
    main()
except GateFailure as e:
    print(f"FAIL: {name}: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
