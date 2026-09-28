#!/usr/bin/env python3
"""Catch the two classes of error a reviewer cannot see without a compiler.

Both are mechanical, and both have shipped from this tree before:

  1. a struct literal that does not name every field of its struct, which the
     compiler reports as E0063 at the literal, hundreds of lines away from the
     field that was added, and only one place at a time;
  2. two modules re-exporting the same name through `pub use module::*;`, which
     the compiler reports as an ambiguous glob rather than as the duplicate name
     that caused it.

Neither needs a Rust toolchain, so both are checked here instead. Struct fields
come from the same source the compiler reads.

A checker that cries wolf is worse than no checker, so anything this cannot
judge with certainty is left alone rather than guessed at: a struct whose name
is declared with two different shapes, a literal that fills the rest of its
fields from a base with `..`, a type from outside this tree, a function body, an
`impl` block, a type definition, and a named enum variant all share enough
syntax with a literal that reporting against one of them teaches a reader to
ignore the report.

Run it with the same file list the build uses:

    python3 scripts/check-struct-literals.py $(git ls-files '*.rs')
"""
import re
import sys
from collections import defaultdict

# A struct and its public fields, as declared.
STRUCT = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?struct[ \t]+([A-Z][A-Za-z0-9_]*)[ \t]*\{", re.M
)
DECL_FIELD = re.compile(r"^[ \t]*pub(?:\([^)]*\))?[ \t]+([a-z_][A-Za-z0-9_]*)[ \t]*:(?!:)", re.M)

# A `Name {` that may open a literal. A `::` in front is a path rather than a
# match arm, so `super::thread::Opts {` is a literal and `Some(Bar {` is not.
LITERAL_HEAD = re.compile(r"(?:^|[^\w])([A-Z][A-Za-z0-9_]*)[ \t\n]*\{")

# A field as written into a literal: no visibility, one space or none.
LITERAL_FIELD = re.compile(r"^[ \t]*([a-z_][A-Za-z0-9_]*)[ \t]*:(?!:)", re.M)
# `field,` shorthand carries no colon but still names the field.
SHORTHAND = re.compile(r"(?:^|,)[ \t\n]*([a-z_][A-Za-z0-9_]*)[ \t\n]*(?=,|$)")

GLOB = re.compile(r"^[ \t]*pub[ \t]+use[ \t]+([a-z_][A-Za-z0-9_]*)[ \t]*::[ \t]*\*[ \t]*;", re.M)
PUB_FN = re.compile(
    r"^[ \t]*pub(?:\([^)]*\))?[ \t]+(?:const[ \t]+)?(?:async[ \t]+)?fn[ \t]+"
    r"([a-z_][A-Za-z0-9_]*)",
    re.M,
)
PUB_STRUCT = re.compile(
    r"^[ \t]*pub(?:\([^)]*\))?[ \t]+(?:const[ \t]+)?struct[ \t]+([A-Z][A-Za-z0-9_]*)", re.M
)
ENUM = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?enum[ \t]+([A-Z][A-Za-z0-9_]*)[ \t]*\{", re.M
)
VARIANT = re.compile(r"^ {4}([A-Z][A-Za-z0-9_]*)[ \t]*(?:,|\(|=|\{|$)", re.M)

# `Name {` also opens a function body, an `impl` block, a type definition, and a
# named enum variant. None of those is a literal, so the token in front of the
# name has to agree before the braces are read as one.
NOT_A_LITERAL = frozenset(
    ("impl", "struct", "enum", "union", "trait", "fn", "type", "mod", "use", "const", "let", "->")
)
BEFORE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*|->)[ \t]*$")
# A path in front of the name is not a token, so `-> crate::db::NewPost {` is
# still a return type and `let x = crate::db::NewPost {` is still a literal.
PATH_TAIL = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]*[ \t]*::)+[ \t]*$")
LOOKBEHIND = 256

# How many braces deep a field list may nest. A literal that closes deeper than
# this is a match pattern reaching past its own arm, not something to judge.
MAX_LITERAL_DEPTH = 2


def strip_noise(text):
    """Blank out comments and string literals, keeping every byte offset."""
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        if text[i:i + 2] == '//':
            while i < n and text[i] != '\n':
                out[i] = ' '
                i += 1
            continue
        if text[i:i + 2] == '/*':
            depth = 1
            out[i] = out[i + 1] = ' '
            i += 2
            while i < n and depth:
                if text[i:i + 2] == '/*':
                    depth += 1
                    out[i] = out[i + 1] = ' '
                    i += 2
                elif text[i:i + 2] == '*/':
                    depth -= 1
                    out[i] = out[i + 1] = ' '
                    i += 2
                else:
                    if text[i] != '\n':
                        out[i] = ' '
                    i += 1
            continue
        m = re.match(r'r(#*)"', text[i:])
        if m:
            close = '"' + m.group(1)
            j = text.find(close, i + m.end())
            j = n if j < 0 else j + len(close)
            for k in range(i, j):
                if text[k] != '\n':
                    out[k] = ' '
            i = j
            continue
        if text[i] == '"':
            j = i + 1
            while j < n:
                if text[j] == '\\':
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, j):
                if text[k] != '\n':
                    out[k] = ' '
            i = j
            continue
        i += 1
    return ''.join(out)


def body_end(text, open_index):
    """Index of the brace closing the one at open_index, or -1 if unbalanced.

    Returns as soon as the closing brace of the literal's own nesting level is
    reached, so a runaway pattern cannot walk the rest of the file.
    """
    depth = 0
    for i in range(open_index, len(text)):
        ch = text[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return i
            if depth > MAX_LITERAL_DEPTH:
                return -1
    return -1


def looks_like_literal(text, name_start):
    """Whether the `Name {` at name_start opens a literal rather than a body."""
    window = text[max(0, name_start - LOOKBEHIND):name_start]
    m = BEFORE.search(PATH_TAIL.sub('', window))
    if m is None:
        return True
    return m.group(1) not in NOT_A_LITERAL


def read_structs(texts):
    """Map each struct this tree declares, unambiguously, to its public fields.

    A name declared with two different shapes cannot be judged from the name
    alone, so it is dropped rather than guessed at: two modules may each have
    their own `VoteForm`, and reporting against the wrong one teaches a reader
    to ignore the report.
    """
    seen = defaultdict(set)
    for text in texts.values():
        for m in STRUCT.finditer(text):
            end = body_end(text, m.end() - 1)
            if end < 0:
                continue
            seen[m.group(1)].add(frozenset(DECL_FIELD.findall(text[m.end():end])))
    return {name: next(iter(shapes)) for name, shapes in seen.items() if len(shapes) == 1}


def read_variants(texts):
    """Every enum variant name, which shares a literal's syntax and is not one."""
    variants = set()
    for text in texts.values():
        for m in ENUM.finditer(text):
            end = body_end(text, m.end() - 1)
            if end < 0:
                continue
            variants |= set(VARIANT.findall(text[m.end():end]))
    return variants


def find_missing_fields(paths, texts, structs, variants):
    problems = []
    for path in paths:
        text = texts[path]
        for m in LITERAL_HEAD.finditer(text):
            name = m.group(1)
            if name in variants or not looks_like_literal(text, m.start(1)):
                continue
            fields = structs.get(name)
            if not fields:
                continue
            end = body_end(text, m.end() - 1)
            if end < 0:
                continue
            body = text[m.end():end]
            if '..' in body:
                # Functional update syntax: the rest comes from the base, so
                # this literal is not naming every field by design.
                continue
            given = set(LITERAL_FIELD.findall(body)) | set(SHORTHAND.findall(body))
            if not given:
                continue
            missing = fields - given
            if missing:
                line = text[:m.start(1)].count('\n') + 1
                problems.append('%s:%d: %s literal is missing %s'
                                % (path, line, name, ', '.join(sorted(missing))))
    return problems


def read_exports(texts):
    """Map each file to the public item names it declares, which is what a glob
    re-exports. A private item is not re-exported and cannot collide."""
    exports = {}
    for path, text in texts.items():
        names = set(PUB_FN.findall(text)) | set(PUB_STRUCT.findall(text))
        for m in ENUM.finditer(text):
            end = body_end(text, m.end() - 1)
            if end < 0:
                continue
            names.add(m.group(1))
            names |= set(VARIANT.findall(text[m.end():end]))
        exports[path] = names
    return exports


def module_path(module, from_path, by_stem):
    """Map a module name to the file in this tree that declares it."""
    stem = from_path.split('/')[-1]
    if stem == 'mod.rs':
        if module == from_path.split('/')[-2]:
            return from_path
    elif module == stem[:-3]:
        return from_path
    return by_stem.get(module)


def find_glob_collisions(paths, texts, by_stem):
    exports = read_exports(texts)
    problems = []
    for path in paths:
        text = texts[path]
        globs = [(m.group(1), m.start()) for m in GLOB.finditer(text)]
        for a in range(len(globs)):
            for b in range(a + 1, len(globs)):
                (name_a, pos_a), (name_b, _) = globs[a], globs[b]
                if name_a == name_b:
                    continue
                path_a = module_path(name_a, path, by_stem)
                path_b = module_path(name_b, path, by_stem)
                if not path_a or not path_b:
                    continue
                for name in sorted(exports[path_a] & exports[path_b]):
                    line = text[:pos_a].count('\n') + 1
                    problems.append('%s:%d: `%s::*` and `%s::*` both export `%s`'
                                    % (path, line, name_a, name_b, name))
    return problems


def main(argv):
    paths = sorted(p for p in argv if p.endswith('.rs'))
    texts = {p: strip_noise(open(p, encoding='utf-8').read()) for p in paths}
    by_stem = {}
    for p in paths:
        by_stem.setdefault(p.split('/')[-1][:-3], p)
    structs = read_structs(texts)
    problems = find_missing_fields(paths, texts, structs, read_variants(texts))
    problems += find_glob_collisions(paths, texts, by_stem)
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
