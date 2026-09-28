#!/usr/bin/env python3
"""Catch the errors a reviewer cannot see without a compiler, and that a
compiler reports one at a time rather than all at once.

Four checks, all mechanical, all of which have shipped from this tree:

  1. a struct literal that does not name every field of its struct, which the
     compiler reports as E0063 at the literal, hundreds of lines away from the
     field that was added;
  2. two modules re-exporting the same name through `pub use module::*;`, which
     the compiler reports as an ambiguous glob rather than as the duplicate name
     that caused it;
  3. a path qualified further than it needs to be, which the workspace denies as
     `unused_qualifications` -- correct in a test module that has not imported
     the module, and an error in the one that has.

Rust stops type-checking a crate partway through, so a build can report one of
the first kind and say nothing about the rest until that one is fixed. These run
first, in a couple of seconds, with no toolchain.

A checker that cries wolf is worse than no checker, so anything that cannot be
judged with certainty is left alone rather than guessed at: a struct whose name
is declared with two shapes, a literal that fills the rest of its fields from a
base with `..`, a type from outside this tree, a function body, an `impl` block,
a type definition, and a named enum variant all share enough syntax with a
literal that reporting against one of them teaches a reader to ignore the
report.

A fourth check was tried and dropped: a call passing the wrong number of
arguments. A tree that imports `post` and `get` from a router, calls `metadata`
on a path, and keeps its SQL in raw strings gave three hundred false positives
against one true one, and no amount of narrowing made it trustworthy.

Run it with the same file list the build uses:

    python3 scripts/check-rust-shape.py $(git ls-files '*.rs')
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

# `name(` is a call rather than the start of a definition when the token in
# front of it is not one of the keywords that introduce a definition.
DEFINITION = frozenset(
    ("fn", "struct", "enum", "impl", "trait", "mod", "use", "const", "static", "type",
     "let", "as", "in", "unsafe")
)


def looks_like_call(text, name_start):
    """Whether the `name(` at name_start is a call rather than a definition."""
    window = text[max(0, name_start - LOOKBEHIND):name_start]
    m = BEFORE.search(PATH_TAIL.sub('', window))
    if m is None:
        return True
    return m.group(1) not in DEFINITION


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

# A module named in a qualified path, and the `use` that would make it shorter.
# The captured group ends in `::`, so it always covers the whole path: `crate::`
# in a `use` statement and `crate::db::` in a signature are the same shape, and
# the `use` one is excluded by position rather than by pattern.
QUALIFIED = re.compile(
    r"(?<![A-Za-z0-9_])(?:crate|self|super)::((?:[a-z_][A-Za-z0-9_]*::)+)"
)
MODULE_HEAD = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?mod[ \t]+([a-z_][A-Za-z0-9_]*)[ \t]*\{", re.M)
USE_STMT = re.compile(r"^[ \t]*(?:pub(?:[ \t]+(?:crate|super|self|in))?[ \t]+)?use[ \t]+", re.M)

# How many braces deep a field list may nest. A literal that closes deeper than
# this is a match pattern reaching past its own arm, not something to judge.
MAX_LITERAL_DEPTH = 2


def strip_noise(text):
    """Blank out comments and string literals, keeping every byte offset.

    An offset found in the blanked text is the same offset in the file as it
    was written, which is what turns a match into a line number. A `Name {`
    inside a string cannot pose as a struct literal, which is the reason for
    blanking the strings rather than just the comments.
    """
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


def block_end(text, open_index, max_depth=None):
    """Index of the brace closing the one at open_index, or -1 if unbalanced.

    `max_depth` stops the walk early, so a literal whose braces were misread
    cannot walk the rest of the file looking for a close that belongs to
    something else.
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
            if max_depth is not None and depth > max_depth:
                return -1
    return -1


def body_end(text, open_index):
    """The closing brace of a struct, enum, or literal body."""
    return block_end(text, open_index, MAX_LITERAL_DEPTH)


def looks_like_literal(text, name_start):
    """Whether the `Name {` at name_start opens a literal rather than a body."""
    window = text[max(0, name_start - LOOKBEHIND):name_start]
    m = BEFORE.search(PATH_TAIL.sub('', window))
    if m is None:
        return True
    return m.group(1) not in NOT_A_LITERAL


# --- module scope -----------------------------------------------------------
#
# A child module does not inherit its parent's imports: it names them
# `super::db`, or pulls them in with `use super::*`. Treating a file's imports
# as if they reached every module in it reports `crate::db::` in a test module
# that has not imported `db` as an error, which it is not.

def module_regions(text):
    """Every `mod name {` body in a file, as (name, start, end) in order."""
    regions = []
    for m in MODULE_HEAD.finditer(text):
        end = block_end(text, m.end() - 1)
        if end > 0:
            regions.append((m.group(1), m.end(), end))
    return regions


def chain_at(regions, offset):
    """The chain of enclosing module names at an offset, outermost first."""
    chain = []
    for name, start, end in regions:
        if start <= offset < end:
            chain.append(name)
    return tuple(chain)


def bound_names(statement):
    """The names one `use` statement binds, or None if it is a glob.

    `use a::b;` binds `b`, and `use a::{b, c};` binds `b` and `c` but not `a`.
    A glob imports everything a module holds, which is not knowable from one
    file, so it is reported as None and the caller falls back to a glob import
    of the parent chain, which is the shape a test module actually uses.
    """
    statement = statement.strip()
    if statement.endswith('::*') or statement.endswith('::*;'):
        return None
    head, brace, rest = statement.partition('{')
    names = set()
    if brace:
        for piece in rest.rstrip('}').split(','):
            leaf = re.findall(r'([A-Za-z_][A-Za-z0-9_]*)', piece)
            if leaf:
                names.add(leaf[-1])
    else:
        head = head.rstrip(';')
        # An `as` renames the binding to the alias, not to the last segment.
        if ' as ' in head:
            head = head.rsplit(' as ', 1)[1]
        leaves = re.findall(r'([A-Za-z_][A-Za-z0-9_]*)', head)
        if len(leaves) >= 2:
            names.add(leaves[-1])
    return names


def is_super_glob(statement):
    return bool(re.match(r'^\s*(?:pub[^\s]*[ \t]+)?use[ \t]+super[ \t]*::[ \t]*\*\s*;?\s*$',
                         statement))


def read_bindings(paths, texts):
    """Map each (file, module chain) to the names imported into it.

    The file is part of the key on purpose. Imports are private to their
    module, so a name one file brings in says nothing about any other, and a
    single shared table would report every `crate::db::` in the crate the
    moment one file somewhere imported `db`.
    """
    bindings = defaultdict(set)
    for path in paths:
        text = texts[path]
        regions = module_regions(text)
        for m in USE_STMT.finditer(text):
            i = m.end()
            j = i
            while j < len(text) and text[j] != ';':
                j += 1
            statement = text[i:j]
            chain = chain_at(regions, m.start())
            if is_super_glob(statement):
                # A test module reaching for everything its parent imported is
                # the common shape, and it is the one that makes a parent's
                # names visible again.
                if len(chain) > 1:
                    bindings[(path, chain)] |= bindings[(path, chain[:-1])]
                continue
            names = bound_names(statement)
            if names:
                bindings[(path, chain)] |= names
    return bindings


def in_scope(bindings, path, chain, name):
    """Whether `name` is importable in a file's module chain."""
    return name in bindings.get((path, chain), ())


# --- checks -----------------------------------------------------------------

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


def find_over_qualified(paths, texts, bindings):
    """Report a path that is longer than it has to be.

    A child module does not inherit its parent's imports, so the same path is
    correct in one module and an error in another. Each use is therefore judged
    against the chain it appears in.
    """
    problems = []
    for path in paths:
        text = texts[path]
        regions = module_regions(text)
        # A `use` statement is the one place a path has to be written out in
        # full, because it is the statement that brings the name into scope.
        uses = []
        for um in USE_STMT.finditer(text):
            end = text.find(';', um.end())
            uses.append((um.start(), len(text) if end < 0 else end))
        for m in QUALIFIED.finditer(text):
            segments = m.group(1).split('::')
            module = segments[0]
            if not module or module in ('crate', 'self', 'super'):
                continue
            if any(start <= m.start() <= stop for start, stop in uses):
                continue
            chain = chain_at(regions, m.start())
            if in_scope(bindings, path, chain, module):
                line = text[:m.start()].count('\n') + 1
                problems.append('%s:%d: `%s` is already imported here, so the '
                                'path can be shortened' % (path, line, module))
    return problems


def main(argv):
    paths = sorted(p for p in argv if p.endswith('.rs'))
    texts = {p: strip_noise(open(p, encoding='utf-8').read()) for p in paths}
    by_stem = {}
    for p in paths:
        by_stem.setdefault(p.split('/')[-1][:-3], p)

    problems = find_missing_fields(paths, texts, read_structs(texts), read_variants(texts))
    problems += find_glob_collisions(paths, texts, by_stem)
    problems += find_over_qualified(paths, texts, read_bindings(paths, texts))
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
