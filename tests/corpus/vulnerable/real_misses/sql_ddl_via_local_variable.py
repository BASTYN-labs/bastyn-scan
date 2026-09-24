"""Known false positive: BAS-LLM10-018 fires on a genuine schema-identifier
interpolation split across a local variable, the same DDL shape Finding 2
of the 2026-09-24 final review fixed for BAS-LLM10-017's same-node case.

BAS-LLM10-017 sees the whole f-string inline at the execute() call site, so
its metavariable_not_matches regex can inspect $ARG's captured text
directly. BAS-LLM10-018 instead matches the f-string's inner text as
$$$FSTR, a variadic (`$$$`-prefixed) capture -- because its `any:` patterns
span the assignment statement and the execute() call as one multi-line
pattern (`$SQL = f"$$$FSTR"`). A `metavariable_not_matches: {FSTR: ...}`
clause mirroring BAS-LLM10-017's fix was tried and empirically confirmed
(built and run against this exact shape) to silently never exclude
anything: ast_grep_core's MetaVarEnv stores a `$$$`-bound capture in
`multi_matched`, but this engine's metavariable_not_matches check only
ever calls `env.get_match()`, which reads `single_matched` -- the same
limitation already documented for metavariable_matches against
vulnerable/real_misses/three_interpolation_override.py's $$$OVERRIDE
capture. Recorded here as a known_false_positive rather than forcing a
fix the engine cannot currently express.
"""


def ensure_column(conn, table: str, column: str) -> None:
    """known_false_positive (LLM10): table and column are SQL identifiers
    in a schema migration, not query values -- DB-API has no way to bind
    an identifier as a parameter, so interpolating one here is the only
    correct way to write this. BAS-LLM10-018 has no DDL-keyword exclusion
    that can see through its own $$$FSTR variadic capture, so it fires
    anyway."""
    sql = f"ALTER TABLE {table} ADD COLUMN {column} TEXT"
    conn.execute(sql)
