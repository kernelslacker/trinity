# Warm-start options

Companion to `main/params/help.c` and the persisted-corpus loaders.
Trinity keeps four independent on-disk warm-start caches; each
`--no-*-warm-start` skips exactly one, and `--hermetic` is the
umbrella that implies all four.  The `--help` output carries only a
one-line contract per option; the rationale for the umbrella and the
back-compat aliasing lives here.

## --hermetic

Run with no persisted fuzzing state.  Implies:

- `--no-minicorpus-warm-start`
- `--no-kcov-warm-start`
- `--no-cmp-hints-warm-start`
- `--no-chain-warm-start`

Use for bisection, A/B comparisons, and clean-baseline repros where
prior-run cache state would confound the measurement.

## The four warm-start caches

Each of the four caches has an independent `--no-*-warm-start` opt-out
so a targeted run can drop exactly one cache without losing the other
three:

- `--no-minicorpus-warm-start`: persisted minicorpus of accepted
  syscall arg tuples.  Dropping this forces the corpus admission
  path to start from an empty ring.
- `--no-kcov-warm-start`: persisted kcov edge bitmap and per-syscall
  edge-total prior.  Dropping this forces the coverage-frontier
  picker's inverse-productivity signal to start with no prior.
- `--no-cmp-hints-warm-start`: persisted kcov CMP-hint pool.
  Dropping this forces RedQueen / cmp_hints_try_get_ex to serve only
  values learned in this run.
- `--no-chain-warm-start`: persisted sequence chain corpus.
  Dropping this forces the chain replayer to start with no cached
  sequences.

Prefer `--hermetic` when what you want is a clean baseline; reach for
an individual `--no-*-warm-start` only when the goal is to isolate a
single cache's contribution.

## --no-warm-start (back-compat alias)

Back-compat alias for `--no-minicorpus-warm-start`.  Only disables
the minicorpus cache -- the other three warm-start caches still load.
Prefer `--hermetic` for a full clean baseline; prefer
`--no-minicorpus-warm-start` when the intent is to name the cache
explicitly.

## --warm-start-path

Override the on-disk minicorpus path.  Default:
`$XDG_CACHE_HOME/trinity/corpus/<arch>`.  Applies to the minicorpus
cache only; the other three warm-start caches have their own paths
(persisted with the minicorpus tree).
