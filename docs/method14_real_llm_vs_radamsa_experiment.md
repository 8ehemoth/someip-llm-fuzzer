# Method 14 Real LLM-like vs Radamsa-like Experiment

## Purpose

This experiment compares Method 14 `changeDoorsState` candidates from two generation families under identical reset-before state validation:

- `llm_real`: source-informed, structure-aware deterministic generator.
- `radamsa_real`: deterministic mutation generator by default, with optional real Radamsa execution when explicitly requested.

The comparison target is Method 14 only. State is checked with Getter 8 `getDoorsOpeningStatusAttribute`.

## Example vs Real Candidate Sets

The earlier `llm_example` and `radamsa_example` CSVs were small pipeline sanity fixtures. They were useful for validating CSV loading, reset-before replay, and summary generation, but they are not a fair final comparison because:

- candidate counts differ,
- candidates are hand-picked examples,
- they are not generated from a larger strategy space,
- they do not enforce balanced source sizes.

The real candidate generator creates larger source-specific pools, removes duplicate payloads, and selects equal candidate counts for fair comparison.

## Why Balance Candidate Counts

LLM and Radamsa must be compared with equal opportunity. If one side has more payloads, it has more chances to discover a state-changing candidate.

The generator supports:

- `--count N`: requested candidate count per source.
- `--balance`: trim both sources to the same count.
- If either side has fewer than `N` unique payloads, the balanced CSV is trimmed to the minimum common count and a warning is printed.

## LLM-like Generation Strategy

The deterministic LLM-like generator encodes the public Method 14 structure:

- payload is treated as a four-byte `CarDoorsCommand`,
- each byte is a door command,
- `00` means no-op / unchanged,
- `01` means open,
- `02` means close/reset,
- `03` and `ff` are invalid/boundary command values.

It generates:

- all four-door combinations over `00,01,02,03,ff`,
- single-door open patterns,
- front-pair and rear-pair open patterns,
- open/close mixed semantic tuples,
- invalid/boundary command tuples,
- prefix/suffix padding,
- duplicated payloads,
- truncation/length variants.

## Radamsa-like Generation Strategy

By default, the generator does not invoke the Radamsa binary. It creates deterministic mutation-style payloads from seed payloads:

- seeds: `01010101`, `02020202`, `00000000`,
- bit flips,
- byte flips,
- byte insertion,
- byte deletion,
- truncation,
- duplication,
- deterministic random bytes,
- long zero/ff padding,
- seed concatenation,
- zero/ff boundary fills.

## Optional Real Radamsa

Real Radamsa execution is opt-in:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/generate_method14_real_candidates.py \
  --count 100 \
  --balance \
  --seed 42 \
  --use-radamsa \
  --radamsa-bin radamsa \
  --radamsa-seed-corpus path/to/seed_corpus \
  --radamsa-count 300
```

The default command does not run Radamsa.

## Reset-Before Evaluation

Every candidate replay must use the same sequence:

1. Send Method 14 reset payload `02020202`.
2. Call Getter 8 and expect reset payload `00000000`.
3. Send candidate Method 14 payload.
4. Call Getter 8 again.
5. Compute:
   - `state_changed`
   - `reset_equivalent`
   - `non_trivial_state_effect`

`normal_response` alone is not sufficient. A candidate is valuable only if it produces a non-trivial Getter 8 state effect.

## Commands

Generate balanced deterministic candidate CSVs:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/generate_method14_real_candidates.py \
  --count 100 \
  --balance \
  --seed 42
```

Dry-run the balanced candidate CSV:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/compare_method14_llm_radamsa.py \
  --balanced-candidates results/method14_candidates_balanced_<timestamp>.csv \
  --trial-count 10 \
  --dry-run
```

Execute the comparison with separate source CSVs:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/compare_method14_llm_radamsa.py \
  --llm-candidates results/method14_llm_candidates_real_<timestamp>.csv \
  --radamsa-candidates results/method14_radamsa_candidates_real_<timestamp>.csv \
  --trial-count 10 \
  --execute
```

Execute the comparison with the balanced CSV:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/compare_method14_llm_radamsa.py \
  --balanced-candidates results/method14_candidates_balanced_<timestamp>.csv \
  --trial-count 10 \
  --execute
```

## Output

Candidate generation writes:

```text
results/method14_llm_candidates_real_<timestamp>.csv
results/method14_radamsa_candidates_real_<timestamp>.csv
results/method14_candidates_balanced_<timestamp>.csv
```

Replay comparison writes:

```text
results/method14_llm_vs_radamsa_detail_<timestamp>.csv
results/method14_llm_vs_radamsa_summary_<timestamp>.csv
results/method14_llm_vs_radamsa_payload_summary_<timestamp>.csv
```

## Interpretation

Compare LLM and Radamsa in this order:

1. `reproducible_non_trivial_state_effect_count`
2. `non_trivial_state_effect_count`
3. `normal_response_count`
4. `unique_payload_count`
5. latency metrics

Do not decide the winner from `normal_response_count` alone. Method 14 has an explicit public state oracle, so the central metric is externally observable Getter 8 state change after reset.
