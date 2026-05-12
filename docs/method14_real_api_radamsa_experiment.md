# Method 14 Real API vs Radamsa Experiment

## Existing planner reuse

The repository already had a root-level `llm_planner.py`. It was reused instead of adding `generate_method14_openai_candidates.py`.

`llm_planner.py` already provided:

- OpenAI Responses API integration through `OPENAI_API_KEY`.
- Optional model selection through `--model` or `OPENAI_MODEL`.
- Local heuristic planning when an API call is not needed.
- JSON plan and summary output under `results/`.
- Payload case normalization for even-length hex payloads.

The existing planner produced JSON plans for previous fuzzing CSVs, not Method 14 candidate CSVs. It was extended with a Method 14 candidate mode while keeping the old `--input`/`--mode` behavior compatible.

## Method 14 LLM API candidate generation

Dry-run is the default and does not call OpenAI:

```bash
../miniconda3/envs/someipfuzz/bin/python llm_planner.py \
  --target-method 14 \
  --method-name changeDoorsState \
  --paired-getter 8 \
  --count 100 \
  --batch-size 20 \
  --model <model_name> \
  --dry-run \
  --output-prefix results/method14_openai_candidates
```

Real API generation is opt-in:

```bash
OPENAI_API_KEY=... ../miniconda3/envs/someipfuzz/bin/python llm_planner.py \
  --target-method 14 \
  --method-name changeDoorsState \
  --paired-getter 8 \
  --count 100 \
  --batch-size 20 \
  --model <model_name> \
  --use-openai-api \
  --output-prefix results/method14_openai_candidates
```

The Method 14 context is:

- Method ID: `14`
- Method name: `changeDoorsState`
- Paired getter: `8`
- Payload assumption: 4-byte `DoorCommand` array
- `00`: no-op or unchanged
- `01`: open
- `02`: close/reset
- `03`, `ff`: invalid or boundary candidates
- reset payload: `02020202`
- reset Getter 8 expected payload: `00000000`
- baseline open payload: `01010101`

Generated candidate CSVs use `payload_source=llm_api` and include the compare-compatible columns:

```text
payload_source,payload_label,method_id,payload_hex,payload_len
```

They also include Method 14 metadata such as `method_name`, `paired_getter`, `batch_index`, and `generation_strategy`.

## Real Radamsa candidate generation

The existing `scripts/generate_method14_real_candidates.py` already supported opt-in Radamsa execution through `--use-radamsa`. That path now stores real binary output with `payload_source=radamsa_bin`.

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/generate_method14_real_candidates.py \
  --count 100 \
  --balance \
  --use-radamsa \
  --radamsa-bin radamsa \
  --radamsa-seed-corpus path/to/seed_corpus \
  --radamsa-count 300
```

Without `--use-radamsa`, the script uses deterministic Radamsa-like mutation and does not run the Radamsa binary.

## Balancing

Use `scripts/balance_method14_candidates.py` to trim LLM and Radamsa candidates to the same count. It accepts either separate CSVs or one combined CSV.

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/balance_method14_candidates.py \
  --llm-candidates results/method14_openai_candidates_<timestamp>.csv \
  --radamsa-candidates results/method14_radamsa_candidates_real_<timestamp>.csv \
  --count 100 \
  --output-prefix results/method14_candidates_balanced
```

The output remains compatible with `scripts/compare_method14_llm_radamsa.py`.

## Replay comparison

Dry-run the replay plan:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/compare_method14_llm_radamsa.py \
  --balanced-candidates results/method14_candidates_balanced_<timestamp>.csv \
  --trial-count 10 \
  --dry-run
```

Actual replay is intentionally manual:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/compare_method14_llm_radamsa.py \
  --balanced-candidates results/method14_candidates_balanced_<timestamp>.csv \
  --trial-count 10 \
  --execute
```

## normal_response vs non_trivial_state_effect

`normal_response` means Method 14 returned a protocol-level normal response for the candidate payload. It does not prove that the door state changed.

`non_trivial_state_effect` is stricter. The comparison script resets Method 14 with `02020202`, confirms Getter 8 is `00000000`, sends the candidate, then calls Getter 8 again. A candidate is non-trivial only when it receives a normal response and changes Getter 8 away from the reset-equivalent state.

For Method 14, `non_trivial_state_effect` is the primary signal. `normal_response` is useful as protocol validity evidence, but it is not enough to claim a meaningful state effect.
