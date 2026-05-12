# All-Defined Methods One-Shot Capture

## Purpose

This is a source-informed smoke probe, not fuzzing. It sends each request-capable method ID defined by the service/FDEP once, records the script-level response CSV, and optionally lets the operator capture the traffic as a pcap in a separate terminal.

Excluded IDs:

- Event/notifier IDs `0x8001` through `0x800a` are not request-probed.

Probe sequence:

| sequence | method ID | payload |
|---:|---:|---|
| 1 | `1` | empty |
| 2 | `2` | empty |
| 3 | `3` | empty |
| 4 | `4` | empty |
| 5 | `5` | empty |
| 6 | `6` | empty |
| 7 | `7` | empty |
| 8 | `8` | empty |
| 9 | `9` | empty |
| 10 | `10` | `0000000701000100010001` |
| 11 | `11` | empty |
| 12 | `12` | `0000000701020300010203` |
| 13 | `13` | empty |
| 14 | `14` | `01010101` |

## Start Server

In the service workspace, start the SOME/IP service with the same vsomeip configuration used for the previous baseline probes.

Example:

```bash
cd /home/client/test-someip-service
VSOMEIP_CONFIGURATION=vsomeip-server-remote.json \
LD_LIBRARY_PATH=/home/client/usr/lib:/home/client/test-someip-service/commonapi-wrappers/playground/lib \
./build-codex/PlaygroundService
```

Adjust the binary path if your local build directory differs.

## Start Pcap Capture

Run tcpdump manually in a separate terminal before executing the probe. The script does not start tcpdump because sudo may be required.

Example:

```bash
cd /home/client/someip-llm-fuzzer
sudo tcpdump -i any -s 0 -w "results/all_defined_methods_once_$(date +%Y%m%d_%H%M%S).pcapng" "udp port 31000"
```

If the service uses a different UDP port, change `31000` to the configured SOME/IP port.

## Run One-Shot Probe

From this repository:

```bash
cd /home/client/someip-llm-fuzzer
../miniconda3/envs/someipfuzz/bin/python scripts/probe_all_defined_methods.py --execute-all-defined-once
```

The script writes:

```text
results/all_defined_methods_once_<timestamp>.csv
```

CSV columns include:

- `timestamp`
- `sequence_index`
- `method_id`
- `hex_method_id`
- `method_name`
- `role`
- `payload_hex`
- `payload_len`
- `response_received`
- `msg_type`
- `retcode`
- `verdict`
- `latency_ms`
- `response_payload_hex`
- `error`

## Stop Pcap Capture

Return to the tcpdump terminal and press `Ctrl-C`. Confirm that tcpdump reports packets captured and that the pcap file exists under `results/`.

## Interpretation

Expected smoke-probe behavior:

- Request method IDs `1..14` appear exactly once in the script CSV, in sequence order.
- Event/notifier IDs `0x8001..0x800a` do not appear as requests.
- A healthy target generally returns `response_received=True`, `msg_type=0x80`, `retcode=0x00`, and `verdict=normal_response` for accepted baseline payloads.
- Getter methods should return their current state in `response_payload_hex`.
- Method 13 and Method 14 have no output fields, so their response payload may be empty even when the response is normal.
- Any timeout, malformed response, or nonzero retcode should be treated as a smoke-probe finding and checked against the pcap.

This experiment is not a state-effect proof for every method. Method 14 state-effect validation is handled separately by `scripts/probe_method14_state.py`.
