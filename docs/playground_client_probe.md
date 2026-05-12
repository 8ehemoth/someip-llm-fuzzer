# PlaygroundClientProbe

## Purpose

`PlaygroundClientProbe` is a separate CommonAPI client for focused Method 10, 12, and 14 baseline calls. It is added as a new file and executable so the original `src/PlaygroundClient.cpp` and its default behavior stay unchanged.

## Probe Sequence

The client waits for the proxy to become available, then runs:

1. Method 10 `setSeatHeatingStatusAttribute`
   - before: Getter 9 `getSeatHeatingStatusAttribute`
   - request: `std::vector<bool>{true,false,true,false,true,false,true}`
   - wire baseline expected from prior probes: `0000000701000100010001`
   - after: Getter 9

2. Method 12 `setSeatHeatingLevelAttribute`
   - before: Getter 11 `getSeatHeatingLevelAttribute`
   - request: `std::vector<uint8_t>{1,2,3,0,1,2,3}`
   - wire baseline expected from prior probes: `0000000701020300010203`
   - after: Getter 11

3. Method 14 `changeDoorsState`
   - before: Getter 8 `getDoorsOpeningStatusAttribute`
   - request: `CarDoorsCommand(OPEN_DOOR, OPEN_DOOR, OPEN_DOOR, OPEN_DOOR)`
   - wire baseline expected from prior probes: `01010101`
   - after: Getter 8

Each CommonAPI call prints `CommonAPI::CallStatus` and human-readable before/after values.

## Build

From the service project:

```bash
cd /home/client/someip-llm-fuzzer/test-someip-service
cmake -S . -B build
cmake --build build --target PlaygroundClientProbe
```

If you use the existing `build-codex` directory:

```bash
cd /home/client/someip-llm-fuzzer/test-someip-service
cmake --build build-codex --target PlaygroundClientProbe
```

## Run

Start `PlaygroundService` separately, then run:

```bash
cd /home/client/someip-llm-fuzzer/test-someip-service
VSOMEIP_CONFIGURATION=vsomeip-client-remote.json \
VSOMEIP_APPLICATION_NAME=graphql \
LD_LIBRARY_PATH=/home/client/usr/lib:/home/client/someip-llm-fuzzer/test-someip-service/commonapi-wrappers/playground/lib \
./build/PlaygroundClientProbe
```

Adjust the build directory if needed, for example `./build-codex/PlaygroundClientProbe`.

## Pcap Check

After capturing traffic separately, filter Method 10, 12, and 14:

```bash
tshark -r <pcap> \
  -d udp.port==31000,someip \
  -Y "someip.methodid == 0x0000000a || someip.methodid == 0x0000000c || someip.methodid == 0x0000000e" \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e someip.serviceid \
  -e someip.methodid \
  -e someip.messagetype \
  -e someip.returncode \
  -e data \
  -E header=y \
  -E separator=, \
  -E quote=d
```
