# Valid SOME/IP IDs in test-someip-service

## Scope

This note summarizes the public SOME/IP IDs exposed by `test-someip-service`.
It is based on:

- `franca/org/genivi/vehicle/playground.fdepl`
- `franca/org/genivi/vehicle/playground.fidl`
- `franca/org/genivi/vehicle/playgroundTypes.fidl`
- `src/PlaygroundStubImpl.cpp`
- `src/mock/MockedAttributes.cpp`

No fuzzer source or server source was modified.

## Service ID

| field | decimal | hex |
|---|---:|---:|
| `SomeIpServiceID` | 65344 | `0xff40` |

Source: `franca/org/genivi/vehicle/playground.fdepl`

## Valid ID Table

| id | hex id | name | kind | related type | source file | actual state-change implementation |
|---:|---:|---|---|---|---|---|
| 1 | `0x0001` | `consumption` | getter | `Float` | `playground.fdepl`, `playground.fidl` | Read-only attribute initialized in `PlaygroundStubImpl::initializeAttributes`; no custom mutation path found in inspected files |
| 2 | `0x0002` | `capacity` | getter | `UInt8` | `playground.fdepl`, `playground.fidl` | Read-only attribute initialized in `PlaygroundStubImpl::initializeAttributes`; no custom mutation path found in inspected files |
| 3 | `0x0003` | `volume` | getter | `Float` | `playground.fdepl`, `playground.fidl` | Attribute initialized; `updateTankVolume()` can update it, but this updater is not shown as a public SOME/IP method in inspected files |
| 4 | `0x0004` | `engineSpeed` | getter | `UInt16` | `playground.fdepl`, `playground.fidl` | Read-only attribute initialized in `PlaygroundStubImpl::initializeAttributes`; no custom mutation path found in inspected files |
| 5 | `0x0005` | `currentGear` | getter | `PlaygroundTypes.Gear` | `playground.fdepl`, `playground.fidl`, `playgroundTypes.fidl` | Read-only attribute initialized in `PlaygroundStubImpl::initializeAttributes`; no custom mutation path found in inspected files |
| 6 | `0x0006` | `isReverseGearOn` | getter | `Boolean` | `playground.fdepl`, `playground.fidl` | Read-only attribute initialized in `PlaygroundStubImpl::initializeAttributes`; no custom mutation path found in inspected files |
| 7 | `0x0007` | `drivePowerTransmission` | getter | `PlaygroundTypes.DriveType` | `playground.fdepl`, `playground.fidl`, `playgroundTypes.fidl` | Read-only attribute initialized in `PlaygroundStubImpl::initializeAttributes`; no custom mutation path found in inspected files |
| 8 | `0x0008` | `doorsOpeningStatus` | getter | `PlaygroundTypes.DoorsStatus` | `playground.fdepl`, `playground.fidl`, `playgroundTypes.fidl` | Yes, observable target for method 14: `changeDoorsState()` calls `setDoorsOpeningStatusAttribute(...)` |
| 9 | `0x0009` | `seatHeatingStatus` | getter | `Boolean[]` | `playground.fdepl`, `playground.fidl` | Attribute initialized; custom setter implementation not present in `PlaygroundStubImpl.cpp`; generated/default setter behavior must be validated by black-box test |
| 10 | `0x000a` | `seatHeatingStatus` | setter | `Boolean[]` | `playground.fdepl`, `playground.fidl` | ID-level valid setter. Payload type correctness and observable state effect require separate black-box validation |
| 11 | `0x000b` | `seatHeatingLevel` | getter | `UInt8[]` | `playground.fdepl`, `playground.fidl` | Attribute initialized; custom setter implementation not present in `PlaygroundStubImpl.cpp`; generated/default setter behavior must be validated by black-box test |
| 12 | `0x000c` | `seatHeatingLevel` | setter | `UInt8[]` | `playground.fdepl`, `playground.fidl` | ID-level valid setter. Payload type correctness and observable state effect require separate black-box validation |
| 13 | `0x000d` | `initTirePressureCalibration` | method | no input / no output | `playground.fdepl`, `playground.fidl` | No custom implementation found in `PlaygroundStubImpl.cpp` among inspected files |
| 14 | `0x000e` | `changeDoorsState` | method | input `PlaygroundTypes.CarDoorsCommand` | `playground.fdepl`, `playground.fidl`, `playgroundTypes.fidl`, `PlaygroundStubImpl.cpp` | Yes. `changeDoorsState()` computes next door states and calls `setDoorsOpeningStatusAttribute(...)`; getter 8 can verify state change |
| 32769 | `0x8001` | `consumption` notifier | event | `Float` | `playground.fdepl`, `playground.fidl` | Attribute notifier ID declared; no direct fire path found in inspected implementation |
| 32770 | `0x8002` | `engineSpeed` notifier | event | `UInt16` | `playground.fdepl`, `playground.fidl` | Attribute notifier ID declared; no direct fire path found in inspected implementation |
| 32771 | `0x8003` | `currentGear` notifier | event | `PlaygroundTypes.Gear` | `playground.fdepl`, `playground.fidl`, `playgroundTypes.fidl` | Attribute notifier ID declared; no direct fire path found in inspected implementation |
| 32772 | `0x8004` | `isReverseGearOn` notifier | event | `Boolean` | `playground.fdepl`, `playground.fidl` | Attribute notifier ID declared; no direct fire path found in inspected implementation |
| 32773 | `0x8005` | `drivePowerTransmission` notifier | event | `PlaygroundTypes.DriveType` | `playground.fdepl`, `playground.fidl`, `playgroundTypes.fidl` | Attribute notifier ID declared; no direct fire path found in inspected implementation |
| 32774 | `0x8006` | `doorsOpeningStatus` notifier | event | `PlaygroundTypes.DoorsStatus` | `playground.fdepl`, `playground.fidl`, `playgroundTypes.fidl` | May be emitted when `doorsOpeningStatus` changes through method 14/default attribute machinery; verify externally if needed |
| 32775 | `0x8007` | `seatHeatingStatus` notifier | event | `Boolean[]` | `playground.fdepl`, `playground.fidl` | Attribute notifier ID declared; custom fire path not found in inspected implementation |
| 32776 | `0x8008` | `seatHeatingLevel` notifier | event | `UInt8[]` | `playground.fdepl`, `playground.fidl` | Attribute notifier ID declared; custom fire path not found in inspected implementation |
| 32777 | `0x8009` | `vehiclePosition` | event | `PlaygroundTypes.StatusGPS` | `playground.fdepl`, `playground.fidl`, `playgroundTypes.fidl` | Event ID declared; no direct fire path found in inspected implementation |
| 32778 | `0x800a` | `currentTankVolume` | event | `UInt8` | `playground.fdepl`, `playground.fidl` | `monitorTankLevel()` calls `fireCurrentTankVolumeEvent(level)` |

## Required ID Checks

- `method_id=10`: valid ID. It is the setter ID for `seatHeatingStatus` (`Boolean[]`).
- `method_id=12`: valid ID. It is the setter ID for `seatHeatingLevel` (`UInt8[]`).
- `method_id=14`: valid ID. It is the method ID for `changeDoorsState`, input type `CarDoorsCommand`.
- `method_id=9`: valid getter ID for `seatHeatingStatus`.
- `method_id=11`: valid getter ID for `seatHeatingLevel`.
- `method_id=8`: valid getter ID for `doorsOpeningStatus`.

## Current LLM Candidate Judgment

The current LLM replay candidate uses `method_id=10`.

Conclusion:

- ID-level validity: valid. `0x000a` is the public SOME/IP setter ID for `seatHeatingStatus`.
- Payload-level validity: not proven from ID mapping alone. The payload must match the expected `Boolean[]` wire encoding and should be validated by black-box replay/getter checks.
- Current observed behavior from replay: it can return `normal_response`, but prior getter-before/setter/getter-after checks did not show an observable `method_id=9` payload change.

## Next Target Recommendation

| candidate | recommendation | reason |
|---|---|---|
| `method_id=10` / `seatHeatingStatus` setter | Lower priority | ID is valid and accepted payloads are interesting, but inspected custom implementation does not show an explicit state-change function, and current getter 9 checks did not observe state change |
| `method_id=12` / `seatHeatingLevel` setter | Medium priority | Payload type `UInt8[]` is simpler than a struct, and getter 11 can check state. However, inspected custom implementation does not show explicit setter logic |
| `method_id=14` / `changeDoorsState` | Highest priority | Payload structure is clear from public `CarDoorsCommand`; getter 8 can verify state; inspected implementation explicitly updates `doorsOpeningStatus` |

Recommended next experiment target: `method_id=14`.

Reason: it has the strongest validation path: `getter 8 -> method 14 -> getter 8`, and `PlaygroundStubImpl.cpp` explicitly shows a state update through `setDoorsOpeningStatusAttribute(...)`.

## Manual Grep Commands

Run from `test-someip-service/`:

```bash
grep -n "SomeIpGetterID\|SomeIpSetterID\|SomeIpMethodID\|SomeIpEventID\|SomeIpServiceID" franca/org/genivi/vehicle/playground.fdepl
grep -n "seatHeatingStatus\|seatHeatingLevel\|changeDoorsState\|doorsOpeningStatus" franca/org/genivi/vehicle/playground.fidl
grep -n "DoorCommand\|CarDoorsCommand\|DoorsStatus" franca/org/genivi/vehicle/playgroundTypes.fidl
grep -n "changeDoorsState\|setDoorsOpeningStatusAttribute\|monitorTankLevel\|fireCurrentTankVolumeEvent" src/PlaygroundStubImpl.cpp
grep -n "SeatHeatingStatus\|SeatHeatingLevel\|DoorsOpeningStatus\|getNextStateFromCommand" src/mock/MockedAttributes.cpp
```
