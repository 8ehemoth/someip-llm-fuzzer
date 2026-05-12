# SOME/IP Method ID Coverage Matrix Report

## Scope

This report is based on `test-someip-service` source definitions only. It does not enumerate or probe the full `0x0000`-`0xffff` Method ID range.

Sources checked:

- `test-someip-service/franca/org/genivi/vehicle/playground.fidl`
- `test-someip-service/franca/org/genivi/vehicle/playground.fdepl`
- `test-someip-service/franca/org/genivi/vehicle/playgroundTypes.fidl`
- generated CommonAPI/SOME-IP wrapper code
- `test-someip-service/src/PlaygroundClient.cpp`
- `test-someip-service/src/PlaygroundService.cpp`
- existing original client capture summary: `results/original_playground_client_method_summary_20260506_104714.csv`
- existing Method 10/12 validation result reports
- existing Method 14 baseline validation result report

Output matrix:

- `results/method_id_coverage_matrix_20260506_105958.csv`

## Defined IDs

Request/response IDs defined by FDEP:

| Method ID | Hex | Name | Role | Input | Output | Paired Getter | Original Client Observed | Probe Status |
|---:|---|---|---|---|---|---:|---|---|
| 1 | `0x0001` | `getConsumptionAttribute` | getter | none | `Float` | - | yes, count 20 | empty-payload getter probe available |
| 2 | `0x0002` | `getCapacityAttribute` | getter | none | `UInt8` | - | yes, count 20 | empty-payload getter probe available |
| 3 | `0x0003` | `getVolumeAttribute` | getter | none | `Float` | - | yes, count 20 | empty-payload getter probe available |
| 4 | `0x0004` | `getEngineSpeedAttribute` | getter | none | `UInt16` | - | yes, count 20 | empty-payload getter probe available |
| 5 | `0x0005` | `getCurrentGearAttribute` | getter | none | `PlaygroundTypes.Gear` | - | yes, count 20 | empty-payload getter probe available |
| 6 | `0x0006` | `getIsReverseGearOnAttribute` | getter | none | `Boolean` | - | yes, count 20 | empty-payload getter probe available |
| 7 | `0x0007` | `getDrivePowerTransmissionAttribute` | getter | none | `PlaygroundTypes.DriveType` | - | yes, count 20 | empty-payload getter probe available |
| 8 | `0x0008` | `getDoorsOpeningStatusAttribute` | getter | none | `PlaygroundTypes.DoorsStatus` | - | yes, count 20 | paired getter for Method 14 |
| 9 | `0x0009` | `getSeatHeatingStatusAttribute` | getter | none | `Boolean[]` | - | yes, count 20 | paired getter for Method 10 |
| 10 | `0x000a` | `setSeatHeatingStatusAttribute` | setter | `Boolean[]` | `Boolean[]` | 9 | no | baseline validation completed |
| 11 | `0x000b` | `getSeatHeatingLevelAttribute` | getter | none | `UInt8[]` | - | yes, count 20 | paired getter for Method 12 |
| 12 | `0x000c` | `setSeatHeatingLevelAttribute` | setter | `UInt8[]` | `UInt8[]` | 11 | no | baseline validation completed |
| 13 | `0x000d` | `initTirePressureCalibration` | method | none | none | unknown | no | additional response probe needed |
| 14 | `0x000e` | `changeDoorsState` | method | `PlaygroundTypes.CarDoorsCommand` | none | 8 | no | additional state probe needed |

Event/notifier IDs defined by FDEP:

| Method ID | Hex | Name | Role | Output | Original Client Observed | Probe Status |
|---:|---|---|---|---|---|---|
| 32769 | `0x8001` | consumption notifier | event | `Float` | no | excluded from request probe |
| 32770 | `0x8002` | engineSpeed notifier | event | `UInt16` | no | excluded from request probe |
| 32771 | `0x8003` | currentGear notifier | event | `PlaygroundTypes.Gear` | no | excluded from request probe |
| 32772 | `0x8004` | isReverseGearOn notifier | event | `Boolean` | no | excluded from request probe |
| 32773 | `0x8005` | drivePowerTransmission notifier | event | `PlaygroundTypes.DriveType` | no | excluded from request probe |
| 32774 | `0x8006` | doorsOpeningStatus notifier | event | `PlaygroundTypes.DoorsStatus` | no | excluded from request probe |
| 32775 | `0x8007` | seatHeatingStatus notifier | event | `Boolean[]` | no | excluded from request probe |
| 32776 | `0x8008` | seatHeatingLevel notifier | event | `UInt8[]` | no | excluded from request probe |
| 32777 | `0x8009` | vehiclePosition | event | `PlaygroundTypes.StatusGPS` | no | excluded from request probe |
| 32778 | `0x800a` | currentTankVolume | event | `UInt8` | yes, count 10 | excluded from request probe |

## Original Client Coverage

Observed in the original `PlaygroundClient` normal communication capture:

- Request/response getters: `1,2,3,4,5,6,7,8,9,11`
- Event/notifier: `0x800a`

Not observed in the original client capture:

- Method 10 `setSeatHeatingStatusAttribute`
- Method 12 `setSeatHeatingLevelAttribute`
- Method 13 `initTirePressureCalibration`
- Method 14 `changeDoorsState`

Interpretation:

- The unmodified original client is getter-heavy.
- It subscribes to or receives `currentTankVolume` event traffic.
- It does not call Method 10, 12, 13, or 14 in the observed normal capture.

## Prior Validation Reflected

Method 10:

- Role: setter for `seatHeatingStatus`
- Paired getter: Method 9
- Existing Method 10/Getter 9 baseline validation completed.
- Fuzzing/replay candidates did not produce a confirmed non-trivial state effect in the 1st validation.

Method 12:

- Role: setter for `seatHeatingLevel`
- Paired getter: Method 11
- Existing Method 12/Getter 11 baseline validation completed.
- Fuzzing/replay candidates did not produce a confirmed non-trivial state effect in the 1st validation.

Method 13:

- Role: method `initTirePressureCalibration`
- Input: none
- Paired getter: unclear
- Next step: response-only probe first, then inspect whether any observable state or event changes.

Method 14:

- Role: method `changeDoorsState`
- Input: `PlaygroundTypes.CarDoorsCommand`
- Paired getter: Method 8 `getDoorsOpeningStatusAttribute`
- Next step: Getter 8 before -> Method 14 -> Getter 8 after probe.

## Probe Design

Probe targets must be limited to defined request/response IDs:

- Getters: `1,2,3,4,5,6,7,8,9,11`
- Setters/methods: `10,12,13,14`

Excluded from request probe:

- `0x8001`-`0x8008` attribute notifiers
- `0x8009` vehiclePosition event
- `0x800a` currentTankVolume event

Recommended probe phases:

1. Empty-payload getter probe for Methods `1,2,3,4,5,6,7,8,9,11`.
2. Response probe for Method 13 with empty payload.
3. State-aware probes:
   - Method 10 with Getter 9 before/after.
   - Method 12 with Getter 11 before/after.
   - Method 14 with Getter 8 before/after.
4. Record normal response separately from observable state effect.

Actual probe execution should only run after user confirmation.
