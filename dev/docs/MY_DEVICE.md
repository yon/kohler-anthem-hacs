# My Kohler Anthem Device Configuration

Device: **Primary Bathroom** (`gcs-sio3225nc9`)

## Outlets

| # | Name | Valve | Mode | Valve Value (37.7°C, 100%) |
|---|------|-------|------|----------------------------|
| 1 | Showerhead | primaryValve1 | `01` | `0179c801` |
| 2 | Bathtub Filler | primaryValve1 | `02` | `0179c802` |
| 3 | Shower Handshower | secondaryValve1 | `01` | `1179c801` |
| 4 | Bathtub Handheld | secondaryValve1 | `03` | `1179c803` |

## Valve Mapping

```
primaryValve1 (prefix 01):
  └── Mode 01: Showerhead
  └── Mode 02: Bathtub Filler

secondaryValve1 (prefix 11):
  └── Mode 01: Shower Handshower
  └── Mode 03: Bathtub Handheld
```

## Common Commands

### Start Shower (Showerhead + Handshower)
```
primaryValve1:   0179c801  (showerhead on)
secondaryValve1: 1179c801  (handshower on)
```

### Start Bath (Filler + Handheld)
```
primaryValve1:   0179c802  (bathtub filler on)
secondaryValve1: 1179c803  (bathtub handheld on)
```

### Stop All
```
primaryValve1:   0179c840  (stop)
secondaryValve1: 1179c840  (stop)
```

### Showerhead Only
```
primaryValve1:   0179c801  (showerhead on)
secondaryValve1: 1179c800  (off)
```

## Temperature/Flow Examples

| Setting | Temp Byte | Flow Byte | Example (showerhead) |
|---------|-----------|-----------|----------------------|
| Default (37.7°C, 100%) | `79` | `c8` | `0179c801` |
| Hot (41.1°C, 100%) | `9b` | `c8` | `019bc801` |
| Cool (35°C, 100%) | `5e` | `c8` | `015ec801` |
| Max (48.8°C, 100%) | `e8` | `c8` | `01e8c801` |
| Half flow (37.7°C, 50%) | `79` | `64` | `01796401` |

## Device IDs

```
deviceId: gcs-sio3225nc9
tenantId: cfd22e16-f7be-4038-b7ff-bf08790b8ec4
sku: GCS
```
