
# GateVerifyResult

Result of an on-demand gate verification

## Properties

Name | Type
------------ | -------------
`name` | string
`verified` | boolean
`phase` | [GatePhase](GatePhase.md)
`expectedSignature` | string
`currentSignature` | string
`layerStatuses` | [Array&lt;LayerStatus&gt;](LayerStatus.md)

## Example

```typescript
import type { GateVerifyResult } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "name": null,
  "verified": null,
  "phase": null,
  "expectedSignature": null,
  "currentSignature": null,
  "layerStatuses": null,
} satisfies GateVerifyResult

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as GateVerifyResult
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


