
# GateSummary

Abbreviated view of a SignatureGate for list responses

## Properties

Name | Type
------------ | -------------
`name` | string
`namespace` | string
`phase` | [GatePhase](GatePhase.md)
`layers` | [Array&lt;LayerType&gt;](LayerType.md)
`expectedSignature` | string
`currentSignature` | string

## Example

```typescript
import type { GateSummary } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "name": null,
  "namespace": null,
  "phase": null,
  "layers": null,
  "expectedSignature": null,
  "currentSignature": null,
} satisfies GateSummary

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as GateSummary
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


