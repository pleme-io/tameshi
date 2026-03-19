
# SignatureGateStatus

Observed state of a SignatureGate

## Properties

Name | Type
------------ | -------------
`phase` | [GatePhase](GatePhase.md)
`currentSignature` | string
`lastVerifiedAt` | Date
`layerStatuses` | [Array&lt;LayerStatus&gt;](LayerStatus.md)
`message` | string
`failureCount` | number
`admissionDecisions` | [AdmissionDecisionCounts](AdmissionDecisionCounts.md)

## Example

```typescript
import type { SignatureGateStatus } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "phase": null,
  "currentSignature": null,
  "lastVerifiedAt": null,
  "layerStatuses": null,
  "message": null,
  "failureCount": null,
  "admissionDecisions": null,
} satisfies SignatureGateStatus

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as SignatureGateStatus
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


