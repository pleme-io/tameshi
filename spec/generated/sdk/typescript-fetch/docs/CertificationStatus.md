
# CertificationStatus

Observed state of a Certification

## Properties

Name | Type
------------ | -------------
`phase` | [CertPhase](CertPhase.md)
`masterSignature` | string
`complianceSignature` | string
`secureSignature` | string
`lastCertifiedAt` | Date
`gateStatuses` | [Array&lt;GateStatusRef&gt;](GateStatusRef.md)
`auditTrail` | [Array&lt;AuditEntry&gt;](AuditEntry.md)

## Example

```typescript
import type { CertificationStatus } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "phase": null,
  "masterSignature": null,
  "complianceSignature": null,
  "secureSignature": null,
  "lastCertifiedAt": null,
  "gateStatuses": null,
  "auditTrail": null,
} satisfies CertificationStatus

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as CertificationStatus
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


