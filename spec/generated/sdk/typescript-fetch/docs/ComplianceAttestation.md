
# ComplianceAttestation

Multi-dimensional compliance attestation for a deployment artifact

## Properties

Name | Type
------------ | -------------
`environment` | string
`artifact` | string
`dimensions` | [Array&lt;ComplianceDimension&gt;](ComplianceDimension.md)
`complianceHash` | string
`computedAt` | Date
`policyName` | string
`allPassed` | boolean

## Example

```typescript
import type { ComplianceAttestation } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "environment": null,
  "artifact": null,
  "dimensions": null,
  "complianceHash": null,
  "computedAt": null,
  "policyName": null,
  "allPassed": null,
} satisfies ComplianceAttestation

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ComplianceAttestation
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


