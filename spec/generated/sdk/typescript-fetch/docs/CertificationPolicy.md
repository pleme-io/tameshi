
# CertificationPolicy

Policy defining certification requirements

## Properties

Name | Type
------------ | -------------
`name` | string
`requireSignedCommits` | boolean
`requirePinnedInputs` | boolean
`minSlsaLevel` | [SlsaLevel](SlsaLevel.md)
`requireReproducible` | boolean
`maxCriticalHighCves` | number
`requireImageSignatures` | boolean
`requireChartProvenance` | boolean
`requireSourceVerification` | boolean
`minCisPassRate` | number
`requireNetworkPolicies` | boolean
`requireCompliance` | boolean

## Example

```typescript
import type { CertificationPolicy } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "name": null,
  "requireSignedCommits": null,
  "requirePinnedInputs": null,
  "minSlsaLevel": null,
  "requireReproducible": null,
  "maxCriticalHighCves": null,
  "requireImageSignatures": null,
  "requireChartProvenance": null,
  "requireSourceVerification": null,
  "minCisPassRate": null,
  "requireNetworkPolicies": null,
  "requireCompliance": null,
} satisfies CertificationPolicy

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as CertificationPolicy
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


