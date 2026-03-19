
# ChartAttestation

Attestation of a Helm chart

## Properties

Name | Type
------------ | -------------
`chartName` | string
`chartVersion` | string
`chartHash` | string
`provenanceVerified` | boolean
`dependencyHashes` | Array&lt;string&gt;
`linterPassed` | boolean
`policyPassed` | boolean
`registryRef` | string

## Example

```typescript
import type { ChartAttestation } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "chartName": null,
  "chartVersion": null,
  "chartHash": null,
  "provenanceVerified": null,
  "dependencyHashes": null,
  "linterPassed": null,
  "policyPassed": null,
  "registryRef": null,
} satisfies ChartAttestation

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ChartAttestation
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


