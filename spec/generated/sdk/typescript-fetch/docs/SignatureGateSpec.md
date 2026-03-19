
# SignatureGateSpec

Desired state of a SignatureGate

## Properties

Name | Type
------------ | -------------
`layers` | [Array&lt;LayerType&gt;](LayerType.md)
`expectedSignature` | string
`targetResources` | [Array&lt;TargetResource&gt;](TargetResource.md)
`compliancePolicy` | string
`expectedCertificationHash` | string
`verificationIntervalSecs` | number

## Example

```typescript
import type { SignatureGateSpec } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "layers": null,
  "expectedSignature": null,
  "targetResources": null,
  "compliancePolicy": null,
  "expectedCertificationHash": null,
  "verificationIntervalSecs": null,
} satisfies SignatureGateSpec

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as SignatureGateSpec
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


