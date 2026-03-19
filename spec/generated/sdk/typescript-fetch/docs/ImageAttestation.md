
# ImageAttestation

Attestation of a container image

## Properties

Name | Type
------------ | -------------
`imageRef` | string
`tag` | string
`architecture` | string
`manifestHash` | string
`cosignVerified` | boolean
`signerIdentity` | string
`vulnScanHash` | string
`vulnCount` | number
`criticalHighVulns` | number
`sbomHash` | string

## Example

```typescript
import type { ImageAttestation } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "imageRef": null,
  "tag": null,
  "architecture": null,
  "manifestHash": null,
  "cosignVerified": null,
  "signerIdentity": null,
  "vulnScanHash": null,
  "vulnCount": null,
  "criticalHighVulns": null,
  "sbomHash": null,
} satisfies ImageAttestation

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ImageAttestation
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


