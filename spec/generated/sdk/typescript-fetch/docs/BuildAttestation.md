
# BuildAttestation

Attestation of a build artifact

## Properties

Name | Type
------------ | -------------
`service` | string
`derivation` | string
`closureHash` | string
`slsaLevel` | [SlsaLevel](SlsaLevel.md)
`reproducible` | boolean
`hermetic` | boolean
`sbomHash` | string
`vulnScanHash` | string
`cveCount` | number
`criticalHighCves` | number
`builder` | string
`builtAt` | Date

## Example

```typescript
import type { BuildAttestation } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "service": null,
  "derivation": null,
  "closureHash": null,
  "slsaLevel": null,
  "reproducible": null,
  "hermetic": null,
  "sbomHash": null,
  "vulnScanHash": null,
  "cveCount": null,
  "criticalHighCves": null,
  "builder": null,
  "builtAt": null,
} satisfies BuildAttestation

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as BuildAttestation
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


