
# ArtifactLocation

Location of an artifact in the global fleet

## Properties

Name | Type
------------ | -------------
`clusterId` | string
`node` | string
`namespace` | string
`pod` | string
`binaryPath` | string
`composedRoot` | string

## Example

```typescript
import type { ArtifactLocation } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "clusterId": null,
  "node": null,
  "namespace": null,
  "pod": null,
  "binaryPath": null,
  "composedRoot": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
} satisfies ArtifactLocation

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ArtifactLocation
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


