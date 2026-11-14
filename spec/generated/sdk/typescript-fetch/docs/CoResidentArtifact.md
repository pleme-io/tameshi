
# CoResidentArtifact

An artifact that shared the same Merkle root as the compromised hash

## Properties

Name | Type
------------ | -------------
`composedRoot` | string
`artifactHash` | string
`controlHash` | string
`intentHash` | string
`binaryPath` | string

## Example

```typescript
import type { CoResidentArtifact } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "composedRoot": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "artifactHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "controlHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "intentHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "binaryPath": null,
} satisfies CoResidentArtifact

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as CoResidentArtifact
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


