
# GlobalStateRootResponse

Global state root aggregating all cluster roots

## Properties

Name | Type
------------ | -------------
`rootHash` | string
`clusterRoots` | [{ [key: string]: ClusterRootEntry; }](ClusterRootEntry.md)
`computedAt` | Date
`sequence` | number
`previousRoot` | string

## Example

```typescript
import type { GlobalStateRootResponse } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "rootHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "clusterRoots": null,
  "computedAt": null,
  "sequence": null,
  "previousRoot": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
} satisfies GlobalStateRootResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as GlobalStateRootResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


