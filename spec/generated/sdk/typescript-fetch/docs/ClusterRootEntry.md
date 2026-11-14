
# ClusterRootEntry

A single cluster\'s contribution to the global state root

## Properties

Name | Type
------------ | -------------
`clusterId` | string
`clusterRoot` | string
`signedRoot` | [SignedRoot](SignedRoot.md)
`nodeCount` | number
`artifactCount` | number
`lastReported` | Date
`status` | [ClusterStatus](ClusterStatus.md)

## Example

```typescript
import type { ClusterRootEntry } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "clusterId": null,
  "clusterRoot": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "signedRoot": null,
  "nodeCount": null,
  "artifactCount": null,
  "lastReported": null,
  "status": null,
} satisfies ClusterRootEntry

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ClusterRootEntry
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


