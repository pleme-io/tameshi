
# ProvenanceResponse

Point-in-time snapshot of all active artifacts on a node

## Properties

Name | Type
------------ | -------------
`node` | string
`timestamp` | Date
`activeArtifacts` | [Array&lt;ProvenanceResponseActiveArtifactsInner&gt;](ProvenanceResponseActiveArtifactsInner.md)

## Example

```typescript
import type { ProvenanceResponse } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "node": null,
  "timestamp": null,
  "activeArtifacts": null,
} satisfies ProvenanceResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ProvenanceResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


