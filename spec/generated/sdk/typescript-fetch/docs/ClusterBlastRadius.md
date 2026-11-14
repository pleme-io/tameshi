
# ClusterBlastRadius

Per-cluster blast radius detail

## Properties

Name | Type
------------ | -------------
`clusterId` | string
`nodesAffected` | number
`podsAffected` | number
`firstSeen` | Date
`lastSeen` | Date
`nodeDetails` | [Array&lt;NodeBlastRadius&gt;](NodeBlastRadius.md)

## Example

```typescript
import type { ClusterBlastRadius } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "clusterId": null,
  "nodesAffected": null,
  "podsAffected": null,
  "firstSeen": null,
  "lastSeen": null,
  "nodeDetails": null,
} satisfies ClusterBlastRadius

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ClusterBlastRadius
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


