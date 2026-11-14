
# GlobalBlastRadiusResponse

Global blast radius report aggregating across all clusters

## Properties

Name | Type
------------ | -------------
`queryHash` | string
`totalClustersAffected` | number
`totalNodesAffected` | number
`totalPodsAffected` | number
`clustersNotAffected` | Array&lt;string&gt;
`clusterReports` | [Array&lt;ClusterBlastRadius&gt;](ClusterBlastRadius.md)
`globalFirstSeen` | Date
`globalLastSeen` | Date

## Example

```typescript
import type { GlobalBlastRadiusResponse } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "queryHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "totalClustersAffected": null,
  "totalNodesAffected": null,
  "totalPodsAffected": null,
  "clustersNotAffected": null,
  "clusterReports": null,
  "globalFirstSeen": null,
  "globalLastSeen": null,
} satisfies GlobalBlastRadiusResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as GlobalBlastRadiusResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


