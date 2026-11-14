
# GlobalRevokeResponse

Aggregate result of revoking a hash across all clusters

## Properties

Name | Type
------------ | -------------
`totalClustersRevoked` | number
`totalNodesAffected` | number
`totalBpfMapsUpdated` | number
`clusterResults` | [Array&lt;RevokeResponse&gt;](RevokeResponse.md)

## Example

```typescript
import type { GlobalRevokeResponse } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "totalClustersRevoked": null,
  "totalNodesAffected": null,
  "totalBpfMapsUpdated": null,
  "clusterResults": null,
} satisfies GlobalRevokeResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as GlobalRevokeResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


