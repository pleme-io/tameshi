
# RevokeRequest

Request to revoke a compromised hash across all nodes

## Properties

Name | Type
------------ | -------------
`hash` | string
`reason` | string
`severity` | string
`operator` | string

## Example

```typescript
import type { RevokeRequest } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "hash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "reason": null,
  "severity": null,
  "operator": null,
} satisfies RevokeRequest

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as RevokeRequest
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


