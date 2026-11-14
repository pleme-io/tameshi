
# RevokeResponse

Result of a hash revocation operation

## Properties

Name | Type
------------ | -------------
`revoked` | boolean
`affectedNodes` | number
`bpfMapsUpdated` | boolean
`heartbeatEntrySequence` | number

## Example

```typescript
import type { RevokeResponse } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "revoked": null,
  "affectedNodes": null,
  "bpfMapsUpdated": null,
  "heartbeatEntrySequence": null,
} satisfies RevokeResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as RevokeResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


