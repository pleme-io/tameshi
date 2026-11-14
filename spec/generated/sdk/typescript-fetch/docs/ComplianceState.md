
# ComplianceState

Aggregate compliance state across all active frameworks

## Properties

Name | Type
------------ | -------------
`status` | string
`distance` | number
`frameworks` | Array&lt;string&gt;
`lastAssessedAt` | Date
`hash` | string

## Example

```typescript
import type { ComplianceState } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "status": null,
  "distance": null,
  "frameworks": null,
  "lastAssessedAt": null,
  "hash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
} satisfies ComplianceState

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ComplianceState
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


