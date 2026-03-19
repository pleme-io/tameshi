
# LayerStatus

Verification status for a single infrastructure layer

## Properties

Name | Type
------------ | -------------
`layer` | [LayerType](LayerType.md)
`hash` | string
`verified` | boolean
`lastVerifiedAt` | Date
`error` | string

## Example

```typescript
import type { LayerStatus } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "layer": null,
  "hash": null,
  "verified": null,
  "lastVerifiedAt": null,
  "error": null,
} satisfies LayerStatus

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as LayerStatus
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


