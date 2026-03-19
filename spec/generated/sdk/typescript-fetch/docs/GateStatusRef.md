
# GateStatusRef

Reference to a gate\'s status within a certification

## Properties

Name | Type
------------ | -------------
`name` | string
`verified` | boolean
`phase` | [GatePhase](GatePhase.md)
`lastCheckedAt` | Date

## Example

```typescript
import type { GateStatusRef } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "name": null,
  "verified": null,
  "phase": null,
  "lastCheckedAt": null,
} satisfies GateStatusRef

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as GateStatusRef
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


