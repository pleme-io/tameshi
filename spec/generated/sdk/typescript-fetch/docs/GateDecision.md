
# GateDecision

An admission decision made by a signature gate

## Properties

Name | Type
------------ | -------------
`allowed` | boolean
`reason` | string
`signature` | string
`expected` | string
`decidedAt` | Date
`gate` | string

## Example

```typescript
import type { GateDecision } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "allowed": null,
  "reason": null,
  "signature": null,
  "expected": null,
  "decidedAt": null,
  "gate": null,
} satisfies GateDecision

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as GateDecision
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


