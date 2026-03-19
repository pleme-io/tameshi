
# LayerVerification

Verification result for a single layer

## Properties

Name | Type
------------ | -------------
`layer` | [LayerType](LayerType.md)
`passed` | boolean
`expected` | string
`actual` | string

## Example

```typescript
import type { LayerVerification } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "layer": null,
  "passed": null,
  "expected": null,
  "actual": null,
} satisfies LayerVerification

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as LayerVerification
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


