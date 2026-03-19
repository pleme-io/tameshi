
# ComputeSignatureRequest

Request to compute a deterministic composite signature

## Properties

Name | Type
------------ | -------------
`layers` | [Array&lt;LayerType&gt;](LayerType.md)
`environment` | string

## Example

```typescript
import type { ComputeSignatureRequest } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "layers": null,
  "environment": null,
} satisfies ComputeSignatureRequest

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ComputeSignatureRequest
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


