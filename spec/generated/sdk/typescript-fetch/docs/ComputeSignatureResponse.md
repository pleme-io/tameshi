
# ComputeSignatureResponse

Result of a signature computation

## Properties

Name | Type
------------ | -------------
`signature` | string
`layers` | Array&lt;string&gt;
`environment` | string

## Example

```typescript
import type { ComputeSignatureResponse } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "signature": null,
  "layers": null,
  "environment": null,
} satisfies ComputeSignatureResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ComputeSignatureResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


