
# ApiResponseHashResponse

API response wrapping a compliance hash

## Properties

Name | Type
------------ | -------------
`data` | [HashResponse](HashResponse.md)

## Example

```typescript
import type { ApiResponseHashResponse } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "data": null,
} satisfies ApiResponseHashResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ApiResponseHashResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


