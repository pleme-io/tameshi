
# ApiResponseRunResponse

API response wrapping a compliance run result

## Properties

Name | Type
------------ | -------------
`data` | [RunResponse](RunResponse.md)

## Example

```typescript
import type { ApiResponseRunResponse } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "data": null,
} satisfies ApiResponseRunResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ApiResponseRunResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


