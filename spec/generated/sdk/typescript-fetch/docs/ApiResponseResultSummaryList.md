
# ApiResponseResultSummaryList

API response wrapping a list of compliance result summaries

## Properties

Name | Type
------------ | -------------
`data` | [Array&lt;ResultSummary&gt;](ResultSummary.md)

## Example

```typescript
import type { ApiResponseResultSummaryList } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "data": null,
} satisfies ApiResponseResultSummaryList

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ApiResponseResultSummaryList
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


