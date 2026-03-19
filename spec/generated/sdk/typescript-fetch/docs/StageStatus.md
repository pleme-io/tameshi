
# StageStatus

Result of a single certification pipeline stage

## Properties

Name | Type
------------ | -------------
`stage` | string
`passed` | boolean
`hash` | string
`violations` | Array&lt;string&gt;

## Example

```typescript
import type { StageStatus } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "stage": null,
  "passed": null,
  "hash": null,
  "violations": null,
} satisfies StageStatus

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as StageStatus
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


