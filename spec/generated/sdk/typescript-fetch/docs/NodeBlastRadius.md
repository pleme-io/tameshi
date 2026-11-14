
# NodeBlastRadius

Per-node blast radius detail

## Properties

Name | Type
------------ | -------------
`node` | string
`pods` | Array&lt;string&gt;
`binaryPaths` | Array&lt;string&gt;
`firstExecution` | Date
`lastExecution` | Date
`executionCount` | number

## Example

```typescript
import type { NodeBlastRadius } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "node": null,
  "pods": null,
  "binaryPaths": null,
  "firstExecution": null,
  "lastExecution": null,
  "executionCount": null,
} satisfies NodeBlastRadius

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as NodeBlastRadius
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


