
# AffectedNode

A node where the compromised hash was active during the queried window

## Properties

Name | Type
------------ | -------------
`node` | string
`cluster` | string
`firstExecution` | Date
`lastExecution` | Date
`executionCount` | number
`pods` | Array&lt;string&gt;
`namespaces` | Array&lt;string&gt;

## Example

```typescript
import type { AffectedNode } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "node": null,
  "cluster": null,
  "firstExecution": null,
  "lastExecution": null,
  "executionCount": null,
  "pods": null,
  "namespaces": null,
} satisfies AffectedNode

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as AffectedNode
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


