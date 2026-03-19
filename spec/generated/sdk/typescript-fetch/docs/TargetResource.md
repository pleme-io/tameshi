
# TargetResource

Kubernetes resource targeted by a gate for admission control

## Properties

Name | Type
------------ | -------------
`group` | string
`kind` | string
`operations` | Array&lt;string&gt;

## Example

```typescript
import type { TargetResource } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "group": null,
  "kind": null,
  "operations": null,
} satisfies TargetResource

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as TargetResource
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


