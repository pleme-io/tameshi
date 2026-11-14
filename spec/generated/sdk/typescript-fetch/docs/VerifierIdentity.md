
# VerifierIdentity

Identity of the component that produced a heartbeat entry

## Properties

Name | Type
------------ | -------------
`component` | string
`instance` | string
`version` | string

## Example

```typescript
import type { VerifierIdentity } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "component": null,
  "instance": null,
  "version": null,
} satisfies VerifierIdentity

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as VerifierIdentity
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


