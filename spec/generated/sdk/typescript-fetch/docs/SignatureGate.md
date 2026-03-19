
# SignatureGate

Full SignatureGate resource with spec and status

## Properties

Name | Type
------------ | -------------
`name` | string
`namespace` | string
`spec` | [SignatureGateSpec](SignatureGateSpec.md)
`status` | [SignatureGateStatus](SignatureGateStatus.md)

## Example

```typescript
import type { SignatureGate } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "name": null,
  "namespace": null,
  "spec": null,
  "status": null,
} satisfies SignatureGate

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as SignatureGate
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


