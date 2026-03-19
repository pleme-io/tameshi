
# Certification

Full Certification resource with spec and status

## Properties

Name | Type
------------ | -------------
`name` | string
`namespace` | string
`spec` | [CertificationSpec](CertificationSpec.md)
`status` | [CertificationStatus](CertificationStatus.md)

## Example

```typescript
import type { Certification } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "name": null,
  "namespace": null,
  "spec": null,
  "status": null,
} satisfies Certification

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as Certification
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


