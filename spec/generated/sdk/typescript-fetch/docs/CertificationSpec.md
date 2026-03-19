
# CertificationSpec

Desired state of a Certification

## Properties

Name | Type
------------ | -------------
`environment` | string
`gates` | Array&lt;string&gt;
`auditRetentionDays` | number

## Example

```typescript
import type { CertificationSpec } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "environment": null,
  "gates": null,
  "auditRetentionDays": null,
} satisfies CertificationSpec

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as CertificationSpec
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


